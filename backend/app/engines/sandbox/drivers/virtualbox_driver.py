"""VirtualBox 沙箱驱动。

适用于以 VirtualBox 作为虚拟化后端的宿主机（Windows/Linux）。
依赖 VBoxManage 命令行与客户机内运行的 MalScope Guest Agent。

隔离与回滚要点：
- 每个样本运行前执行 ``VBoxManage snapshot <vm> restore <snapshot>`` 回滚到纯净快照；
- 通过 guestcontrol 投递样本、受控执行；
- 运行结束强制断电并再次回滚，实现“跑一次清一次”；
- 网络通过内部网络/NAT 限制，禁止真实外联（配合 INetSim 诱捕）。
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger
from app.engines.sandbox.base import SandboxDriver, SandboxRun, run_with_driver
from app.engines.sandbox.drivers.mock_driver import MockDriver

logger = get_logger("sandbox.virtualbox")

VBOXMANAGE = "VBoxManage"
GUEST_LOG_PATH = r"C:\malscope\behavior.json"


class VirtualBoxDriver(SandboxDriver):
    name = "virtualbox"

    def __init__(self, *args, vm_name=None, snapshot=None, guest_user=None, guest_password=None, **kwargs):
        super().__init__(vm_name or settings.SANDBOX_VM_NAME, snapshot or settings.SANDBOX_SNAPSHOT, **kwargs)
        self.guest_user = guest_user or settings.SANDBOX_GUEST_USER
        self.guest_password = guest_password or settings.SANDBOX_GUEST_PASSWORD
        self._log_local: Path | None = None

    @classmethod
    def available(cls) -> bool:
        return shutil.which(VBOXMANAGE) is not None

    # ---------------- 命令封装 ----------------

    def _run(self, *args: str, timeout: int | None = None, check: bool = True) -> subprocess.CompletedProcess:
        cmd = [VBOXMANAGE, *args]
        logger.debug("执行：%s", " ".join(cmd))
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout or (self.timeout + 60)
        )
        if check and proc.returncode != 0:
            raise RuntimeError(f"VBoxManage {' '.join(args)} 失败：{proc.stderr.strip()}")
        return proc

    # ---------------- 生命周期 ----------------

    def prepare(self) -> None:
        logger.info("回滚虚拟机 %s 到快照 %s", self.vm_name, self.snapshot)
        # 先确保虚拟机关机
        self._run("controlvm", self.vm_name, "poweroff", check=False, timeout=30)
        time.sleep(2)
        self._run("snapshot", self.vm_name, "restore", self.snapshot, timeout=120)
        self._start_guest()
        self._wait_guest_ready()

    def _start_guest(self) -> None:
        self._run("startvm", self.vm_name, "--type", "headless", timeout=120)
        self._started = True
        logger.info("虚拟机已启动（无头模式）")

    def _wait_guest_ready(self, retries: int = 30) -> None:
        for _ in range(retries):
            proc = self._run("guestcontrol", self.vm_name, "run", "--username", self.guest_user,
                             "--password", self.guest_password, "--exe", "cmd.exe", "--",
                             "/c", "echo ready", check=False, timeout=15)
            if proc.returncode == 0:
                logger.info("客户机已就绪")
                return
            time.sleep(5)
        logger.warning("等待客户机就绪超时，继续尝试投递")

    def transfer_sample(self, local_path: Path, guest_path: str) -> None:
        guest_dir = str(Path(guest_path).parent).replace("/", "\\")
        self._run("guestcontrol", self.vm_name, "mkdir", "--username", self.guest_user,
                  "--password", self.guest_password, "--parents", guest_dir, check=False, timeout=30)
        self._run("guestcontrol", self.vm_name, "copyto", "--username", self.guest_user,
                  "--password", self.guest_password, str(local_path), guest_path, timeout=60)
        logger.info("样本已投递到 %s", guest_path)

    def execute(self, guest_path: str) -> None:
        # 启动客户机内采集 agent，等待样本执行窗口
        self._run("guestcontrol", self.vm_name, "start",
                  "--username", self.guest_user, "--password", self.guest_password,
                  "--exe", "C:\\malscope\\agent.exe", "--", "--sample", guest_path,
                  "--timeout", str(self.timeout), check=False, timeout=self.timeout + 30)
        time.sleep(self.timeout)

    def collect_log(self) -> dict:
        local = settings.TMP_DIR / f"vb_{int(time.time())}_behavior.json"
        proc = self._run("guestcontrol", self.vm_name, "copyfrom",
                         "--username", self.guest_user, "--password", self.guest_password,
                         GUEST_LOG_PATH, str(local), check=False, timeout=60)
        if proc.returncode != 0 or not local.exists():
            logger.warning("未能回收客户机行为日志：%s", proc.stderr.strip())
            return {}
        try:
            return json.loads(local.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            logger.warning("行为日志解析失败：%s", exc)
            return {}

    def revert(self) -> None:
        logger.info("执行结束，关机并回滚快照")
        self._run("controlvm", self.vm_name, "poweroff", check=False, timeout=30)
        time.sleep(2)
        self._run("snapshot", self.vm_name, "restore", self.snapshot, check=False, timeout=120)
        self._started = False

    def screenshot(self) -> bytes | None:
        out = settings.TMP_DIR / f"vb_{int(time.time())}.png"
        proc = self._run("controlvm", self.vm_name, "screenshotpng", str(out), check=False, timeout=30)
        if proc.returncode == 0 and out.exists():
            return out.read_bytes()
        return None


def run_virtualbox(local_path: Path, hints: dict | None = None, **opts) -> SandboxRun:
    """对外执行入口；若 VirtualBox 不可用则回退到 mock 驱动。"""
    if not VirtualBoxDriver.available():
        logger.warning("未检测到 VBoxManage，动态分析回退到 mock 驱动")
        return run_with_driver(MockDriver(**opts), local_path)
    driver = VirtualBoxDriver(**opts)
    driver.options["hints"] = hints or {}
    return run_with_driver(driver, local_path)
