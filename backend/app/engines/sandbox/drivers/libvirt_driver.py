"""libvirt / KVM-QEMU 沙箱驱动。

适用于 Ubuntu 22.04 等 Linux 宿主机，使用 KVM 硬件虚拟化 + libvirt 管理。
通过 qemu-guest-agent（QGA）实现文件投递、命令执行与日志回收。

隔离要点：
- ``virsh snapshot-revert`` 回滚到纯净快照；
- 网络使用 isolated/隔离网桥，配合 INetSim/FakeNet 模拟应答，杜绝真实外联；
- 运行后 ``virsh destroy`` 强制关机并再次回滚。
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import time
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger
from app.engines.sandbox.base import SandboxDriver, SandboxRun, run_with_driver
from app.engines.sandbox.drivers.mock_driver import MockDriver

logger = get_logger("sandbox.libvirt")

VIRSH = "virsh"
GUEST_LOG_PATH = r"C:\malscope\behavior.json"


class LibvirtDriver(SandboxDriver):
    name = "libvirt"

    def __init__(self, *args, vm_name=None, snapshot=None, **kwargs):
        super().__init__(vm_name or settings.SANDBOX_VM_NAME, snapshot or settings.SANDBOX_SNAPSHOT, **kwargs)

    @classmethod
    def available(cls) -> bool:
        return shutil.which(VIRSH) is not None

    def _virsh(self, *args, check=True, timeout=120) -> subprocess.CompletedProcess:
        cmd = [VIRSH, *args]
        logger.debug("执行：%s", " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if check and proc.returncode != 0:
            raise RuntimeError(f"virsh {' '.join(args)} 失败：{proc.stderr.strip()}")
        return proc

    def _qga(self, command: str, arguments: dict | None = None, timeout: int = 30) -> dict:
        """通过 qemu-guest-agent 执行命令并返回结果 JSON。"""
        payload = {"execute": command}
        if arguments:
            payload["arguments"] = arguments
        proc = self._virsh(
            "qemu-agent-command", self.vm_name, json.dumps(payload), timeout=timeout
        )
        return json.loads(proc.stdout.strip() or "{}")

    # ---------------- 生命周期 ----------------

    def prepare(self) -> None:
        logger.info("回滚 KVM 虚拟机 %s 到快照 %s", self.vm_name, self.snapshot)
        self._virsh("destroy", self.vm_name, check=False)
        time.sleep(2)
        self._virsh("snapshot-revert", self.vm_name, self.snapshot)
        self._virsh("start", self.vm_name)
        self._started = True
        self._wait_agent()

    def _wait_agent(self, retries: int = 30) -> None:
        for _ in range(retries):
            try:
                self._qga("guest-ping", timeout=10)
                logger.info("guest agent 已就绪")
                return
            except Exception:  # noqa: BLE001
                time.sleep(5)
        logger.warning("等待 guest agent 超时")

    def transfer_sample(self, local_path: Path, guest_path: str) -> None:
        data = base64.b64encode(local_path.read_bytes()).decode()
        handle = self._qga("guest-file-open", {"path": guest_path, "mode": "wb"})
        fh = handle.get("return")
        self._qga("guest-file-write", {"handle": fh, "buf-b64": data})
        self._qga("guest-file-close", {"handle": fh})
        logger.info("样本已通过 QGA 投递到 %s", guest_path)

    def execute(self, guest_path: str) -> None:
        self._qga(
            "guest-exec",
            {
                "path": r"C:\malscope\agent.exe",
                "arg": ["--sample", guest_path, "--timeout", str(self.timeout)],
                "capture-output": True,
            },
        )
        time.sleep(self.timeout)

    def collect_log(self) -> dict:
        try:
            handle = self._qga("guest-file-open", {"path": GUEST_LOG_PATH, "mode": "rb"})
            fh = handle.get("return")
            chunks: list[bytes] = []
            while True:
                resp = self._qga("guest-file-read", {"handle": fh, "count": 1024 * 1024})
                result = resp.get("return", {})
                b64 = result.get("buf-b64")
                if not b64:
                    break
                chunks.append(base64.b64decode(b64))
                if result.get("eof"):
                    break
            self._qga("guest-file-close", {"handle": fh})
            return json.loads(b"".join(chunks).decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("回收行为日志失败：%s", exc)
            return {}

    def revert(self) -> None:
        logger.info("执行结束，强制关机并回滚快照")
        self._virsh("destroy", self.vm_name, check=False)
        time.sleep(2)
        self._virsh("snapshot-revert", self.vm_name, self.snapshot, check=False)
        self._started = False

    def screenshot(self) -> bytes | None:
        out = settings.TMP_DIR / f"kvm_{int(time.time())}.ppm"
        proc = self._virsh("screenshot", self.vm_name, str(out), check=False, timeout=30)
        if proc.returncode == 0 and out.exists():
            return out.read_bytes()
        return None


def run_libvirt(local_path: Path, hints: dict | None = None, **opts) -> SandboxRun:
    if not LibvirtDriver.available():
        logger.warning("未检测到 virsh，动态分析回退到 mock 驱动")
        return run_with_driver(MockDriver(**opts), local_path)
    driver = LibvirtDriver(**opts)
    driver.options["hints"] = hints or {}
    return run_with_driver(driver, local_path)
