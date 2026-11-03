"""沙箱驱动抽象接口。

驱动负责：准备隔离环境（快照回滚）→ 投递样本 → 受控执行 → 回收行为日志 → 环境复原。
所有驱动必须保证“跑一次清一次”，样本运行不影响真实主机与网络。
"""

from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SandboxRun:
    """一次沙箱运行的原始产出。"""

    driver: str
    vm_name: str | None = None
    snapshot: str | None = None
    guest_os: str | None = None
    started_at: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))
    duration_sec: int = 0
    status: str = "success"
    log: dict = field(default_factory=dict)
    screenshots: list[str] = field(default_factory=list)
    error: str | None = None
    network_mode: str = "isolated"


class SandboxDriver(ABC):
    """沙箱驱动基类。"""

    name: str = "base"

    def __init__(self, vm_name: str | None = None, snapshot: str | None = None,
                 timeout: int = 120, **options):
        self.vm_name = vm_name
        self.snapshot = snapshot
        self.timeout = timeout
        self.options = options
        self._started = False

    @classmethod
    @abstractmethod
    def available(cls) -> bool:
        """当前主机是否具备该虚拟化能力。"""

    @abstractmethod
    def prepare(self) -> None:
        """回滚到干净快照，准备隔离环境。"""

    @abstractmethod
    def transfer_sample(self, local_path: Path, guest_path: str) -> None:
        """将样本投递到客户机。"""

    @abstractmethod
    def execute(self, guest_path: str) -> None:
        """在客户机中受控执行样本，受超时限制。"""

    @abstractmethod
    def collect_log(self) -> dict:
        """回收客户机内采集到的行为日志。"""

    @abstractmethod
    def revert(self) -> None:
        """执行完毕回滚快照，清除环境残留。"""

    def screenshot(self) -> bytes | None:
        """可选：截取客户机屏幕。"""
        return None

    def _start_guest(self) -> None:  # pragma: no cover - 具体驱动覆盖
        raise NotImplementedError


def run_with_driver(driver: SandboxDriver, local_path: Path, guest_path: str = r"C:\Users\analyst\Desktop\sample.exe") -> SandboxRun:
    """通用执行流程（模板方法）。"""
    started = dt.datetime.now(dt.timezone.utc)
    run = SandboxRun(driver=driver.name, vm_name=driver.vm_name, snapshot=driver.snapshot)
    try:
        driver.prepare()
        driver.transfer_sample(local_path, guest_path)
        driver.execute(guest_path)
        run.log = driver.collect_log()
        run.status = "success"
    except Exception as exc:  # noqa: BLE001
        run.status = "failed"
        run.error = str(exc)
        run.log = run.log or {}
    finally:
        try:
            driver.revert()
        except Exception as exc:  # noqa: BLE001
            run.error = (run.error or "") + f" | 回滚失败: {exc}"
    run.duration_sec = int((dt.datetime.now(dt.timezone.utc) - started).total_seconds())
    return run
