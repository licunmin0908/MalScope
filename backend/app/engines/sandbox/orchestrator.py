"""沙箱编排器：驱动选择、样本投递、受控执行与日志回收。

对外仅暴露 ``SandboxOrchestrator.run(sample, plaintext_path)``，
内部依据配置选择驱动，并保证无论成功与否都执行环境回滚。
"""

from __future__ import annotations

from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger
from app.engines.sandbox.base import run_with_driver
from app.engines.sandbox.drivers import DRIVERS

logger = get_logger("sandbox.orchestrator")

_READ_CAP = 16 * 1024 * 1024


class SandboxOrchestrator:
    def __init__(self, driver_name: str | None = None):
        self.driver_name = (driver_name or settings.SANDBOX_DRIVER).lower()

    def _pick_driver(self):
        cls = DRIVERS.get(self.driver_name, DRIVERS["mock"])
        if not cls.available():
            logger.warning("驱动 %s 不可用，回退 mock", self.driver_name)
            cls = DRIVERS["mock"]
        return cls

    def run(self, sample, plaintext_path: str | Path) -> dict:
        """执行一次沙箱分析，返回原始运行结果（含行为日志）。"""
        path = Path(plaintext_path)
        hints = self._build_hints(sample, path)
        driver_cls = self._pick_driver()
        driver = driver_cls(
            vm_name=settings.SANDBOX_VM_NAME,
            snapshot=settings.SANDBOX_SNAPSHOT,
            timeout=settings.SANDBOX_TIMEOUT,
        )
        driver.options["hints"] = hints
        logger.info("使用 %s 驱动执行样本 %s", driver.name, sample.sha256[:12])

        run = run_with_driver(driver, path)

        return {
            "sandbox_driver": run.driver,
            "vm_name": run.vm_name,
            "snapshot": run.snapshot,
            "guest_os": run.guest_os,
            "duration_sec": run.duration_sec,
            "status": run.status,
            "network_mode": "isolated" if settings.SANDBOX_DISABLE_NETWORK else "simulated",
            "error": run.error,
            "log": run.log,
            "screenshots": run.screenshots,
        }

    def _build_hints(self, sample, path: Path) -> dict:
        """从样本内容提取线索，供 mock 驱动合成与真实驱动参考。"""
        hints: dict = {
            "sha256": sample.sha256,
            "sample_name": sample.original_filename,
            # 静态研判结果用于让沙箱行为强度与静态画像保持一致
            "risk_level": getattr(sample, "threat_level", "unknown"),
            "risk_score": getattr(sample, "risk_score", 0),
            "packer": getattr(sample, "packer", None),
            "domains": [],
            "ips": [],
            "urls": [],
            "strings_sample": [],
            "apis": [],
        }
        try:
            from app.engines.static_analysis.strings_extract import extract_strings

            data = path.read_bytes()[:_READ_CAP]
            strings = extract_strings(data)
            hl = strings.get("highlights", {})
            hints["domains"] = hl.get("domain", [])[:10]
            hints["ips"] = hl.get("ipv4", [])[:10]
            hints["urls"] = hl.get("url", [])[:10]
            hints["strings_sample"] = [s["value"] for s in strings.get("strings", [])[:800]]
            hints["apis"] = [s["value"] for s in strings.get("strings", [])
                             if s["category"] == "text"][:800]
        except Exception as exc:  # noqa: BLE001
            logger.warning("构建沙箱线索失败：%s", exc)
        return hints
