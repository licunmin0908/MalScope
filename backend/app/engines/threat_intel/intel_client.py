"""外部威胁情报源对接：VirusTotal、MISP。

无 API Key 时优雅降级（返回 None 并给出说明），不影响本地分析流程。
所有外发请求均设置超时，避免阻塞主流程。
"""

from __future__ import annotations

import datetime as dt

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("intel.client")

_TIMEOUT = 15


class VirusTotalClient:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or settings.VIRUSTOTAL_API_KEY

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict:
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    def lookup_hash(self, file_hash: str) -> dict | None:
        """查询文件哈希情报。"""
        if not self.enabled:
            return None
        try:
            import requests

            resp = requests.get(
                f"{self.BASE}/files/{file_hash}", headers=self._headers(), timeout=_TIMEOUT
            )
            if resp.status_code == 404:
                return {"verdict": "not_found", "positives": 0, "total_engines": 0, "source": "VirusTotal"}
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            positives = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
            total = sum(int(v) for v in stats.values()) if stats else 0
            verdict = "malicious" if positives > 0 else "clean"
            return {
                "source": "VirusTotal",
                "verdict": verdict,
                "positives": positives,
                "total_engines": total,
                "tags": data.get("tags", []),
                "meaningful_name": data.get("meaningful_name"),
                "raw": {
                    "stats": stats,
                    "type_description": data.get("type_description"),
                    "names": (data.get("names") or [])[:10],
                },
                "fetched_at": dt.datetime.now(dt.timezone.utc),
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("VirusTotal 查询失败：%s", exc)
            return None

    def lookup_domain(self, domain: str) -> dict | None:
        if not self.enabled:
            return None
        try:
            import requests

            resp = requests.get(
                f"{self.BASE}/domains/{domain}", headers=self._headers(), timeout=_TIMEOUT
            )
            if resp.status_code != 200:
                return None
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            positives = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
            return {
                "source": "VirusTotal",
                "verdict": "malicious" if positives else "clean",
                "positives": positives,
                "total_engines": sum(int(v) for v in stats.values()) if stats else 0,
                "raw": {"categories": data.get("categories", {})},
                "fetched_at": dt.datetime.now(dt.timezone.utc),
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("VirusTotal 域名查询失败：%s", exc)
            return None


class MISPClient:
    def __init__(self, url: str | None = None, api_key: str | None = None):
        self.url = (url or settings.MISP_URL).rstrip("/")
        self.api_key = api_key or settings.MISP_API_KEY

    @property
    def enabled(self) -> bool:
        return bool(self.url and self.api_key)

    def push_event(self, info: str, attributes: list[dict]) -> dict | None:
        """将 IOC 推送为 MISP 事件。"""
        if not self.enabled:
            return None
        payload = {
            "Event": {
                "info": info,
                "distribution": 0,
                "threat_level_id": 2,
                "analysis": 1,
                "Attribute": attributes,
            }
        }
        try:
            import requests

            resp = requests.post(
                f"{self.url}/events",
                json=payload,
                headers={
                    "Authorization": self.api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=_TIMEOUT,
                verify=False,  # 内网 MISP 常为自签证书
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            logger.warning("MISP 推送失败：%s", exc)
            return None


def enrich_iocs(iocs: list) -> list:
    """对哈希/IP/域名类 IOC 补充外部情报（仅在配置了 Key 时生效）。"""
    vt = VirusTotalClient()
    if not vt.enabled:
        return iocs
    for ioc in iocs:
        ioc_type = ioc.get("ioc_type") if isinstance(ioc, dict) else getattr(ioc, "ioc_type", None)
        value = ioc.get("value") if isinstance(ioc, dict) else getattr(ioc, "value", None)
        if not value:
            continue
        record = None
        if ioc_type in ("md5", "sha1", "sha256"):
            record = vt.lookup_hash(value)
        elif ioc_type == "domain":
            record = vt.lookup_domain(value)
        if record:
            if isinstance(ioc, dict):
                ioc["intel"] = record
    return iocs
