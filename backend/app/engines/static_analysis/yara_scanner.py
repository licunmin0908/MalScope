"""YARA 规则匹配引擎封装。

实现要点（含 Windows 兼容处理）：
- 以“读取规则文本 + yara.compile(source=..., namespace=...)”的方式编译，
  而非 filepath，避免 yara-python C 扩展在含非 ASCII 字符（中文路径）的
  文件路径下打不开文件的问题；
- 扫描同样以 data= 传入文件内容，规避同一路径兼容性问题；
- 每条规则独立编译，单条失败不影响其余规则。
"""

from __future__ import annotations

from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("static.yara")

try:
    import yara  # type: ignore

    _HAS_YARA = True
except ImportError:  # pragma: no cover
    yara = None  # type: ignore
    _HAS_YARA = False

_SCAN_TIMEOUT = 60


def _serialize_match(match) -> dict:
    strings = []
    for s in getattr(match, "strings", []):
        identifier = getattr(s, "identifier", str(s))
        instances = getattr(s, "instances", None)
        if instances:
            for inst in instances[:20]:
                data = getattr(inst, "matched_data", b"")
                strings.append(
                    {
                        "identifier": identifier,
                        "offset": int(getattr(inst, "offset", 0)),
                        "data": (
                            data[:120].decode("latin-1", errors="replace")
                            if isinstance(data, bytes)
                            else str(data)[:120]
                        ),
                    }
                )
        else:
            strings.append(
                {
                    "identifier": identifier,
                    "offset": int(getattr(s, "offset", 0)),
                    "data": bytes(s)[:120].decode("latin-1", errors="replace"),
                }
            )
    meta = dict(getattr(match, "meta", {}) or {})
    return {
        "rule_name": match.rule,
        "namespace": getattr(match, "namespace", None) or "default",
        "tags": list(getattr(match, "tags", [])),
        "description": meta.get("description") or meta.get("desc"),
        "severity": meta.get("severity"),
        "meta": meta,
        "matched_strings": strings[:40],
    }


class YaraScanner:
    """YARA 规则扫描器（编译结果缓存复用）。"""

    def __init__(self, rule_dir: Path | None = None):
        self.rule_dir = Path(rule_dir) if rule_dir else settings.YARA_RULE_DIR
        self._rules: list = []
        self._compiled = False
        self.compile_errors: list[str] = []

    def compile(self, extra_rules: dict[str, str] | None = None) -> None:
        """编译规则目录与额外规则文本（按命名空间）。"""
        self._rules = []
        self.compile_errors = []
        if not _HAS_YARA:
            self.compile_errors.append("未安装 yara-python")
            self._compiled = True
            return

        texts: dict[str, str] = {}
        if self.rule_dir.exists():
            for yar in sorted(self.rule_dir.glob("*.yar")):
                try:
                    texts[yar.stem] = yar.read_text(encoding="utf-8", errors="ignore")
                except OSError as exc:
                    self.compile_errors.append(f"{yar.name}: 读取失败 {exc}")
        if extra_rules:
            texts.update(extra_rules)

        if not texts:
            self._compiled = True
            return

        # 优先整体编译（多命名空间一次完成）
        try:
            self._rules = [yara.compile(sources=texts)]
        except Exception as exc:  # noqa: BLE001
            logger.warning("YARA 整体编译失败，改为逐命名空间编译：%s", exc)
            self.compile_errors.append(f"整体编译失败: {exc}")
            self._rules = []
            for ns, text in texts.items():
                try:
                    self._rules.append(yara.compile(sources={ns: text}))
                except Exception as inner:  # noqa: BLE001
                    self.compile_errors.append(f"{ns}: {inner}")
                    logger.warning("YARA 规则 %s 编译失败：%s", ns, inner)

        self._compiled = True
        if self._rules:
            logger.info("YARA 规则编译完成，共 %d 个命名空间", len(self._rules))

    def _ensure(self) -> None:
        if not self._compiled:
            self.compile()

    def scan_data(self, data: bytes) -> list[dict]:
        self._ensure()
        if not _HAS_YARA or not self._rules:
            return []
        results: list[dict] = []
        for rules in self._rules:
            try:
                for match in rules.match(data=data, timeout=_SCAN_TIMEOUT):
                    results.append(_serialize_match(match))
            except Exception as exc:  # noqa: BLE001
                logger.warning("YARA 扫描异常：%s", exc)
        return results

    def scan_file(self, path: str | Path, max_bytes: int = 128 * 1024 * 1024) -> list[dict]:
        self._ensure()
        if not _HAS_YARA or not self._rules:
            return []
        try:
            with Path(path).open("rb") as f:
                data = f.read(max_bytes)
        except OSError as exc:
            logger.warning("YARA 读取样本失败：%s", exc)
            return []
        return self.scan_data(data)


_SCANNER: YaraScanner | None = None


def get_scanner(extra_rules: dict[str, str] | None = None) -> YaraScanner:
    """获取默认扫描器（带缓存）。"""
    global _SCANNER
    if _SCANNER is None or extra_rules:
        scanner = YaraScanner()
        scanner.compile(extra_rules=extra_rules)
        if extra_rules is None:
            _SCANNER = scanner
        return scanner
    return _SCANNER
