"""恶意字符串与常量提取。

- 同时提取 ASCII 与 UTF-16LE 字符串，保留偏移；
- 使用正则规则库对字符串分类（URL/IP/域名/邮箱/路径/注册表/命令行/互斥体/Base64/加密常量/勒索特征等）；
- 通过白名单过滤降噪，避免把系统库字符串当作恶意特征；
- 输出按风险优先级排序，并对超量样本做上限截断。
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict

from app.core.constants import STRING_PATTERNS, STRING_WHITELIST

_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,512}")
_UNICODE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,512}")

# 预编译分类规则
_COMPILED = [
    {"name": p["name"], "level": p["level"], "desc": p["desc"], "re": re.compile(p["regex"])}
    for p in STRING_PATTERNS
]

_LEVEL_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_MAX_STRINGS = 6000


def _iter_strings(data: bytes):
    for m in _ASCII_RE.finditer(data):
        yield m.group().decode("latin-1"), "ascii", m.start()
    for m in _UNICODE_RE.finditer(data):
        yield m.group().decode("utf-16le", errors="replace"), "utf-16le", m.start()


def _is_whitelisted(value: str) -> bool:
    return any(w.lower() in value.lower() for w in STRING_WHITELIST)


def _classify(value: str) -> tuple[str, str, str | None]:
    """返回 (category, risk_level, 匹配子串)。

    命中多条规则时取风险最高者；同时返回正则实际匹配到的子串，
    便于把 "version=x.y.z.w" 这类文本精确抽取为 IP/域名等指标。
    """
    best_cat, best_level, best_match = "text", "info", None
    for rule in _COMPILED:
        m = rule["re"].search(value)
        if m and _LEVEL_ORDER[rule["level"]] > _LEVEL_ORDER[best_level]:
            best_cat, best_level, best_match = rule["name"], rule["level"], m.group(0)
    return best_cat, best_level, best_match


# 高亮类指标中的常见误报过滤
def _is_noise(category: str, matched: str, original: str) -> bool:
    low_original = original.lower()
    if category == "ipv4":
        if matched in ("0.0.0.0", "255.255.255.255"):
            return True
        # 版本号/时间戳误判：形如 version="5.1.0.0" 或 1.2.3.4 紧邻 version
        if "version" in low_original or "ver." in low_original or low_original.startswith("v"):
            return True
    if category == "domain":
        # 排除纯数字与常见版本号样式
        if matched.replace(".", "").isdigit():
            return True
    return False


def extract_strings(
    data: bytes,
    *,
    min_length: int = 4,
    max_strings: int = _MAX_STRINGS,
) -> dict:
    """从二进制数据中提取并分类字符串。"""
    seen: set[str] = set()
    rows: list[dict] = []
    by_category: Counter = Counter()
    by_level: Counter = Counter()
    highlights: dict[str, list[str]] = defaultdict(list)
    total_ascii = total_unicode = 0

    for value, encoding, offset in _iter_strings(data):
        if encoding == "ascii":
            total_ascii += 1
        else:
            total_unicode += 1
        value = value.strip()
        if len(value) < min_length or value in seen:
            continue
        seen.add(value)

        whitelisted = _is_whitelisted(value)
        category, level, matched = _classify(value)
        if whitelisted:
            level = "info"

        by_category[category] += 1
        by_level[level] += 1
        _HIGHLIGHT_CATS = ("url", "ipv4", "domain", "registry_key", "cmdline",
                           "mutex", "btc_wallet", "email")
        if category in _HIGHLIGHT_CATS and not whitelisted:
            indicator = (matched or value)[:512]
            if not _is_noise(category, indicator, value) and indicator not in highlights[category]:
                if len(highlights[category]) < 100:
                    highlights[category].append(indicator)

        rows.append(
            {
                "value": value[:1024],
                "encoding": encoding,
                "offset": offset,
                "category": category,
                "risk_level": level,
                "is_whitelisted": whitelisted,
            }
        )

    # 按风险等级降序、去白名单优先排序后截断
    rows.sort(key=lambda r: (_LEVEL_ORDER[r["risk_level"]], not r["is_whitelisted"]), reverse=True)
    truncated = len(rows)
    rows = rows[:max_strings]

    return {
        "strings": rows,
        "counts": {
            "total_ascii": total_ascii,
            "total_unicode": total_unicode,
            "unique": truncated,
            "stored": len(rows),
            "by_category": dict(by_category),
            "by_level": dict(by_level),
        },
        "highlights": {k: v for k, v in highlights.items()},
    }
