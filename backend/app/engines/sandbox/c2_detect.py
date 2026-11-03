"""C2 外联与 DGA 域名检测启发式。

信号来源：
- 端口（远控常用端口）、协议（长连接心跳）、HTTP 特征（POST 到固定路径、可疑 UA）；
- 域名结构（长度、数字/连字符占比、元音比例、随机性）用于 DGA 判定；
- 与内网/良性基础设施的对齐（在白名单中的不判为 C2）。
"""

from __future__ import annotations

import math
import re
from collections import Counter

from app.utils.net import is_benign_domain, is_private_ip

SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337, 8080, 8443, 9001, 1080, 4443, 1234, 9999, 7777}
COMMON_PORTS = {80, 443, 53, 25, 110, 143, 587, 993, 995, 3389}

_C2_PATH_HINTS = ("gate.php", "/panel/", "/c2/", "/cmd", "/bot", "/ping", "/api/gate", "/report.php")
_DGA_TLDS = (".top", ".xyz", ".tk", ".ml", ".ga", ".gq", ".cf", ".pw", ".cc", ".su", ".icu", ".online", ".site")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_dga(domain: str) -> bool:
    """基于字符分布启发式判定 DGA 域名。"""
    if not domain:
        return False
    labels = domain.lower().strip(".").split(".")
    if len(labels) < 2:
        return False
    sld = labels[-2]
    tld = "." + labels[-1]
    if len(sld) < 8:
        return False
    vowels = sum(1 for c in sld if c in "aeiou")
    digits = sum(1 for c in sld if c.isdigit())
    vowel_ratio = vowels / len(sld)
    digit_ratio = digits / len(sld)
    ent = _entropy(sld)
    # 无元音/元音极少、数字偏多、熵高 → 疑似 DGA
    score = 0
    if vowel_ratio < 0.15:
        score += 2
    if digit_ratio > 0.25:
        score += 2
    if ent > 3.4:
        score += 2
    if len(sld) > 16:
        score += 1
    if tld in _DGA_TLDS:
        score += 1
    return score >= 4


def score_c2(flow: dict) -> tuple[bool, int, str | None]:
    """对单条网络流给出 (是否C2, 置信度, 原因)。"""
    reasons: list[str] = []
    confidence = 0

    dst_ip = flow.get("dst_ip")
    domain = flow.get("domain") or flow.get("tls_sni") or flow.get("dns_query")
    port = flow.get("dst_port")
    url = flow.get("url") or ""

    if dst_ip and is_private_ip(dst_ip):
        return False, 0, None
    if domain and is_benign_domain(domain):
        return False, 0, None

    if port in SUSPICIOUS_PORTS:
        confidence += 35
        reasons.append(f"目的端口 {port} 为常见远控端口")

    low = url.lower()
    for hint in _C2_PATH_HINTS:
        if hint in low:
            confidence += 40
            reasons.append(f"HTTP 路径命中 C2 特征 {hint}")
            break

    ua = (flow.get("user_agent") or "")
    if ua and ("MSIE 7.0" in ua or "MSIE 6.0" in ua or ua.startswith("curl") or "python" in ua.lower()):
        confidence += 20
        reasons.append("User-Agent 陈旧或非浏览器特征")

    if domain and is_dga(domain):
        confidence += 40
        reasons.append("域名结构符合 DGA 生成特征")

    if domain and domain.lower().endswith(_DGA_TLDS):
        confidence += 15
        reasons.append(f"使用高风险 TLD {domain.split('.')[-1]}")

    if flow.get("http_method") == "POST" and port in (80, 443, 8080, 8443):
        confidence += 10

    if domain and dst_ip and port in COMMON_PORTS and not reasons:
        confidence += 5

    confidence = min(confidence, 99)
    is_c2 = confidence >= 50
    return is_c2, confidence, ("；".join(reasons) if reasons else None)


def analyze_flows(flows: list[dict]) -> dict:
    """批量标注网络流，返回统计。"""
    c2_count = 0
    dga_domains: list[str] = []
    for flow in flows:
        is_c2, conf, reason = score_c2(flow)
        flow["is_c2"] = is_c2
        flow["c2_confidence"] = max(conf, flow.get("c2_confidence", 0))
        flow["c2_reason"] = reason or flow.get("c2_reason")
        if is_c2:
            c2_count += 1
        dom = flow.get("domain") or flow.get("dns_query")
        if dom and is_dga(dom) and dom not in dga_domains:
            dga_domains.append(dom)
    return {"c2_count": c2_count, "dga_domains": dga_domains}
