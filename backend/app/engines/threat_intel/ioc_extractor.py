"""IOC（威胁指标）自动提取。

从静态分析结果与动态沙箱结果中归纳可用于威胁情报共享与检索的指标：
文件哈希、IP、域名、URL、C2 地址、注册表键、可疑文件路径、互斥体、邮箱、
User-Agent、证书等，并完成内网/良性域名降噪。
"""

from __future__ import annotations

import datetime as dt

from app.engines.threat_intel.scoring import confidence_for, score_ioc
from app.utils.net import is_benign_domain, is_private_ip


def _make_ioc(
    ioc_type: str,
    value: str,
    *,
    source: str,
    context: str | None = None,
    tags: list[str] | None = None,
    is_c2: bool = False,
    is_persistence: bool = False,
) -> dict:
    value = (value or "").strip()
    return {
        "ioc_type": ioc_type,
        "value": value[:2048],
        "source": source,
        "context": (context or "")[:1000],
        "tags": tags or [],
        "confidence": confidence_for(source, ioc_type),
        "threat_score": score_ioc(ioc_type, source=source, context=context,
                                  is_c2=is_c2, is_persistence=is_persistence),
        "is_c2": is_c2,
        "first_seen": dt.datetime.now(dt.timezone.utc),
    }


def extract_from_static(static_result: dict) -> list[dict]:
    """从静态分析结果提取 IOC。"""
    iocs: list[dict] = []

    hashes = static_result.get("hashes", {})
    for algo in ("md5", "sha1", "sha256", "ssdeep"):
        if hashes.get(algo):
            iocs.append(_make_ioc(algo, hashes[algo], source="static", context=f"样本{algo.upper()}"))

    strings = static_result.get("strings", {})
    highlights = strings.get("highlights", {})

    for url in highlights.get("url", []):
        iocs.append(_make_ioc("url", url, source="static", context="静态字符串-URL", tags=["url"]))

    for ip in highlights.get("ipv4", []):
        if is_private_ip(ip):
            continue
        iocs.append(_make_ioc("ip", ip, source="static", context="静态字符串-IP", tags=["ip"]))

    for domain in highlights.get("domain", []):
        if is_benign_domain(domain):
            continue
        iocs.append(_make_ioc("domain", domain, source="static", context="静态字符串-域名", tags=["domain"]))

    for email in highlights.get("email", []):
        iocs.append(_make_ioc("email", email, source="static", context="静态字符串-邮箱"))

    for key in highlights.get("registry_key", []):
        persistence = "run" in key.lower() or "services" in key.lower()
        iocs.append(_make_ioc("registry", key, source="static", context="静态字符串-注册表键",
                              is_persistence=persistence))

    for mutex in highlights.get("mutex", []):
        iocs.append(_make_ioc("mutex", mutex, source="static", context="静态字符串-互斥体"))

    for wallet in highlights.get("btc_wallet", []):
        iocs.append(_make_ioc("c2", wallet, source="static", context="加密货币钱包-赎金",
                              is_c2=True, tags=["ransom"]))

    # 从全量字符串中补充文件路径
    for s in strings.get("strings", [])[:2000]:
        if s.get("category") == "windows_path" and not s.get("is_whitelisted"):
            val = s["value"]
            if any(k in val.lower() for k in ("\\temp\\", "\\appdata\\", "startup", "\\programdata\\")):
                iocs.append(_make_ioc("filepath", val, source="static", context="静态字符串-可疑路径"))

    # 数字签名证书
    sig = static_result.get("signature", {})
    for cert in sig.get("certs", []):
        if cert.get("subject"):
            iocs.append(_make_ioc("certificate", cert["subject"], source="static",
                                  context=f"签名证书 issuer={cert.get('issuer')}"))

    # YARA 命中作为规则类指标
    for m in static_result.get("yara_matches", []):
        iocs.append(_make_ioc("yara", m.get("rule_name"), source="static",
                              context=m.get("description") or "YARA 命中",
                              tags=m.get("tags") or []))

    return dedupe(iocs)


def extract_from_dynamic(dynamic_result: dict) -> list[dict]:
    """从动态沙箱结果提取 IOC（网络外联、C2、注册表、落地文件）。"""
    iocs: list[dict] = []

    for flow in dynamic_result.get("network_flows", []):
        is_c2 = bool(flow.get("is_c2"))
        ctx = f"{flow.get('protocol')} 外联"
        if flow.get("url"):
            iocs.append(_make_ioc("url", flow["url"], source="dynamic", context=ctx,
                                  is_c2=is_c2, tags=["network"]))
        if flow.get("dns_query"):
            if not is_benign_domain(flow["dns_query"]):
                iocs.append(_make_ioc("domain", flow["dns_query"], source="dynamic",
                                      context="DNS 查询", is_c2=is_c2, tags=["dns"]))
        if flow.get("tls_sni") and not is_benign_domain(flow["tls_sni"]):
            iocs.append(_make_ioc("domain", flow["tls_sni"], source="dynamic",
                                  context="TLS SNI", is_c2=is_c2, tags=["tls"]))
        if flow.get("domain") and not is_benign_domain(flow["domain"]):
            iocs.append(_make_ioc("domain", flow["domain"], source="dynamic",
                                  context=ctx, is_c2=is_c2, tags=["network"]))
        dst = flow.get("dst_ip")
        if dst and not is_private_ip(dst):
            ioc_type = "c2" if is_c2 else "ip"
            iocs.append(_make_ioc(ioc_type, dst, source="dynamic",
                                  context=f"{ctx} 目的地址", is_c2=is_c2, tags=["network"]))

    for reg in dynamic_result.get("registry_events", []):
        key = reg.get("key_path", "")
        if not key:
            continue
        persistence = bool(reg.get("is_persistence")) or "run" in key.lower()
        iocs.append(_make_ioc("registry", key, source="dynamic",
                              context=f"注册表 {reg.get('action')}", is_persistence=persistence))

    for fe in dynamic_result.get("file_events", []):
        path = fe.get("path", "")
        if fe.get("action") in ("create", "write", "rename") and path:
            iocs.append(_make_ioc("filepath", path, source="dynamic",
                                  context=f"文件 {fe.get('action')}",
                                  tags=["dropped"] if fe.get("is_dropped") else []))

    return dedupe(iocs)


def dedupe(iocs: list[dict]) -> list[dict]:
    """按 (类型, 值) 去重，保留威胁分最高者。"""
    best: dict[tuple[str, str], dict] = {}
    for ioc in iocs:
        key = (ioc["ioc_type"], ioc["value"].lower())
        if key not in best or ioc["threat_score"] > best[key]["threat_score"]:
            best[key] = ioc
    return sorted(best.values(), key=lambda x: x["threat_score"], reverse=True)


def merge_iocs(*lists: list[dict]) -> list[dict]:
    merged: list[dict] = []
    for lst in lists:
        merged.extend(lst)
    return dedupe(merged)
