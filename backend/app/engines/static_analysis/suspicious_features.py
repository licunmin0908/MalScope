"""可疑特征聚合。

把散落在各子模块的信号（区段异常、加壳、可疑 API、字符串、资源、签名、
时间戳、Overlay 附加数据、TLS 回调等）统一归纳为带严重级别的特征列表，
作为风险评分与静态画像的输入。
"""

from __future__ import annotations

from pathlib import Path

_SEVERITY_SCORE = {"info": 0, "low": 2, "medium": 5, "high": 12, "critical": 20}

# API 类别的误报抑制：单一类别命中数少时整体降级。
# 依据：合法程序（如浏览器、加密组件）也会导入少量高风险 API，
# 需结合“命中数量 + 组合证据”判定，避免把正常软件误判为恶意的。
_LOW_COUNT_DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low", "low": "info"}


def _adjust_api_level(category: str, level: str, count: int) -> str:
    """按命中数量调整 API 类别风险等级。"""
    if category == "file_encryption_ransomware":
        # 勒索判定需要组合证据：命中过少则降级为可疑，避免与正常加密组件混淆
        if count < 3:
            return "medium"
        if count < 6:
            return "high"
        return "critical"
    if count <= 2:
        return _LOW_COUNT_DOWNGRADE.get(level, level)
    if count <= 4 and level == "critical":
        return "high"
    return level


def _feature(code: str, name: str, severity: str, description: str, evidence=None,
             attack: str | None = None, kind: str = "static") -> dict:
    """构造一条可疑特征。

    kind 取值：
    - "static"          实际恶意/异常证据（加壳、区段异常、可疑字符串、Overlay 等）；
    - "api_capability"  导入表能力画像（仅表示“具备某类能力”，不等于恶意，
                        因此在评分中单独低权重处理，避免对正常软件误报）。
    """
    return {
        "code": code,
        "name": name,
        "severity": severity,
        "description": description,
        "evidence": evidence or [],
        "attack": attack,
        "kind": kind,
    }


def detect_overlay(sections: list[dict], file_size: int) -> dict | None:
    """检测文件尾部附加数据（Overlay）：常见于捆绑载荷、加密数据。"""
    if not sections:
        return None
    end = max((s["raw_offset"] + s["raw_size"]) for s in sections)
    if file_size > end + 1024:
        return {"overlay_offset": end, "overlay_size": file_size - end}
    return None


def aggregate_features(
    *,
    pe_result: dict,
    file_type: dict,
    hashes: dict,
    packer: dict,
    imports: dict,
    strings: dict,
    signature: dict,
    resources: list[dict],
    file_size: int,
    path: str | Path | None = None,
) -> list[dict]:
    features: list[dict] = []
    headers = pe_result.get("headers", {})
    sections = pe_result.get("sections", [])

    # ---- 文件层 ----
    for w in file_type.get("warnings", []):
        features.append(_feature("file_disguise", "文件类型伪装", "high", w, attack="T1036"))

    if not signature.get("is_signed"):
        features.append(
            _feature(
                "unsigned",
                "无数字签名",
                "low",
                "样本未携带数字签名，可信度低（非恶意 INDICATOR，仅作参考）",
                attack="T1553.002",
            )
        )
    elif signature.get("trusted") is False:
        features.append(
            _feature(
                "bad_signature",
                "签名不可信/失效",
                "high",
                f"数字签名校验失败：{signature.get('trust_message')}",
                evidence=[signature.get("signer") or ""],
                attack="T1553.002",
            )
        )
    elif signature.get("is_expired"):
        features.append(_feature("expired_signature", "签名证书已过期", "medium", "签名证书已过期"))

    # ---- 时间戳 ----
    for w in headers.get("timestamp_warnings", []):
        features.append(_feature("fake_timestamp", "编译时间戳异常", "medium", w, attack="T1070"))

    # ---- 区段层 ----
    for sec in sections:
        if sec.get("is_suspicious"):
            sev = "high" if sec.get("is_rwx") else "medium"
            features.append(
                _feature(
                    f"section_{sec['name'] or 'unnamed'}",
                    f"可疑节区「{sec['name'] or '空名'}」",
                    sev,
                    sec.get("suspicion_reason") or "节区异常",
                    evidence=[f"熵={sec['entropy']}", f"属性={'/'.join(sec['flags'])}"],
                )
            )

    for ov in pe_result.get("section_overlaps", []):
        features.append(
            _feature(
                "section_overlap",
                "区段重叠",
                "high",
                f"节区 {ov['first']} 与 {ov['second']} 原始数据重叠 {ov['overlap_bytes']} 字节，可能对抗反编译",
                attack="T1027",
            )
        )

    # IP / RVA 一致性：入口点不在任何已映射节区
    if sections:
        ep = headers.get("entry_point_rva", 0)
        inside = any(
            s["virtual_address"] <= ep < s["virtual_address"] + max(s["virtual_size"], s["raw_size"])
            for s in sections
        )
        if not inside and ep:
            features.append(
                _feature(
                    "ep_outside",
                    "入口点不在任何节区",
                    "high",
                    f"入口点 RVA {hex(ep)} 不落在任何已映射节区内，结构被刻意构造",
                )
            )

    # ---- Overlay ----
    overlay = detect_overlay(sections, file_size)
    if overlay:
        sev = "medium" if overlay["overlay_size"] < 1024 * 100 else "high"
        features.append(
            _feature(
                "overlay",
                "存在附加数据(Overlay)",
                sev,
                f"文件尾部含 {overlay['overlay_size']} 字节附加数据，可能捆绑载荷或加密配置",
                evidence=[f"offset={overlay['overlay_offset']}"],
                attack="T1027.009",
            )
        )

    # ---- 加壳 ----
    if packer.get("detected"):
        features.append(
            _feature(
                "packed",
                f"疑似加壳({packer.get('name')})",
                "high" if packer.get("severity") == "high" else "medium",
                "；".join(packer.get("evidence", [])) or "命中加壳特征",
                attack="T1027.002",
            )
        )

    # ---- 导入表 ----
    summary = imports.get("summary", {})
    for cat, data in summary.items():
        level = _adjust_api_level(cat, data["level"], data.get("count", 0))
        sev = {"critical": "critical", "high": "high", "medium": "medium"}.get(level, "low")
        features.append(
            _feature(
                f"api_{cat}",
                f"可疑 API 类别：{cat}",
                sev,
                f"{data['description']}（命中 {data['count']} 个 API）",
                evidence=data["apis"][:10],
                attack=data.get("attack"),
                kind="api_capability",
            )
        )

    # ---- 字符串 ----
    by_cat = strings.get("counts", {}).get("by_category", {})
    if by_cat.get("ransom_note"):
        features.append(_feature("ransom_note", "勒索信文本特征", "critical", "样本包含勒索信文案", attack="T1486"))
    if by_cat.get("btc_wallet"):
        features.append(_feature("btc_wallet", "比特币钱包地址", "high", "样本内嵌加密货币钱包地址", attack="T1486"))
    if by_cat.get("powershell_enc"):
        features.append(_feature("powershell_enc", "PowerShell 编码命令", "high", "存在编码执行的 PowerShell 命令", attack="T1059.001"))
    if by_cat.get("cmdline"):
        features.append(_feature("cmdline", "可疑命令行", "medium", "样本内嵌可疑命令行/脚本宿主调用", attack="T1059"))
    if by_cat.get("registry_key"):
        features.append(_feature("reg_string", "注册表路径字符串", "low", "样本内嵌注册表路径", attack="T1112"))
    hl = strings.get("highlights", {})
    if hl.get("url") or hl.get("domain") or hl.get("ipv4"):
        features.append(
            _feature(
                "network_ioc",
                "网络相关字符串",
                "medium",
                f"提取到 URL={len(hl.get('url', []))} 域名={len(hl.get('domain', []))} IP={len(hl.get('ipv4', []))}",
                evidence=(hl.get("url", []) + hl.get("domain", []) + hl.get("ipv4", []))[:10],
                attack="T1071",
            )
        )
    if by_cat.get("aes_sbox"):
        features.append(_feature("crypto_const", "加密算法常量", "medium", "发现 AES S-Box 等加密常量", attack="T1027"))

    # ---- 资源 ----
    for res in resources:
        if res.get("type") == "MANIFEST" and res.get("entropy", 0) > 6.5:
            features.append(_feature("high_entropy_manifest", "高熵清单资源", "medium", "MANIFEST 资源熵值异常"))

    # ---- TLS 回调 ----
    tls = pe_result.get("tls", {})
    if tls.get("has_tls"):
        features.append(
            _feature("tls_callback", "存在 TLS 回调", "medium", "样本注册 TLS 回调，代码可在入口点前执行", attack="T1055")
        )

    return features


def features_score(features: list[dict]) -> int:
    """由特征严重级别折算风险分（0-100）。"""
    total = 0
    for f in features:
        total += _SEVERITY_SCORE.get(f["severity"], 0)
    return min(total, 100)
