"""静态风险评分模型。

评分思路（多源融合、抑制单一维度误报）：
1. 特征分为两类：
   - 核心证据（kind=static）：加壳、区段异常(RWX/高熵)、可疑字符串/C2、Overlay、
     TLS 回调、文件伪装等，属于“实际异常证据”，全权重计入；
   - 能力画像（kind=api_capability）：导入表命中的 API 类别，仅表示样本“具备某类
     能力”，正常软件（浏览器、加密组件）同样会导入，故整体权重封顶（默认 25 分），
     且不参与“高危强制抬升”，避免把合法程序判为恶意。
2. 强制抬升仅依据核心证据的数量组合；
3. 有效数字签名（Authenticode 校验通过）显著降权。
"""

from __future__ import annotations

from collections import Counter

LEVEL_THRESHOLDS = {"malicious": 70, "suspicious": 40}

_SEVERITY_WEIGHT = {"critical": 20, "high": 12, "medium": 5, "low": 2, "info": 0}
# 导入表能力画像的总权重上限
_API_CAPABILITY_CAP = 25


def compute_risk(
    features: list[dict],
    *,
    signature: dict | None = None,
    yara_matches: list[dict] | None = None,
) -> dict:
    api_features = [f for f in features if f.get("kind") == "api_capability"]
    core_features = [f for f in features if f.get("kind") != "api_capability"]

    api_score = min(sum(_SEVERITY_WEIGHT.get(f["severity"], 0) for f in api_features), _API_CAPABILITY_CAP)
    core_score = sum(_SEVERITY_WEIGHT.get(f["severity"], 0) for f in core_features)
    score = api_score + core_score

    reasons: list[str] = []
    core_counts = Counter(f["severity"] for f in core_features)
    critical_names = [f["name"] for f in core_features if f["severity"] == "critical"]
    high_names = [f["name"] for f in core_features if f["severity"] == "high"]
    critical_count = core_counts.get("critical", 0)
    high_count = core_counts.get("high", 0)

    # 强制抬升仅基于核心证据
    if critical_count >= 2 or (critical_count >= 1 and high_count >= 2):
        score = max(score, LEVEL_THRESHOLDS["malicious"])
        reasons.append(f"存在严重级证据：{'、'.join(critical_names[:5])}")
    elif critical_count == 1:
        score = max(score, 55)
        reasons.append(f"存在严重级证据（需复核）：{'、'.join(critical_names[:3])}")

    if high_count >= 3:
        score = max(score, LEVEL_THRESHOLDS["malicious"])
        reasons.append(f"命中 {high_count} 项高危证据：{'、'.join(high_names[:5])}")
    elif high_count >= 1:
        score = max(score, LEVEL_THRESHOLDS["suspicious"])

    # YARA 命中加分（规则命中属于较强证据）
    if yara_matches:
        yara_bonus = min(len(yara_matches) * 6, 24)
        score = min(score + yara_bonus, 100)
        reasons.append(f"YARA 规则命中 {len(yara_matches)} 条")

    # 数字签名降权
    trusted = bool(signature and signature.get("trusted") is True)
    if trusted:
        score = max(score - 25, 0)
        reasons.append("Authenticode 签名校验通过，风险降权 25 分")
    elif signature and signature.get("is_signed"):
        score = max(score - 10, 0)
        reasons.append("样本携带数字签名，风险降权 10 分")

    if api_features:
        reasons.append(
            f"导入表能力画像命中 {len(api_features)} 类"
            f"（能力分 {api_score}，仅表示具备相关能力，不单独作为恶意判定依据）"
        )

    score = max(0, min(score, 100))

    if score >= LEVEL_THRESHOLDS["malicious"]:
        level = "malicious"
    elif score >= LEVEL_THRESHOLDS["suspicious"]:
        level = "suspicious"
    elif score == 0 and not features:
        level = "unknown"
    else:
        level = "clean"

    if not reasons:
        reasons.append("未发现明显恶意特征")

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "severity_counts": dict(core_counts),
        "api_capability_score": api_score,
        "core_evidence_score": core_score,
    }
