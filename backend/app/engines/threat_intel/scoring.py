"""IOC 与样本威胁评分。

IOC 威胁分（0-100）综合：指标类型权重 + 来源（静态/动态/情报）+ 上下文线索
（是否 C2、是否持久化路径、是否高熵等）。样本威胁分融合静态特征、动态行为与
情报匹配结果，输出 恶意/可疑/无害 与置信度。
"""

from __future__ import annotations

_TYPE_BASE = {
    "sha256": 10, "sha1": 8, "md5": 10, "ssdeep": 5,
    "c2": 85, "ip": 55, "domain": 50, "url": 60,
    "mutex": 30, "registry": 40, "filepath": 25,
    "email": 20, "useragent": 25, "certificate": 30, "cve": 70, "yara": 65,
}

_SOURCE_BONUS = {"static": 0, "dynamic": 10, "intel": 25}


def score_ioc(ioc_type: str, *, source: str = "static", context: str | None = None,
              is_c2: bool = False, is_persistence: bool = False) -> int:
    score = _TYPE_BASE.get(ioc_type, 20)
    score += _SOURCE_BONUS.get(source, 0)
    if is_c2:
        score = max(score, 85)
    if is_persistence:
        score += 10
    ctx = (context or "").lower()
    for kw, bonus in (
        ("powershell", 10), ("cmd.exe", 10), ("rundll32", 8), ("regsvr32", 8),
        ("\\temp\\", 5), ("startup", 12), ("currentversion\\run", 15),
        ("download", 8), ("base64", 6), (".onion", 20), ("bitcoin", 20),
    ):
        if kw in ctx:
            score += bonus
    return max(0, min(score, 100))


def confidence_for(source: str, ioc_type: str) -> int:
    base = {"static": 60, "dynamic": 75, "intel": 90}.get(source, 50)
    if ioc_type in ("sha256", "md5", "sha1"):
        base += 20
    if ioc_type == "c2":
        base += 10
    return min(base, 100)


def score_sample(
    *,
    static_risk: int = 0,
    dynamic_risk: int = 0,
    ioc_scores: list[int] | None = None,
    yara_hits: int = 0,
    intel_positive: bool = False,
) -> dict:
    """融合多源信息给出样本最终危害等级与置信度。"""
    ioc_scores = ioc_scores or []
    score = 0.0
    weights = []

    if static_risk:
        score += static_risk * 0.35
        weights.append(0.35)
    if dynamic_risk:
        score += dynamic_risk * 0.4
        weights.append(0.4)
    if ioc_scores:
        top = sorted(ioc_scores, reverse=True)[:10]
        ioc_component = sum(top) / len(top)
        score += ioc_component * 0.25
        weights.append(0.25)
    if yara_hits:
        bonus = min(yara_hits * 5, 20)
        score += bonus
    if intel_positive:
        score += 20

    if weights:
        norm = sum(weights)
        final = score / norm * (1 if norm <= 1 else 1)
    else:
        final = score
    final = int(max(0, min(final, 100)))

    if final >= 70:
        level = "malicious"
    elif final >= 40:
        level = "suspicious"
    else:
        level = "clean"

    # 置信度：证据来源越多越高
    conf = 40
    conf += 15 if static_risk else 0
    conf += 20 if dynamic_risk else 0
    conf += 15 if ioc_scores else 0
    conf += 10 if intel_positive else 0
    conf = min(conf, 99)

    return {"score": final, "level": level, "confidence": conf}
