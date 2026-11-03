"""加壳/混淆检测。

判定依据（多信号加权，避免单一特征误报）：
1. 节区名硬签名匹配（UPX/ASPack/FSG/PECompact/Themida/VMProtect 等）；
2. 入口点位于最后一节；
3. 末节熵值显著偏高（加密/压缩）；
4. 导入表极小（DLL 数与函数数异常少，运行期动态解析）；
5. 存在 RWX 节区。
"""

from __future__ import annotations

import json

from app.core.config import settings
from app.core.constants import PACKER_HEURISTICS, PACKER_SIGNATURES

_MEM_EXEC = 0x20000000
_MEM_WRITE = 0x80000000


def _load_signatures() -> list[dict]:
    path = settings.PACKER_SIGNATURE_FILE
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return PACKER_SIGNATURES


SIGNATURES = _load_signatures()


def detect_packer(pe_result: dict, import_summary: dict | None = None) -> dict:
    """返回 ``{detected, name, confidence, severity, evidence[]}``。"""
    if not pe_result.get("is_valid_pe"):
        return {"detected": False, "name": None, "confidence": 0, "severity": "info", "evidence": []}

    sections = pe_result.get("sections", [])
    headers = pe_result.get("headers", {})
    entry_rva = headers.get("entry_point_rva", 0)

    evidence: list[str] = []
    matched_name: str | None = None
    severity = "info"
    score = 0

    # 1) 节区名签名匹配
    section_names = {s["name"].lower() for s in sections}
    for sig in SIGNATURES:
        names = {n.lower() for n in sig.get("section_names", [])}
        if names & section_names:
            matched_name = sig["name"]
            severity = sig.get("severity", "medium")
            score += 55
            evidence.append(
                f"命中壳签名「{sig['name']}」：节区名 {sorted(names & section_names)}（{sig.get('description', '')}）"
            )
            break

    if not sections:
        return {
            "detected": bool(matched_name),
            "name": matched_name,
            "confidence": score,
            "severity": severity,
            "evidence": evidence,
        }

    # 2) 入口点落在最后一节
    last = max(sections, key=lambda s: s["raw_offset"])
    last_start = last["virtual_address"]
    last_end = last_start + max(last["virtual_size"], last["raw_size"])
    ep_in_last = last_start <= entry_rva < last_end
    if ep_in_last:
        score += 20
        evidence.append(f"入口点(RVA {hex(entry_rva)})位于最后一节「{last['name'] or '空名'}」")

    # 3) 末节高熵
    if last["entropy"] >= PACKER_HEURISTICS["high_entropy_threshold"]:
        score += 18
        evidence.append(f"末节熵值 {last['entropy']:.2f} 偏高，疑似压缩/加密载荷")

    # 4) 导入表极小
    if import_summary:
        dll_count = import_summary.get("dll_count", 0)
        func_count = import_summary.get("function_count", 0)
        if dll_count and dll_count <= PACKER_HEURISTICS["tiny_import_dll_threshold"]:
            score += 15
            evidence.append(f"导入 DLL 仅 {dll_count} 个，导入表异常精简")
        if func_count and func_count <= PACKER_HEURISTICS["tiny_import_func_threshold"]:
            score += 12
            evidence.append(f"导入函数仅 {func_count} 个，疑似运行期动态解析")

    # 5) RWX 节区
    rwx = [s["name"] for s in sections if s["is_rwx"]]
    if rwx:
        score += 12
        evidence.append(f"存在可写可执行(RWX)节区：{rwx}")

    # 6) 节区数量极少（仅 1-2 个）也常见于壳
    if len(sections) <= 2 and not matched_name:
        score += 8
        evidence.append(f"节区数量仅 {len(sections)} 个，结构异常精简")

    score = min(score, 100)
    detected = score >= 45 or bool(matched_name)

    if not matched_name and detected:
        matched_name = "未公开/自定义壳（启发式判定）"
        severity = "medium"

    return {
        "detected": detected,
        "name": matched_name,
        "confidence": score,
        "severity": severity,
        "evidence": evidence,
    }
