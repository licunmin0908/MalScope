"""静态分析总编排。

流程：
文件类型识别 → 多算法哈希 → （PE 深度解析 | 非 PE 类型化分析）→ 导入/导出表
→ 加壳检测 → 资源/版本/签名 → 字符串提取 → YARA 匹配 → 可疑特征聚合 → 风险评分。

任一子步骤异常均被隔离，保证单点失败不影响整体产出。
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger
from app.engines.static_analysis import (
    file_type as file_type_mod,
)
from app.engines.static_analysis import (
    hashing,
    imports_exports,
    nonpe_analysis,
    packer_detect,
    pe_parser,
    resources as resources_mod,
    risk_score,
    strings_extract,
    suspicious_features,
    yara_scanner,
)
from app.engines.static_analysis.pe_parser import section_entropy

logger = get_logger("static.engine")

# 字符串提取读取上限，避免超大文件耗尽内存
_STRINGS_READ_CAP = 64 * 1024 * 1024


def _safe(step: str, func, default, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001
        logger.warning("静态分析步骤 [%s] 失败：%s", step, exc)
        return default


def analyze_file(
    path: str | Path,
    *,
    run_yara: bool = True,
    extra_yara: dict[str, str] | None = None,
) -> dict:
    """对单个样本文件执行完整静态分析，返回结构化结果。"""
    path = Path(path)
    started = dt.datetime.now(dt.timezone.utc)

    # 1) 文件类型
    ftype = _safe("file_type", file_type_mod.detect_file_type, {"kind": "unknown", "warnings": []}, path)

    # 2) 哈希
    hashes = _safe("hashing", hashing.compute_hashes, {}, path)

    # 3) 读取内容（用于字符串/非 PE 分析）
    data = b""
    try:
        with path.open("rb") as f:
            data = f.read(_STRINGS_READ_CAP)
    except OSError as exc:
        logger.warning("读取文件失败：%s", exc)

    overall_entropy = round(section_entropy(data[: 8 * 1024 * 1024]), 4) if data else 0.0

    kind = ftype.get("kind", "unknown")

    pe_result: dict = {"is_valid_pe": False}
    imports: dict = {"imports": [], "summary": {}, "behavior_hints": [], "dll_count": 0, "function_count": 0, "max_risk_level": "info"}
    exports: list[dict] = []
    sections: list[dict] = []
    res_list: list[dict] = []
    version_info = None
    signature: dict = {"is_signed": False, "trusted": None, "certs": []}
    nonpe: dict = {}
    features: list[dict] = []

    headers: dict = {}

    if kind in ("pe", "unknown") and data[:2] == b"MZ":
        # 4) PE 解析
        try:
            with pe_parser.PEContext(path) as ctx:
                headers = pe_parser.parse_headers(ctx)
                sections = pe_parser.parse_sections(ctx)
                debug = pe_parser.parse_debug_info(ctx)
                tls = pe_parser.parse_tls(ctx)
                rich = _safe("rich_header", pe_parser.parse_rich_header, None, ctx)
                overlaps = pe_parser.find_section_overlaps(sections)
                pe_result = {
                    "is_valid_pe": True,
                    "headers": headers,
                    "sections": sections,
                    "debug": debug,
                    "tls": tls,
                    "rich_header": rich,
                    "section_overlaps": overlaps,
                }
                # 5) 导入/导出
                imports = _safe("imports", imports_exports.parse_imports, imports, ctx)
                exports = _safe("exports", imports_exports.parse_exports, [], ctx)
                # 6) 资源 / 版本 / 签名
                res_list = _safe("resources", resources_mod.parse_resources, [], ctx)
                version_info = _safe("version_info", resources_mod.parse_version_info, None, ctx)
                signature = _safe(
                    "signature", resources_mod.check_signature, signature, path, ctx
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("PE 处理失败：%s", exc)
            pe_result = {"is_valid_pe": False, "error": str(exc)}
    else:
        # 非 PE 类型化分析
        nonpe = _safe("nonpe", nonpe_analysis.analyze_by_kind, {"details": {}, "features": []}, kind, path, data)
        features.extend(nonpe.get("features", []))
        signature = _safe("signature", resources_mod.check_signature, signature, path)

    # 7) 加壳检测（仅 PE）
    packer = {"detected": False, "name": None, "confidence": 0, "severity": "info", "evidence": []}
    if pe_result.get("is_valid_pe"):
        packer = _safe("packer", packer_detect.detect_packer, packer, pe_result, imports)

    # 8) 字符串提取
    strings = _safe("strings", strings_extract.extract_strings, {"strings": [], "counts": {}, "highlights": {}}, data)

    # 9) YARA
    yara_matches: list[dict] = []
    if run_yara:
        scanner = yara_scanner.get_scanner(extra_rules=extra_yara)
        yara_matches = _safe("yara", scanner.scan_file, [], path)

    # 10) 可疑特征聚合
    features.extend(
        _safe(
            "features",
            suspicious_features.aggregate_features,
            [],
            pe_result=pe_result,
            file_type=ftype,
            hashes=hashes,
            packer=packer,
            imports=imports,
            strings=strings,
            signature=signature,
            resources=res_list,
            file_size=path.stat().st_size if path.exists() else 0,
            path=path,
        )
    )

    # 11) 风险评分
    risk = _safe("risk", risk_score.compute_risk, {"score": 0, "level": "unknown", "reasons": []},
                 features, signature=signature, yara_matches=yara_matches)

    duration_ms = int((dt.datetime.now(dt.timezone.utc) - started).total_seconds() * 1000)

    summary = _build_summary(hashes, ftype, pe_result, packer, imports, strings, risk, yara_matches)

    return {
        "file_type": ftype,
        "hashes": hashes,
        "overall_entropy": overall_entropy,
        "file_size": path.stat().st_size if path.exists() else 0,
        "pe": pe_result,
        "headers": headers,
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "resources": res_list,
        "version_info": version_info,
        "signature": signature,
        "packer": packer,
        "strings": strings,
        "yara_matches": yara_matches,
        "features": features,
        "risk": risk,
        "summary": summary,
        "duration_ms": duration_ms,
        "analyzed_at": started.isoformat(),
    }


def _build_summary(hashes, ftype, pe_result, packer, imports, strings, risk, yara_matches) -> dict:
    return {
        "kind": ftype.get("kind"),
        "type_desc": ftype.get("description"),
        "sha256": hashes.get("sha256"),
        "md5": hashes.get("md5"),
        "size": hashes.get("size"),
        "is_pe": bool(pe_result.get("is_valid_pe")),
        "packer": packer.get("name") if packer.get("detected") else None,
        "section_count": len(pe_result.get("sections", [])),
        "import_dll_count": imports.get("dll_count", 0),
        "import_func_count": imports.get("function_count", 0),
        "suspicious_api_categories": list(imports.get("summary", {}).keys()),
        "string_highlights": {k: len(v) for k, v in strings.get("highlights", {}).items()},
        "yara_hit_count": len(yara_matches),
        "risk_score": risk.get("score"),
        "risk_level": risk.get("level"),
    }


def analyze_to_dict(path: str | Path, **kwargs) -> dict:
    """便捷入口（供服务层/CLI 调用）。"""
    return analyze_file(path, **kwargs)


if __name__ == "__main__":  # pragma: no cover - 手动调试入口
    import json
    import sys

    if len(sys.argv) < 2:
        print("用法: python -m app.engines.static_analysis.engine <样本路径>")
        raise SystemExit(1)
    result = analyze_file(sys.argv[1])
    print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
