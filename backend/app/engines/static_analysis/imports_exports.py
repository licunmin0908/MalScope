"""导入表/导出表提取与可疑 API 风险注标。

以 core.constants.SUSPICIOUS_APIS 为知识库，将导入函数映射到：
风险类别 -> 风险等级 -> MITRE ATT&CK 技术 -> 行为提示。
"""

from __future__ import annotations

from app.core.constants import SUSPICIOUS_APIS

_LEVEL_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _build_index() -> dict[str, dict]:
    """构建 API 名 -> 风险信息 的索引（含去 A/W 后缀的归一化键）。"""
    index: dict[str, dict] = {}
    for category, meta in SUSPICIOUS_APIS.items():
        for api in meta["apis"]:
            info = {
                "category": category,
                "level": meta["level"],
                "description": meta["description"],
                "attack": meta["attack"],
            }
            index[api.lower()] = info
            if api.endswith(("A", "W")) and len(api) > 2:
                index.setdefault(api[:-1].lower(), info)
    return index


API_INDEX = _build_index()

# 类别 -> 行为提示（用于静态画像与动态验证建议）
CATEGORY_HINT = {
    "process_injection": "具备进程注入能力，需重点观察 CreateRemoteThread/WriteProcessMemory 调用链",
    "memory_manipulation": "存在动态内存可执行申请，可能用于 Shellcode 执行或脱壳",
    "anti_debug": "包含反调试行为，动态分析需进行反反调试对抗",
    "anti_vm_sandbox": "包含反虚拟机/反沙箱探测，需隐藏虚拟化痕迹",
    "network_c2": "具备网络通信能力，需捕获 C2 外联行为",
    "persistence_registry": "可写注册表自启动项，具备持久化能力",
    "persistence_service": "可创建服务/计划任务，具备高权限持久化能力",
    "file_encryption_ransomware": "疑似勒索加密行为，需监控批量文件改写",
    "defense_evasion": "存在防御规避行为，可能终止安全进程或自删除",
    "credential_access": "具备凭据获取能力（键盘记录/截屏/内存转储）",
    "privilege_escalation": "可进行令牌提权操作",
    "discovery": "具备主机信息探测能力",
    "execution_shell": "可执行命令/脚本宿主，具备寄生虫式执行能力",
    "lateral_movement": "具备横向移动能力（SMB/WMI/远程服务）",
    "crypto": "使用密码学操作，可能用于加解密或校验",
    "dynamic_resolution": "使用动态解析，规避静态导入表检测",
}


def _lookup(name: str) -> dict | None:
    key = name.lower()
    if key in API_INDEX:
        return API_INDEX[key]
    if key.endswith(("a", "w")) and key[:-1] in API_INDEX:
        return API_INDEX[key[:-1]]
    return None


def parse_imports(ctx) -> dict:
    """提取导入表并完成风险注标。"""
    pe = ctx.pe
    imports: list[dict] = []
    summary: dict[str, dict] = {}
    level_counter = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    max_level = "info"

    directory = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
    dll_count = 0
    func_count = 0

    for entry in directory:
        dll_name = (
            entry.dll.decode("utf-8", errors="replace")
            if isinstance(entry.dll, bytes)
            else str(entry.dll)
        )
        dll_count += 1
        for imp in entry.imports:
            func_count += 1
            if imp.name:
                func = imp.name.decode("utf-8", errors="replace")
            else:
                func = f"Ordinal_{imp.ordinal}"
            risk = _lookup(func)
            row = {
                "dll": dll_name,
                "function": func,
                "ordinal": int(imp.ordinal) if imp.ordinal else None,
                "risk_category": None,
                "risk_level": None,
                "description": None,
                "attack": None,
            }
            if risk:
                row.update(
                    {
                        "risk_category": risk["category"],
                        "risk_level": risk["level"],
                        "description": risk["description"],
                        "attack": risk["attack"],
                    }
                )
                cat = risk["category"]
                bucket = summary.setdefault(
                    cat,
                    {
                        "category": cat,
                        "level": risk["level"],
                        "description": risk["description"],
                        "attack": risk["attack"],
                        "apis": [],
                        "count": 0,
                    },
                )
                bucket["apis"].append(f"{dll_name}!{func}")
                bucket["count"] += 1
                if _LEVEL_ORDER[risk["level"]] > _LEVEL_ORDER[bucket["level"]]:
                    bucket["level"] = risk["level"]
                level_counter[risk["level"]] += 1
                if _LEVEL_ORDER[risk["level"]] > _LEVEL_ORDER[max_level]:
                    max_level = risk["level"]
            imports.append(row)

    behavior_hints = [
        f"[{data['level'].upper()}] {CATEGORY_HINT.get(cat, data['description'])}（ATT&CK {data['attack']}）"
        for cat, data in sorted(
            summary.items(), key=lambda kv: _LEVEL_ORDER[kv[1]["level"]], reverse=True
        )
    ]

    return {
        "imports": imports,
        "summary": summary,
        "behavior_hints": behavior_hints,
        "dll_count": dll_count,
        "function_count": func_count,
        "max_risk_level": max_level,
        "level_counter": level_counter,
    }


def parse_exports(ctx) -> list[dict]:
    """提取导出表。"""
    exports: list[dict] = []
    directory = getattr(ctx.pe, "DIRECTORY_ENTRY_EXPORT", None)
    if not directory:
        return exports
    for exp in getattr(directory, "symbols", []):
        name = exp.name.decode("utf-8", errors="replace") if exp.name else f"Ordinal_{exp.ordinal}"
        exports.append(
            {
                "name": name,
                "ordinal": int(exp.ordinal) if exp.ordinal else None,
                "address": hex(int(exp.address)) if exp.address else None,
                "forwarder": (
                    exp.forwarder.decode("utf-8", errors="replace") if exp.forwarder else None
                ),
            }
        )
    return exports
