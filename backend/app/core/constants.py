"""MalScope 知识库加载器。

平台的安全知识（可疑 API 分类、加壳器特征、恶意字符串规则、行为—ATT&CK 映射、
RBAC 权限/角色）存储在数据文件 ``backend/rules/knowledge_base.json`` 中，由本模块
加载为模块级常量，便于按需扩展与版本化管理。

知识库外部化的意义：
1. 分析规则与代码解耦，新增检测能力无需改动引擎代码；
2. 便于评审与查重（规则集以数据形式独立可查）；
3. 支持运行时热更新（重新加载 JSON 即可）。

若数据文件缺失或损坏，则回退到本模块内置的最小默认值，保证平台仍可运行。
"""

from __future__ import annotations

import json
from pathlib import Path

# ============================================================
# 文件类型魔数签名（内置，属纯静态常量）
# ============================================================
FILE_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"MZ", "pe", "Windows PE 可执行文件 (DOS MZ 头)"),
    (b"\x7fELF", "elf", "Linux ELF 可执行文件"),
    (b"\xca\xfe\xba\xbe", "macho", "Mach-O 通用二进制 (Fat)"),
    (b"\xcf\xfa\xed\xfe", "macho", "Mach-O 64 位可执行文件"),
    (b"\xce\xfa\xed\xfe", "macho", "Mach-O 32 位可执行文件"),
    (b"%PDF", "pdf", "PDF 文档"),
    (b"PK\x03\x04", "archive", "ZIP / Office 2007+ / JAR"),
    (b"Rar!\x1a\x07", "archive", "RAR 压缩包"),
    (b"7z\xbc\xaf\x27\x1c", "archive", "7-Zip 压缩包"),
    (b"\x1f\x8b", "archive", "GZIP 压缩流"),
    (b"BZh", "archive", "BZIP2 压缩流"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "office", "OLE 复合文档 (旧版 Office/RTF 容器)"),
    (b"{\\rtf", "office", "RTF 富文本"),
    (b"#!", "script", "脚本文件 (Shebang)"),
    (b"\xef\xbb\xbf", "script", "UTF-8 BOM 文本"),
    (b"SQLite format 3", "unknown", "SQLite 数据库"),
    (b"<!DOC", "script", "HTML 文档"),
    (b"<htm", "script", "HTML 文档"),
    (b"<?xm", "script", "XML 文档"),
]

SCRIPT_EXTENSIONS = {
    ".js", ".vbs", ".vbe", ".jse", ".wsf", ".wsh", ".ps1", ".psm1",
    ".bat", ".cmd", ".py", ".pl", ".sh", ".hta", ".jar", ".scr", ".pyc",
}

RISKY_EXTENSIONS = {".exe", ".dll", ".scr", ".sys", ".com", ".pif", ".cpl", ".jar", ".js", ".vbs", ".hta", ".lnk", ".msi"}

DOUBLE_EXTENSION_DECOY = {".pdf", ".doc", ".docx", ".xls", ".jpg", ".png", ".txt", ".mp4", ".zip"}

# ============================================================
# 最小内置默认值（数据文件缺失时的兜底）
# ============================================================
SUSPICIOUS_APIS: dict[str, dict] = {
    "process_injection": {"level": "high", "description": "进程注入", "attack": "T1055", "apis": []},
    "anti_debug": {"level": "high", "description": "反调试", "attack": "T1622", "apis": []},
    "network_c2": {"level": "high", "description": "网络通信与 C2 外联", "attack": "T1071", "apis": []},
    "persistence_registry": {"level": "high", "description": "注册表持久化", "attack": "T1547", "apis": []},
    "file_encryption_ransomware": {"level": "critical", "description": "文件加密/勒索", "attack": "T1486", "apis": []},
}

PACKER_SIGNATURES: list[dict] = []
PACKER_HEURISTICS = {"high_entropy_threshold": 7.2, "tiny_import_dll_threshold": 3, "tiny_import_func_threshold": 15}
STRING_PATTERNS: list[dict] = []
STRING_WHITELIST: list[str] = ["Microsoft", "Windows", "System32"]
ATTACK_MAPPING: dict[str, dict[str, str]] = {}

PERMISSIONS: list[dict[str, str]] = [
    {"code": "sample:read", "name": "查看样本", "module": "样本库"},
    {"code": "analysis:read", "name": "查看分析结果", "module": "分析引擎"},
]

DEFAULT_ROLES: list[dict] = [
    {"name": "超级管理员", "description": "拥有平台全部权限", "permissions": ["*"]},
]

DEFAULT_ADMIN = {
    "username": "admin",
    "password": "Admin@123456",
    "email": "admin@malscope.local",
    "display_name": "系统管理员",
}

# ============================================================
# 加载外部知识库
# ============================================================
_KB_FILE = Path(__file__).resolve().parents[2] / "rules" / "knowledge_base.json"

_MAP = {
    "suspicious_apis": "SUSPICIOUS_APIS",
    "packer_signatures": "PACKER_SIGNATURES",
    "packer_heuristics": "PACKER_HEURISTICS",
    "string_patterns": "STRING_PATTERNS",
    "string_whitelist": "STRING_WHITELIST",
    "attack_mapping": "ATTACK_MAPPING",
    "permissions": "PERMISSIONS",
    "default_roles": "DEFAULT_ROLES",
    "default_admin": "DEFAULT_ADMIN",
}


def reload_knowledge() -> bool:
    """从 JSON 数据文件加载知识库，返回是否成功。"""
    if not _KB_FILE.exists():
        return False
    try:
        data = json.loads(_KB_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False

    g = globals()
    for src_key, var_name in _MAP.items():
        if src_key in data:
            g[var_name] = data[src_key]

    # 展开角色通配权限
    all_codes = [p["code"] for p in g["PERMISSIONS"]]
    for role in g["DEFAULT_ROLES"]:
        if "*" in role.get("permissions", []):
            role["permissions"] = all_codes
    return True


EXTERNAL_KB_LOADED = reload_knowledge()
KB_VERSION = "1.0.0"
