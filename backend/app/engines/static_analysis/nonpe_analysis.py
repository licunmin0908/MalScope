"""非 PE 文件分析：ELF / Office / PDF / 脚本。

每类分析器返回 ``{details, features}``，features 复用可疑特征结构，
以便与 PE 分析结果统一进入风险评分与静态画像。
"""

from __future__ import annotations

import re
from pathlib import Path

from app.core.logging import get_logger
from app.engines.static_analysis.pe_parser import section_entropy
from app.engines.static_analysis.strings_extract import extract_strings

logger = get_logger("static.nonpe")

_TEXT_CAP = 8 * 1024 * 1024


def _feature(code, name, severity, description, evidence=None, attack=None, kind="static") -> dict:
    return {
        "code": code,
        "name": name,
        "severity": severity,
        "description": description,
        "evidence": evidence or [],
        "attack": attack,
        "kind": kind,
    }


# ---------------- ELF ----------------

_ELF_RISKY_SYMBOLS = {
    "ptrace": ("anti_debug", "T1622"),
    "execve": ("execution", "T1059"),
    "fork": ("process", "T1106"),
    "socket": ("network", "T1071"),
    "connect": ("network", "T1071"),
    "system": ("execution", "T1059"),
    "dlopen": ("dynamic_resolution", "T1027.007"),
    "mprotect": ("memory", "T1055"),
    "mmap": ("memory", "T1055"),
    "crypt": ("crypto", "T1027"),
}


def analyze_elf(path: str | Path, data: bytes) -> dict:
    details: dict = {"is_elf": True}
    features: list[dict] = []
    try:
        from elftools.elf.elffile import ELFFile

        with Path(path).open("rb") as f:
            elf = ELFFile(f)
            details["class"] = elf.elfclass
            details["endianness"] = elf.little_endian and "little" or "big"
            details["type"] = elf.header["e_type"]
            details["machine"] = elf.header["e_machine"]
            details["entry_point"] = hex(elf.header["e_entry"])
            sections = []
            for sec in elf.iter_sections():
                if not sec.name:
                    continue
                raw = sec.data() if sec["sh_type"] != "SHT_NOBITS" else b""
                sections.append(
                    {
                        "name": sec.name,
                        "type": sec["sh_type"],
                        "size": sec["sh_size"],
                        "entropy": round(section_entropy(raw), 4) if raw else 0.0,
                        "flags": {"exec": bool(sec["sh_flags"] & 0x4), "write": bool(sec["sh_flags"] & 0x1)},
                    }
                )
            details["sections"] = sections
            # 动态符号 / 依赖
            needed, symbols = [], []
            for sec in elf.iter_sections():
                if sec.name == ".dynstr":
                    try:
                        for s in sec.iter_strtab_syms(sec):
                            pass
                    except Exception:  # noqa: BLE001
                        pass
            dyn = elf.get_section_by_name(".dynamic")
            if dyn:
                for tag in dyn.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        needed.append(tag.needed)
            details["needed_libraries"] = needed
            symtab = elf.get_section_by_name(".dynsym") or elf.get_section_by_name(".symtab")
            if symtab:
                for sym in symtab.iter_symbols():
                    if sym.name:
                        symbols.append(sym.name)
            details["symbol_count"] = len(symbols)
            details["imports"] = symbols[:500]
            risky = [s for s in symbols if s in _ELF_RISKY_SYMBOLS]
            for name in risky:
                cat, attack = _ELF_RISKY_SYMBOLS[name]
                features.append(
                    _feature(f"elf_symbol_{name}", f"ELF 危险符号：{name}", "medium",
                             f"动态符号包含 {name}（{cat}）", attack=attack)
                )
            if sections:
                exec_sections = [s for s in sections if s["flags"]["exec"]]
                if any(s["entropy"] >= 7.2 for s in exec_sections):
                    features.append(_feature("elf_high_entropy_code", "可执行节高熵", "high",
                                             "可执行节区熵值偏高，疑似加壳或加密载荷", attack="T1027.002"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("ELF 解析失败：%s", exc)
        details["error"] = str(exc)
    return {"details": details, "features": features}


# ---------------- Office（宏病毒） ----------------

_SUSPICIOUS_VBA = {
    "AutoOpen": "自动执行宏（打开文档即触发）",
    "Document_Open": "文档打开事件触发",
    "Workbook_Open": "工作簿打开事件触发",
    "Shell": "调用外部命令",
    "WScript.Shell": "调用 WScript Shell 执行命令",
    "CreateObject": "创建 COM 对象（常用于执行命令/下载）",
    "powershell": "调用 PowerShell",
    "cmd.exe": "调用命令提示符",
    "URLDownloadToFile": "下载文件",
    "XMLHTTP": "发起 HTTP 请求",
    "ADODB.Stream": "写入二进制文件（释放载荷）",
    "Environ": "读取环境变量（反沙箱）",
    "Chr(": "字符拼接混淆",
    "StrReverse": "字符串反转混淆",
    "Base64": "Base64 编码",
    "CallByName": "动态调用（混淆）",
}


def analyze_office(path: str | Path, data: bytes) -> dict:
    details: dict = {"is_office": True, "macros": [], "autoexec": False}
    features: list[dict] = []
    try:
        from oletools.olevba import VBA_Parser

        parser = VBA_Parser(str(path))
        macro_count = 0
        for (
            filename, stream_path, vba_filename, vba_code,
        ) in parser.extract_macros():
            macro_count += 1
            suspicious = []
            for kw, desc in _SUSPICIOUS_VBA.items():
                if kw.lower() in vba_code.lower():
                    suspicious.append({"keyword": kw, "description": desc})
                    if kw.startswith(("AutoOpen", "Document_Open", "Workbook_Open")):
                        details["autoexec"] = True
            details["macros"].append(
                {
                    "vba_filename": vba_filename,
                    "size": len(vba_code),
                    "suspicious_keywords": suspicious,
                    "code_preview": vba_code[:2000],
                }
            )
        details["macro_count"] = macro_count
        parser.close()
        if macro_count:
            features.append(_feature("office_macro", "包含 VBA 宏", "high",
                                     f"文档内嵌 {macro_count} 个 VBA 宏（宏病毒常见载体）", attack="T1204.002"))
            if details["autoexec"]:
                features.append(_feature("office_autoexec", "宏自动执行", "critical",
                                         "存在自动执行宏（AutoOpen/Document_Open）", attack="T1204.002"))
        # OLE 对象与外部关系
        if b"\\x00" in data[:8]:
            pass
    except Exception as exc:  # noqa: BLE001
        logger.warning("Office 宏解析失败：%s", exc)
        details["error"] = str(exc)
    return {"details": details, "features": features}


# ---------------- PDF ----------------

_PDF_SUSPICIOUS = {
    b"/JavaScript": ("pdf_js", "PDF 内嵌 JavaScript", "high", "T1204.002"),
    b"/JS": ("pdf_js", "PDF 内嵌 JavaScript", "high", "T1204.002"),
    b"/OpenAction": ("pdf_openaction", "PDF 自动动作", "high", "T1204.002"),
    b"/AA": ("pdf_openaction", "PDF 附加动作", "medium", "T1204.002"),
    b"/Launch": ("pdf_launch", "PDF 启动外部程序", "critical", "T1204.002"),
    b"/EmbeddedFile": ("pdf_embedded", "PDF 内嵌文件", "high", "T1027"),
    b"/SubmitForm": ("pdf_submit", "PDF 表单外发", "medium", "T1041"),
    b"/URI": ("pdf_uri", "PDF 内嵌链接", "low", "T1566"),
    b"/RichMedia": ("pdf_richmedia", "PDF 富媒体（Flash）", "medium", "T1204.002"),
}


def analyze_pdf(path: str | Path, data: bytes) -> dict:
    details: dict = {"is_pdf": True, "objects": data.count(b" obj"), "streams": data.count(b"stream")}
    features: list[dict] = []
    seen: set[str] = set()
    for marker, (code, name, sev, attack) in _PDF_SUSPICIOUS.items():
        count = data.count(marker)
        if count:
            details.setdefault("markers", {})[marker.decode("latin-1")] = count
            if code not in seen:
                seen.add(code)
                features.append(_feature(code, name, sev, f"命中 {count} 次：{marker.decode('latin-1')}", attack=attack))
    # 多级过滤/加密标记
    if b"/Filter" in data and data.count(b"/Filter") > 50:
        features.append(_feature("pdf_obfuscated", "PDF 结构高度混淆", "medium",
                                 "大量 Filter 对象，可能用于规避检测", attack="T1027"))
    return {"details": details, "features": features}


# ---------------- 脚本 ----------------

_SCRIPT_PATTERNS = [
    (re.compile(rb"eval\s*\(", re.I), "script_eval", "动态执行 eval", "medium", "T1059"),
    (re.compile(rb"fromCharCode", re.I), "script_charcode", "字符编码混淆", "medium", "T1027"),
    (re.compile(rb"String\.fromCharCode", re.I), "script_charcode", "字符编码混淆", "medium", "T1027"),
    (re.compile(rb"(?:ActiveXObject|WScript\.Shell|Shell\.Application)", re.I), "script_com", "调用 COM 组件执行命令", "high", "T1059.005"),
    (re.compile(rb"(?:powershell|cmd\.exe|rundll32|regsvr32|mshta|bitsadmin|certutil)", re.I), "script_lolbin", "调用 LOLBin 执行", "high", "T1218"),
    (re.compile(rb"(?:DownloadFile|XMLHTTP|URLDownloadToFile|Invoke-WebRequest|curl|wget)", re.I), "script_download", "下载远程载荷", "high", "T1105"),
    (re.compile(rb"(?:CreateObject)", re.I), "script_createobject", "创建 COM 对象", "medium", "T1059"),
    (re.compile(rb"(?:\\x[0-9a-f]{2}){6,}", re.I), "script_hex", "十六进制编码载荷", "medium", "T1027"),
    (re.compile(rb"[A-Za-z0-9+/]{80,}={0,2}"), "script_base64", "疑似 Base64 大块载荷", "medium", "T1027"),
    (re.compile(rb"(?:net\s+user|net\s+localgroup|whoami|systeminfo|tasklist)", re.I), "script_discovery", "系统信息探测命令", "medium", "T1082"),
    (re.compile(rb"(?:schtasks|reg\s+add|sc\s+create|New-Service)", re.I), "script_persistence", "持久化命令（计划任务/服务/注册表）", "high", "T1053"),
]


def analyze_script(path: str | Path, data: bytes) -> dict:
    text = data[:_TEXT_CAP]
    details: dict = {"is_script": True, "length": len(text)}
    features: list[dict] = []
    seen: set[str] = set()
    for pattern, code, desc, sev, attack in _SCRIPT_PATTERNS:
        if pattern.search(text):
            if code not in seen:
                seen.add(code)
                features.append(_feature(code, desc, sev, f"脚本命中特征：{desc}", attack=attack))
    # 混淆判定：极长单行 / 高熵
    lines = text.splitlines() or [text]
    max_line = max(len(line) for line in lines)
    details["max_line_length"] = max_line
    details["line_count"] = len(lines)
    if max_line > 5000:
        features.append(_feature("script_longline", "超长脚本行", "medium",
                                 f"存在长度 {max_line} 的脚本行，疑似混淆/编码", attack="T1027"))
    ent = section_entropy(text[:65536])
    details["entropy"] = round(ent, 4)
    if ent > 6.0 and len(text) > 4096:
        features.append(_feature("script_entropy", "脚本内容高熵", "medium",
                                 f"脚本熵值 {ent:.2f}，疑似加密/编码内容", attack="T1027"))
    return {"details": details, "features": features}


def analyze_by_kind(kind: str, path: str | Path, data: bytes) -> dict:
    """按文件类型分发到对应分析器。"""
    if kind == "elf":
        return analyze_elf(path, data)
    if kind == "office":
        return analyze_office(path, data)
    if kind == "pdf":
        return analyze_pdf(path, data)
    if kind in ("script", "archive"):
        return analyze_script(path, data)
    return {"details": {}, "features": []}
