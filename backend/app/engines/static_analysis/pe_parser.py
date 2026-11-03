"""PE 文件结构解析与区段分析。

覆盖：DOS 头、NT 头（File/Signature/可选头）、节表、数据目录、
编译时间戳、Rich 头、PDB 路径、各区段熵与读写执行属性，并识别常见异常
（RWX 区段、超高熵、零填充大节、节区名异常、入口点不在可执行节）。
"""

from __future__ import annotations

import datetime as dt
import math
import struct
from collections import Counter
from pathlib import Path

from app.core.logging import get_logger

logger = get_logger("static.pe")

try:
    import pefile  # type: ignore
except ImportError:  # pragma: no cover
    pefile = None  # type: ignore

# 区段属性标志位
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ = 0x40000000
_SCN_MEM_WRITE = 0x80000000
_SCN_CNT_CODE = 0x00000020
_SCN_CNT_INIT_DATA = 0x00000040
_SCN_CNT_UNINIT_DATA = 0x00000080

HIGH_ENTROPY = 7.2


def section_entropy(data: bytes) -> float:
    """计算数据块的香农熵（0-8）。"""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class PEContext:
    """封装一次 PE 解析，供各静态分析子模块复用，避免重复解析。"""

    def __init__(self, path: str | Path):
        if pefile is None:
            raise RuntimeError("未安装 pefile，无法进行 PE 解析")
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.pe = pefile.PE(data=self.data, fast_load=True)
        # 解析数据目录（导入/导出/资源/调试等）
        self.pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"],
            ]
        )

    def close(self) -> None:
        try:
            self.pe.close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self) -> "PEContext":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _ts_to_datetime(ts: int) -> dt.datetime | None:
    try:
        if ts <= 0:
            return None
        return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def parse_headers(ctx: PEContext) -> dict:
    """解析 DOS/NT/可选头与数据目录。"""
    pe = ctx.pe
    dos = pe.DOS_HEADER
    nt = pe.NT_HEADERS
    opt = pe.OPTIONAL_HEADER
    fh = nt.FILE_HEADER

    compile_ts = int(fh.TimeDateStamp)
    compile_dt = _ts_to_datetime(compile_ts)

    ts_warnings: list[str] = []
    if compile_ts == 0:
        ts_warnings.append("编译时间戳为 0，可能被抹除或由工具伪造")
    elif compile_dt and compile_dt > dt.datetime.now(dt.timezone.utc):
        ts_warnings.append("编译时间戳位于未来，时间戳被篡改")
    elif compile_dt and compile_dt.year < 2000:
        ts_warnings.append("编译时间戳异常偏早，疑似伪造")

    data_dirs = []
    for entry in opt.DATA_DIRECTORY:
        if entry.VirtualAddress or entry.Size:
            data_dirs.append(
                {
                    "name": entry.name.replace("IMAGE_DIRECTORY_ENTRY_", ""),
                    "virtual_address": int(entry.VirtualAddress),
                    "size": int(entry.Size),
                }
            )

    machine_map = {
        0x014C: "x86 (I386)",
        0x8664: "x64 (AMD64)",
        0x01C0: "ARM",
        0xAA64: "ARM64",
        0x0200: "IA64",
    }

    dos_header = {
        "e_magic": hex(int(dos.e_magic)),
        "e_lfanew": int(dos.e_lfanew),
        "e_cblp": int(dos.e_cblp),
        "e_cp": int(dos.e_cp),
    }

    nt_headers = {
        "signature": hex(int(nt.Signature)),
        "machine": machine_map.get(int(fh.Machine), hex(int(fh.Machine))),
        "machine_raw": int(fh.Machine),
        "number_of_sections": int(fh.NumberOfSections),
        "time_date_stamp_raw": compile_ts,
        "compile_time": compile_dt.isoformat() if compile_dt else None,
        "characteristics": int(fh.Characteristics),
        "is_dll": bool(fh.Characteristics & 0x2000),
        "is_exe": bool(fh.Characteristics & 0x0002),
        "timestamp_warnings": ts_warnings,
    }

    optional_header = {
        "magic": hex(int(opt.Magic)),
        "is_pe32_plus": int(opt.Magic) == 0x20B,
        "major_linker_version": int(opt.MajorLinkerVersion),
        "minor_linker_version": int(opt.MinorLinkerVersion),
        "size_of_code": int(opt.SizeOfCode),
        "size_of_initialized_data": int(opt.SizeOfInitializedData),
        "size_of_uninitialized_data": int(opt.SizeOfUninitializedData),
        "address_of_entry_point": hex(int(opt.AddressOfEntryPoint)),
        "entry_point_rva": int(opt.AddressOfEntryPoint),
        "image_base": hex(int(opt.ImageBase)),
        "section_alignment": int(opt.SectionAlignment),
        "file_alignment": int(opt.FileAlignment),
        "size_of_image": int(opt.SizeOfImage),
        "size_of_headers": int(opt.SizeOfHeaders),
        "checksum": hex(int(opt.CheckSum)),
        "subsystem": int(opt.Subsystem),
        "subsystem_name": _subsystem_name(int(opt.Subsystem)),
        "dll_characteristics": int(opt.DllCharacteristics),
        "enable_aslr": bool(int(opt.DllCharacteristics) & 0x0040),
        "enable_dep": bool(int(opt.DllCharacteristics) & 0x0100),
        "enable_cfg": bool(int(opt.DllCharacteristics) & 0x4000),
        "has_seh": not bool(int(opt.DllCharacteristics) & 0x0400),
    }

    return {
        "dos_header": dos_header,
        "nt_headers": nt_headers,
        "optional_header": optional_header,
        "data_directories": data_dirs,
        "entry_point": hex(int(opt.AddressOfEntryPoint)),
        "entry_point_rva": int(opt.AddressOfEntryPoint),
        "image_base": hex(int(opt.ImageBase)),
        "compile_timestamp_raw": compile_ts,
        "compile_time": compile_dt,
        "compile_time_iso": compile_dt.isoformat() if compile_dt else None,
        "is_dll": bool(fh.Characteristics & 0x2000),
        "is_pe32_plus": int(opt.Magic) == 0x20B,
        "machine": machine_map.get(int(fh.Machine), hex(int(fh.Machine))),
        "timestamp_warnings": ts_warnings,
        "imphash": _safe_imphash(pe),
    }


def _subsystem_name(value: int) -> str:
    return {
        1: "NATIVE (驱动)",
        2: "WINDOWS_GUI (图形界面)",
        3: "WINDOWS_CUI (控制台)",
        5: "OS2_CUI",
        7: "POSIX_CUI",
        9: "WINDOWS_CE_GUI",
        10: "EFI_APPLICATION",
        14: "XBOX",
        16: "WINDOWS_BOOT_APPLICATION",
    }.get(value, f"UNKNOWN({value})")


def _safe_imphash(pe) -> str | None:
    try:
        value = pe.get_imphash()
        return value or None
    except Exception:  # noqa: BLE001
        return None


def parse_sections(ctx: PEContext) -> list[dict]:
    """解析节表并计算熵、属性与异常。"""
    pe = ctx.pe
    sections: list[dict] = []
    entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    last_index = len(pe.sections) - 1

    for idx, sec in enumerate(pe.sections):
        name = sec.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        raw_data = sec.get_data()
        entropy = round(sec.get_entropy(), 4) if raw_data else 0.0
        ch = int(sec.Characteristics)

        is_exec = bool(ch & _SCN_MEM_EXECUTE)
        is_write = bool(ch & _SCN_MEM_WRITE)
        is_read = bool(ch & _SCN_MEM_READ)
        is_rwx = is_exec and is_write

        va = int(sec.VirtualAddress)
        vsize = int(sec.Misc_VirtualSize)
        raw_size = int(sec.SizeOfRawData)
        raw_ptr = int(sec.PointerToRawData)

        flags = []
        if is_read:
            flags.append("R")
        if is_write:
            flags.append("W")
        if is_exec:
            flags.append("X")
        if ch & _SCN_CNT_CODE:
            flags.append("CODE")
        if ch & _SCN_CNT_INIT_DATA:
            flags.append("DATA")
        if ch & _SCN_CNT_UNINIT_DATA:
            flags.append("BSS")

        # 异常判定
        reasons: list[str] = []
        if is_rwx:
            reasons.append("可写可执行(RWX)，常见于自解码/Shellcode 注入")
        if entropy >= HIGH_ENTROPY and raw_size > 1024:
            reasons.append(f"熵值偏高({entropy:.2f})，疑似加密或压缩数据")
        if raw_size == 0 and vsize > 0:
            reasons.append("原始大小为 0 但虚拟大小非 0，常见于加壳占位")
        if vsize > raw_size * 10 and raw_size > 0:
            reasons.append("虚拟大小远大于原始大小，疑似解压后展开")
        if not name.replace(" ", "").isprintable() or any(c in name for c in ("\x00")):
            reasons.append("节区名含不可打印字符，疑似刻意混淆")
        if idx == last_index and va <= entry_rva < va + max(vsize, raw_size):
            reasons.append("入口点位于最后一节，加壳特征")
        if is_exec and va <= entry_rva < va + max(vsize, raw_size) and name.lower() not in (".text", "code", "text"):
            reasons.append(f"入口点位于非常规代码节 ({name or '空名'})")

        # 节区名熵（短名通常是单字母/单字符）
        sections.append(
            {
                "name": name,
                "index": idx,
                "virtual_address": va,
                "virtual_size": vsize,
                "raw_offset": raw_ptr,
                "raw_size": raw_size,
                "entropy": entropy,
                "md5": _md5(raw_data),
                "sha256": _sha256(raw_data),
                "characteristics": ch,
                "flags": flags,
                "is_readable": is_read,
                "is_writable": is_write,
                "is_executable": is_exec,
                "is_rwx": is_rwx,
                "is_suspicious": bool(reasons),
                "suspicion_reason": "；".join(reasons) if reasons else None,
                "vsize_ratio": round(vsize / raw_size, 2) if raw_size else None,
            }
        )

    return sections


def _md5(data: bytes) -> str | None:
    if not data:
        return None
    import hashlib

    return hashlib.md5(data).hexdigest()


def _sha256(data: bytes) -> str | None:
    if not data:
        return None
    import hashlib

    return hashlib.sha256(data).hexdigest()


def parse_rich_header(ctx: PEContext) -> dict | None:
    """解析 Rich 头，可用于推断编译器/构建工具链。"""
    try:
        rich = ctx.pe.parse_rich_header()
    except Exception:  # noqa: BLE001
        return None
    if not rich:
        return None
    entries = []
    values = rich.get("values", [])
    for i in range(0, len(values), 2):
        if i + 1 < len(values):
            entries.append({"id": hex(values[i]), "count": values[i + 1]})
    return {"checksum": rich.get("checksum"), "entries": entries}


def parse_debug_info(ctx: PEContext) -> dict:
    """提取调试目录中的 PDB 路径与时间戳（构建环境指纹）。"""
    result = {"pdb_path": None, "debug_entries": []}
    pe = ctx.pe
    if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        return result
    for entry in pe.DIRECTORY_ENTRY_DEBUG:
        info = {"type": int(entry.struct.Type), "size": int(entry.struct.SizeOfData)}
        try:
            if getattr(entry, "entry", None) is not None:
                si = entry.entry
                pdb = getattr(si, "PdbFileName", None)
                if isinstance(pdb, bytes):
                    pdb = pdb.rstrip(b"\x00").decode("utf-8", errors="replace")
                if pdb:
                    result["pdb_path"] = pdb
                    info["pdb_path"] = pdb
                info["timestamp"] = int(getattr(si, "TimeDateStamp", 0))
        except Exception:  # noqa: BLE001
            pass
        result["debug_entries"].append(info)
    return result


def parse_tls(ctx: PEContext) -> dict:
    """解析 TLS 回调（恶意代码常用 TLS 回调在入口点前执行）。"""
    if not hasattr(ctx.pe, "DIRECTORY_ENTRY_TLS"):
        return {"has_tls": False, "callbacks": []}
    try:
        tls = ctx.pe.DIRECTORY_ENTRY_TLS.struct
        callbacks = []
        if getattr(tls, "AddressOfCallBacks", 0):
            callbacks = [hex(int(c)) for c in ctx.pe.parse_tls_callbacks()] if hasattr(ctx.pe, "parse_tls_callbacks") else []
        return {
            "has_tls": True,
            "start_address_of_raw_data": hex(int(getattr(tls, "StartAddressOfRawData", 0))),
            "address_of_callbacks": hex(int(getattr(tls, "AddressOfCallBacks", 0))),
            "callbacks": callbacks,
        }
    except Exception:  # noqa: BLE001
        return {"has_tls": True, "callbacks": []}


def find_section_overlaps(sections: list[dict]) -> list[dict]:
    """检测区段在文件中的重叠（可能是反分析构造）。"""
    overlaps = []
    sorted_secs = sorted(sections, key=lambda s: s["raw_offset"])
    for i in range(len(sorted_secs) - 1):
        a = sorted_secs[i]
        b = sorted_secs[i + 1]
        a_end = a["raw_offset"] + a["raw_size"]
        if a["raw_size"] and b["raw_size"] and b["raw_offset"] < a_end:
            overlaps.append(
                {
                    "first": a["name"],
                    "second": b["name"],
                    "overlap_bytes": a_end - b["raw_offset"],
                    "reason": "区段原始数据重叠，可能用于对抗反编译",
                }
            )
    return overlaps


def parse_pe(path: str | Path) -> dict:
    """完整解析 PE，返回结构化字典（供引擎与测试直接调用）。"""
    with PEContext(path) as ctx:
        header_info = parse_headers(ctx)
        sections = parse_sections(ctx)
        debug = parse_debug_info(ctx)
        tls = parse_tls(ctx)
        rich = parse_rich_header(ctx)
        overlaps = find_section_overlaps(sections)
        return {
            "headers": header_info,
            "sections": sections,
            "debug": debug,
            "tls": tls,
            "rich_header": rich,
            "section_overlaps": overlaps,
            "is_valid_pe": True,
        }


def safe_parse_pe(path: str | Path) -> dict:
    """带异常兜底的解析入口。"""
    try:
        return parse_pe(path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("PE 解析失败 %s: %s", path, exc)
        return {"is_valid_pe": False, "error": str(exc)}
