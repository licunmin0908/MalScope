"""资源、版本信息与数字签名提取。

- 资源目录：列出图标/清单/版本/自定义资源及其大小与熵值；
- 版本信息：VS_VERSIONINFO 的公司名、产品名、原始文件名等（可用于冒充合法软件）；
- 数字签名：解析 PKCS#7 证书链信息，并在 Windows 上调用 WinVerifyTrust 校验可信性。
"""

from __future__ import annotations

import ctypes
import datetime as dt
import os
from ctypes import wintypes
from pathlib import Path

from app.core.logging import get_logger
from app.engines.static_analysis.pe_parser import section_entropy

logger = get_logger("static.resources")

_RESOURCE_TYPES = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING",
    7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE",
    12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE",
    19: "PLUGPLAY", 20: "VXD", 21: "ANICURSOR", 22: "ANIICON", 23: "HTML",
    24: "MANIFEST",
}


def parse_resources(ctx) -> list[dict]:
    """列出资源条目。"""
    pe = ctx.pe
    resources: list[dict] = []
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if not root:
        return resources

    for type_entry in root.entries:
        type_id = getattr(type_entry, "id", None)
        type_name = _RESOURCE_TYPES.get(type_id, str(type_entry.name) if type_entry.name else f"TYPE_{type_id}")
        if not hasattr(type_entry, "directory"):
            continue
        for name_entry in type_entry.directory.entries:
            res_name = name_entry.name if name_entry.name else str(name_entry.id)
            if not hasattr(name_entry, "directory"):
                continue
            for lang_entry in name_entry.directory.entries:
                data = lang_entry.data
                rva = int(data.struct.OffsetToData)
                size = int(data.struct.Size)
                try:
                    raw = pe.get_data(rva, size)
                except Exception:  # noqa: BLE001
                    raw = b""
                resources.append(
                    {
                        "type": type_name,
                        "type_id": type_id,
                        "name": str(res_name),
                        "language": int(lang_entry.id) if lang_entry.id is not None else None,
                        "size": size,
                        "entropy": round(section_entropy(raw), 4) if raw else 0.0,
                        "language_name": _lang_name(lang_entry.id),
                    }
                )
    return resources


def _lang_name(lang: int | None) -> str:
    return {
        0x0409: "en-US", 0x0804: "zh-CN", 0x0404: "zh-TW", 0x0411: "ja-JP",
        0x040C: "fr-FR", 0x0407: "de-DE", 0x0419: "ru-RU",
    }.get(lang or 0, f"0x{(lang or 0):04x}")


def parse_version_info(ctx) -> dict | None:
    """解析 VS_VERSIONINFO。"""
    pe = ctx.pe
    info = getattr(pe, "FileInfo", None)
    if not info:
        return None
    result: dict = {}
    for fileinfo_list in info:
        for fileinfo in fileinfo_list:
            try:
                key_name = getattr(fileinfo, "Key", b"")
                if key_name == b"StringFileInfo":
                    for table in getattr(fileinfo, "StringTable", []):
                        for key, value in table.entries.items():
                            k = key.decode("utf-8", errors="replace")
                            v = value.decode("utf-8", errors="replace").strip("\x00")
                            result[k] = v
                elif key_name == b"VarFileInfo":
                    for var in getattr(fileinfo, "Var", []) or []:
                        entry = getattr(var, "entry", None)
                        langid = getattr(entry, "langid", None)
                        charset = getattr(entry, "charset", None)
                        if langid is not None:
                            result["Translation"] = f"{langid:#06x}/{charset:#06x}" if charset is not None else f"{langid:#06x}"
            except Exception:  # noqa: BLE001 - 版本信息资源结构不一时忽略
                continue
    return result or None


# ==================== 数字签名 ====================

class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(_GUID)),
    ]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


def _win_verify_trust(path: str) -> tuple[bool | None, str]:
    """调用 WinVerifyTrust 校验 Authenticode 可信性。仅在 Windows 有效。"""
    if os.name != "nt":
        return None, "非 Windows 平台，跳过 Authenticode 校验"
    try:
        action = _GUID(
            0x00AAC56B,
            0xCD44,
            0x11D0,
            (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
        )
        file_info = _WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(_WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = str(path)
        file_info.hFile = None
        file_info.pgKnownSubject = None

        wintrust_data = _WINTRUST_DATA()
        wintrust_data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
        wintrust_data.dwUIChoice = 2  # WTD_UI_NONE
        wintrust_data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
        wintrust_data.dwUnionChoice = 1  # WTD_CHOICE_FILE
        wintrust_data.pFile = ctypes.pointer(file_info)
        wintrust_data.dwStateAction = 1  # WTD_STATEACTION_VERIFY
        wintrust_data.dwProvFlags = 0x00000010  # WTD_CACHE_ONLY_URL_RETRIEVAL（离线）

        wintrust = ctypes.windll.wintrust
        result = wintrust.WinVerifyTrust(
            None, ctypes.byref(action), ctypes.byref(wintrust_data)
        )
        # 释放状态
        wintrust_data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(wintrust_data))

        if result == 0:
            return True, "签名有效且受信任"
        mapping = {
            0x800B0100: "无签名或签名无效 (TRUST_E_NOSIGNATURE)",
            0x800B0109: "证书链不受信任 (CERT_E_UNTRUSTEDROOT)",
            0x800B010A: "证书链不完整 (CERT_E_CHAINING)",
            0x800B0101: "证书已过期 (CERT_E_EXPIRED)",
            0x80096010: "签名摘要不匹配，文件被篡改 (TRUST_E_BAD_DIGEST)",
        }
        return False, mapping.get(result & 0xFFFFFFFF, f"校验失败 (0x{result & 0xFFFFFFFF:08X})")
    except Exception as exc:  # noqa: BLE001
        logger.warning("WinVerifyTrust 调用失败：%s", exc)
        return None, f"校验异常：{exc}"


def _parse_pkcs7(path: Path, ctx) -> dict:
    """从 SECURITY 目录提取 PKCS#7 并解析证书信息。"""
    info: dict = {"certs": []}
    security = getattr(ctx.pe, "DIRECTORY_ENTRY_SECURITY", None)
    data = path.read_bytes()
    if security:
        offset = int(security.struct.VirtualAddress)
        size = int(security.struct.Size)
        der = data[offset: offset + size]
    else:
        der = _find_pkcs7(data)
    if not der:
        return info
    info["pkcs7_size"] = len(der)
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7

        certs = pkcs7.load_der_pkcs7_certificates(der)
        for cert in certs:
            info["certs"].append(
                {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "serial": format(cert.serial_number, "x"),
                    "not_before": cert.not_valid_before_utc.isoformat(),
                    "not_after": cert.not_valid_after_utc.isoformat(),
                    "signature_algorithm": cert.signature_algorithm_oid._name,
                }
            )
    except Exception as exc:  # noqa: BLE001
        info["parse_error"] = str(exc)
    return info


def _find_pkcs7(data: bytes) -> bytes:
    """在文件中定位 Authenticode PKCS#7（ASN.1 SEQUENCE + OID 1.2.840.113549.1.7.2）。"""
    marker = bytes.fromhex("3006" + "06092a864886f70d010702")
    idx = data.find(marker)
    if idx == -1:
        return b""
    return data[idx - 4: idx - 4 + _der_seq_length(data, idx - 4)]


def _der_seq_length(data: bytes, start: int) -> int:
    if start + 2 > len(data):
        return 0
    length = data[start + 1]
    header = 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[start + 2: start + 2 + n], "big")
        header += n
    return header + length


def check_signature(path: str | Path, ctx=None) -> dict:
    """综合返回签名信息：是否签名、证书信息、可信性校验结果。"""
    path = Path(path)
    result: dict = {
        "is_signed": False,
        "trusted": None,
        "trust_message": "",
        "certs": [],
        "signer": None,
    }
    if ctx is not None:
        result.update(_parse_pkcs7(path, ctx))
    else:
        result.update(_parse_pkcs7_basic(path))

    if result.get("certs"):
        result["is_signed"] = True
        result["signer"] = result["certs"][0]["subject"]
        result["issuer"] = result["certs"][0]["issuer"]
        result["valid_from"] = result["certs"][0]["not_before"]
        result["valid_to"] = result["certs"][0]["not_after"]
        result["is_expired"] = _is_expired(result["certs"][0]["not_after"])

    trusted, message = _win_verify_trust(str(path))
    result["trusted"] = trusted
    result["trust_message"] = message
    return result


def _parse_pkcs7_basic(path: Path) -> dict:
    der = _find_pkcs7(path.read_bytes())
    info: dict = {"certs": []}
    if not der:
        return info
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7

        for cert in pkcs7.load_der_pkcs7_certificates(der):
            info["certs"].append(
                {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "serial": format(cert.serial_number, "x"),
                    "not_before": cert.not_valid_before_utc.isoformat(),
                    "not_after": cert.not_valid_after_utc.isoformat(),
                }
            )
    except Exception as exc:  # noqa: BLE001
        info["parse_error"] = str(exc)
    return info


def _is_expired(not_after_iso: str) -> bool:
    try:
        dt_obj = dt.datetime.fromisoformat(not_after_iso)
        return dt_obj < dt.datetime.now(dt.timezone.utc)
    except (ValueError, TypeError):
        return False
