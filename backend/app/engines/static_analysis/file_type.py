"""基于魔数（magic）的文件类型识别，用于识破扩展名伪装。"""

from __future__ import annotations

import os
from pathlib import Path

from app.core.constants import (
    DOUBLE_EXTENSION_DECOY,
    FILE_SIGNATURES,
    RISKY_EXTENSIONS,
    SCRIPT_EXTENSIONS,
)

_MIME_MAP = {
    "pe": "application/x-dosexec",
    "elf": "application/x-executable",
    "macho": "application/x-mach-binary",
    "pdf": "application/pdf",
    "office": "application/msword",
    "archive": "application/zip",
    "script": "text/plain",
    "unknown": "application/octet-stream",
}


def _read_head(path: Path, n: int = 512) -> bytes:
    with path.open("rb") as f:
        return f.read(n)


def _has_pe_header(head: bytes) -> bool:
    """进一步确认 MZ 后是否含有效 PE 头。"""
    if len(head) < 0x40:
        return False
    import struct

    e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    return 0x40 <= e_lfanew < 0x10000000


def detect_file_type(path: str | Path) -> dict:
    """返回 ``{kind, description, mime_type, extension, warnings}``。"""
    path = Path(path)
    head = _read_head(path)
    ext = path.suffix.lower()
    kind = "unknown"
    description = "未知文件类型"

    for magic, sig_kind, desc in FILE_SIGNATURES:
        if head.startswith(magic):
            kind, description = sig_kind, desc
            break

    warnings: list[str] = []

    # PE 需二次确认，避免 "MZ" 误判
    if kind == "pe" and not _has_pe_header(head):
        warnings.append("存在 MZ 头但未发现有效 PE 签名，疑似伪造或截断")

    # 扩展名兜底
    if kind == "unknown":
        if ext in SCRIPT_EXTENSIONS:
            kind, description = "script", f"脚本文件 ({ext})"
        elif ext in {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf"}:
            kind, description = "office", f"Office 文档 ({ext})"
        elif ext == ".pdf":
            kind, description = "pdf", "PDF 文档"
        elif ext in {".exe", ".dll", ".sys", ".scr", ".ocx", ".com", ".cpl"}:
            kind, description = "pe", f"可执行文件 ({ext})"

    # 双扩展名诱饵检测：如 invoice.pdf.exe
    parts = path.name.lower().split(".")
    if len(parts) >= 3:
        second_last = "." + parts[-2]
        if ext in RISKY_EXTENSIONS and second_last in DOUBLE_EXTENSION_DECOY:
            warnings.append(f"双扩展名伪装：{second_last}{ext}，常见于钓鱼投递")

    # 扩展名与实际类型不符
    if kind == "pe" and ext and ext not in {".exe", ".dll", ".sys", ".scr", ".ocx", ".com", ".cpl", ".efi", ".mui"}:
        if ext not in {"", ".bin"}:
            warnings.append(f"扩展名 {ext} 与 PE 实际类型不符，疑似伪装")

    return {
        "kind": kind,
        "description": description,
        "mime_type": _MIME_MAP.get(kind, "application/octet-stream"),
        "extension": ext,
        "warnings": warnings,
    }
