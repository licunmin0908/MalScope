"""上传安全校验：大小限制、类型限制与压缩炸弹防护。

平台自身不具备直接执行样本的能力；上传接口对文件做前置校验，
压缩包需满足条目数与解压后总大小限制，防止 Zip Bomb 耗尽磁盘/内存。
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("service.security_checks")

BLOCKED_EXTENSIONS = {".lnk", ".url", ".scf", ".inf", ".reg"}

MAX_COMPRESSION_RATIO = 200  # 解压比阈值


class UploadRejected(Exception):
    """上传被拒绝。"""


def check_size(size: int) -> None:
    if size <= 0:
        raise UploadRejected("文件为空")
    if size > settings.MAX_UPLOAD_SIZE:
        raise UploadRejected(
            f"文件大小 {size} 字节超过上限 {settings.MAX_UPLOAD_SIZE} 字节"
        )


def check_extension(filename: str) -> None:
    ext = Path(filename).suffix.lower()
    if ext in BLOCKED_EXTENSIONS:
        raise UploadRejected(f"出于安全考虑，禁止上传 {ext} 类型文件")


def check_archive(path: str | Path) -> dict:
    """检测压缩包是否为压缩炸弹。

    返回 ``{is_archive, entries, extracted_size, ratio, ok, reason}``。
    """
    path = Path(path)
    head = path.open("rb").read(8)
    result = {"is_archive": False, "entries": 0, "extracted_size": 0, "ratio": 0.0, "ok": True, "reason": None}

    if not head.startswith(b"PK\x03\x04") and not head.startswith(b"PK\x05\x06"):
        return result

    result["is_archive"] = True
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            result["entries"] = len(infos)
            total = sum(i.file_size for i in infos)
            compressed = max(sum(i.compress_size for i in infos), 1)
            result["extracted_size"] = total
            result["ratio"] = round(total / compressed, 2)

            if len(infos) > settings.MAX_ARCHIVE_ENTRIES:
                result["ok"] = False
                result["reason"] = f"压缩包条目数 {len(infos)} 超过上限 {settings.MAX_ARCHIVE_ENTRIES}"
            elif total > settings.MAX_EXTRACTED_SIZE:
                result["ok"] = False
                result["reason"] = f"解压后大小 {total} 字节超过上限 {settings.MAX_EXTRACTED_SIZE}"
            elif result["ratio"] > MAX_COMPRESSION_RATIO:
                result["ok"] = False
                result["reason"] = f"压缩比 {result['ratio']} 异常，疑似压缩炸弹"
            # 路径穿越检测
            for info in infos:
                if info.filename.startswith(("/", "\\")) or ".." in info.filename.split("/"):
                    result["ok"] = False
                    result["reason"] = f"压缩包包含可疑路径：{info.filename}"
                    break
    except zipfile.BadZipFile as exc:
        result["ok"] = False
        result["reason"] = f"压缩包损坏或非法：{exc}"
    return result


def validate_upload(filename: str, size: int, path: str | Path) -> dict:
    """综合校验，返回压缩包检测信息。"""
    check_size(size)
    check_extension(filename)
    archive = check_archive(path)
    if not archive["ok"]:
        raise UploadRejected(archive["reason"] or "压缩包校验失败")
    return archive
