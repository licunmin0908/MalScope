"""样本加密存储服务。

样本以 AES-256-CTR + HMAC-SHA256 加密落盘，磁盘上永不出现明文。
分析时临时解密到隔离目录，分析结束后立即清除。
"""

from __future__ import annotations

import os
import shutil
from contextlib import contextmanager
from pathlib import Path

from app.core import crypto
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("service.storage")


def sample_path(sample_id: str) -> Path:
    """样本密文路径。"""
    return settings.SAMPLE_DIR / f"{sample_id}.enc"


def store_encrypted(src: str | Path, sample_id: str) -> tuple[str, str]:
    """加密保存样本，返回 (存储路径, IV 十六进制)。"""
    dst = sample_path(sample_id)
    iv_hex = crypto.encrypt_file(src, dst, settings.AES_KEY_BYTES)
    logger.info("样本已加密落盘：%s", dst.name)
    return str(dst), iv_hex


@contextmanager
def materialize(sample) -> Path:
    """将加密样本临时解密到隔离目录，退出时自动清除。"""
    tmp_dir = settings.QUARANTINE_DIR / sample.id
    tmp_dir.mkdir(parents=True, exist_ok=True)
    safe_name = _safe_name(sample.original_filename)
    out_path = tmp_dir / safe_name
    try:
        crypto.decrypt_file(sample.storage_path, out_path, settings.AES_KEY_BYTES)
        yield out_path
    finally:
        try:
            if out_path.exists():
                _secure_delete(out_path)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def _safe_name(name: str) -> str:
    """将原始文件名规范化为安全名称，防止路径穿越。"""
    base = os.path.basename(name or "sample.bin")
    keep = [c for c in base if c.isalnum() or c in "._- ()[]"]
    cleaned = "".join(keep).strip() or "sample.bin"
    return cleaned[:180]


def delete_sample(storage_path: str | Path) -> None:
    p = Path(storage_path)
    if p.exists():
        _secure_delete(p)


def _secure_delete(path: Path, passes: int = 1) -> None:
    """覆写后删除（尽力而为，SSD 上不保证彻底擦除）。"""
    try:
        size = path.stat().st_size
        with path.open("r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(min(size, 1024 * 1024)))
                f.flush()
                os.fsync(f.fileno())
    except OSError:
        pass
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
