"""样本库服务：入库、哈希去重、加密落盘、检索。"""

from __future__ import annotations

import uuid
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db import models
from app.engines.static_analysis import file_type as file_type_mod
from app.engines.static_analysis import hashing
from app.services import storage

logger = get_logger("service.sample")


def get_by_sha256(db: Session, sha256: str) -> models.Sample | None:
    return db.scalar(select(models.Sample).where(models.Sample.sha256 == sha256))


def get_sample(db: Session, sample_id: str) -> models.Sample | None:
    return db.get(models.Sample, sample_id)


def create_sample(
    db: Session,
    src_path: str | Path,
    original_filename: str,
    *,
    uploader=None,
    upload_ip: str | None = None,
    description: str | None = None,
) -> tuple[models.Sample, bool]:
    """将明文样本入库（加密存储 + 哈希去重）。

    返回 ``(样本, 是否新建)``；若哈希已存在则返回既有样本且不重复落盘。
    """
    src_path = Path(src_path)
    hashes = hashing.compute_hashes(src_path)

    existing = get_by_sha256(db, hashes["sha256"])
    if existing:
        logger.info("样本已存在（SHA256 命中），复用以去重：%s", existing.id)
        return existing, False

    ftype = file_type_mod.detect_file_type(src_path)
    sample_id = str(uuid.uuid4())
    storage_path, iv_hex = storage.store_encrypted(src_path, sample_id)

    sample = models.Sample(
        id=sample_id,
        original_filename=Path(original_filename).name[:500],
        stored_filename=f"{sample_id}.enc",
        file_size=hashes["size"],
        file_kind=ftype["kind"],
        mime_type=ftype["mime_type"],
        md5=hashes["md5"],
        sha1=hashes["sha1"],
        sha256=hashes["sha256"],
        ssdeep=hashes.get("ssdeep"),
        crc32=hashes.get("crc32"),
        storage_path=storage_path,
        aes_nonce=iv_hex,
        is_encrypted=True,
        threat_level="unknown",
        tags=[],
        description=description,
        uploader_id=getattr(uploader, "id", None),
        upload_ip=upload_ip,
    )
    db.add(sample)
    db.commit()
    db.refresh(sample)
    logger.info("样本入库：%s (%s)", sample.id, sample.sha256[:12])
    return sample, True


def delete_sample(db: Session, sample_id: str) -> bool:
    sample = get_sample(db, sample_id)
    if not sample:
        return False
    storage.delete_sample(sample.storage_path)
    db.delete(sample)
    db.commit()
    logger.info("样本已删除：%s", sample_id)
    return True


def search_samples(
    db: Session,
    *,
    keyword: str | None = None,
    file_kind: str | None = None,
    threat_level: str | None = None,
    family: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[models.Sample], int]:
    """按关键字/类型/等级/家族检索样本。"""
    stmt = select(models.Sample)
    if keyword:
        like = f"%{keyword}%"
        stmt = stmt.where(
            (models.Sample.sha256.like(like))
            | (models.Sample.md5.like(like))
            | (models.Sample.original_filename.like(like))
            | (models.Sample.family.like(like))
        )
    if file_kind:
        stmt = stmt.where(models.Sample.file_kind == file_kind)
    if threat_level:
        stmt = stmt.where(models.Sample.threat_level == threat_level)
    if family:
        stmt = stmt.where(models.Sample.family == family)

    total = len(db.scalars(stmt).all())
    stmt = stmt.order_by(models.Sample.created_at.desc()).limit(limit).offset(offset)
    return list(db.scalars(stmt).all()), total
