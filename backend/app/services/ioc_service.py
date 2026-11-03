"""IOC 持久化服务：保存、去重合并、检索与情报富化。"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db import models

logger = get_logger("service.ioc")


def save_iocs(
    db: Session,
    sample_id: str | None,
    iocs: list[dict],
    *,
    source: str = "static",
    dynamic_id: int | None = None,
) -> list[models.IOC]:
    """保存 IOC；同一 (样本, 类型, 值) 已存在时更新威胁分与上下文。"""
    saved: list[models.IOC] = []
    for item in iocs:
        value = item.get("value")
        ioc_type = item.get("ioc_type")
        if not value or not ioc_type:
            continue
        existing = db.scalar(
            select(models.IOC).where(
                models.IOC.sample_id == sample_id,
                models.IOC.ioc_type == ioc_type,
                models.IOC.value == value,
            )
        )
        if existing:
            existing.threat_score = max(existing.threat_score, item.get("threat_score", 0))
            existing.confidence = max(existing.confidence, item.get("confidence", 0))
            if item.get("context"):
                existing.context = item["context"]
            saved.append(existing)
            continue

        row = models.IOC(
            sample_id=sample_id,
            dynamic_id=dynamic_id,
            ioc_type=ioc_type,
            value=value[:2048],
            context=item.get("context"),
            confidence=int(item.get("confidence", 50)),
            threat_score=int(item.get("threat_score", 0)),
            source=source,
            tags=item.get("tags") or [],
            first_seen=item.get("first_seen") or dt.datetime.now(dt.timezone.utc),
        )
        db.add(row)
        saved.append(row)
    db.commit()
    logger.info("保存 IOC %d 条（样本 %s）", len(saved), sample_id)
    return saved


def list_iocs(
    db: Session,
    *,
    sample_id: str | None = None,
    ioc_type: str | None = None,
    min_score: int | None = None,
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[models.IOC], int]:
    stmt = select(models.IOC)
    if sample_id:
        stmt = stmt.where(models.IOC.sample_id == sample_id)
    if ioc_type:
        stmt = stmt.where(models.IOC.ioc_type == ioc_type)
    if min_score is not None:
        stmt = stmt.where(models.IOC.threat_score >= min_score)
    total = len(db.scalars(stmt).all())
    stmt = stmt.order_by(models.IOC.threat_score.desc()).limit(limit).offset(offset)
    return list(db.scalars(stmt).all()), total


def to_export_rows(iocs: list[models.IOC]) -> list[dict]:
    return [
        {
            "ioc_type": i.ioc_type,
            "value": i.value,
            "source": i.source,
            "context": i.context,
            "confidence": i.confidence,
            "threat_score": i.threat_score,
            "tags": i.tags or [],
        }
        for i in iocs
    ]
