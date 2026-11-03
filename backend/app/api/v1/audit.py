"""审计日志接口。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.db import models
from app.db.session import get_db
from app.schemas import AuditOut

router = APIRouter(prefix="/audit", tags=["审计"])


@router.get("", response_model=list[AuditOut], summary="审计日志列表")
def list_audit(
    action: str | None = Query(None),
    username: str | None = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission("audit:read")),
):
    stmt = select(models.AuditLog)
    if action:
        stmt = stmt.where(models.AuditLog.action == action)
    if username:
        stmt = stmt.where(models.AuditLog.username == username)
    stmt = stmt.order_by(models.AuditLog.created_at.desc()).limit(limit).offset(offset)
    return list(db.scalars(stmt).all())
