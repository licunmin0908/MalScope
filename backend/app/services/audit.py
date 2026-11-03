"""审计日志服务。

记录样本上传、下载、分析、删除等敏感操作，满足可追溯要求。
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db import models

logger = get_logger("service.audit")


def record(
    db: Session,
    *,
    action: str,
    user=None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    result: str = "success",
    ip: str | None = None,
    user_agent: str | None = None,
    detail: dict | None = None,
) -> models.AuditLog:
    log = models.AuditLog(
        user_id=getattr(user, "id", None),
        username=getattr(user, "username", None),
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        result=result,
        ip=ip,
        user_agent=(user_agent or "")[:500] or None,
        detail=detail,
    )
    db.add(log)
    db.commit()
    logger.info("审计：%s %s %s -> %s", getattr(user, "username", "-"), action, resource_id, result)
    return log
