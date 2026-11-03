"""分析任务接口：发起静态/动态分析、查询任务与结果。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_client_ip, require_permission
from app.db import models
from app.db.session import get_db
from app.schemas import (
    AnalysisRequest,
    DynamicFull,
    StaticFull,
    TaskOut,
)
from app.services import analysis_service, audit

router = APIRouter(prefix="/analysis", tags=["分析引擎"])


def _get_sample(db: Session, sample_id: str) -> models.Sample:
    sample = db.get(models.Sample, sample_id)
    if not sample:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "样本不存在")
    return sample


@router.post("/{sample_id}/run", response_model=TaskOut, summary="发起分析任务")
def create_analysis(
    sample_id: str,
    payload: AnalysisRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_permission("analysis:run")),
):
    sample = _get_sample(db, sample_id)
    if payload.task_type in ("dynamic", "full") and not user.has_permission("sandbox:run"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "缺少动态沙箱分析权限（sandbox:run）")

    task = analysis_service.create_task(db, sample.id, payload.task_type, user=user)
    audit.record(db, action="analysis_run", user=user, resource_type="task",
                 resource_id=task.id, ip=get_client_ip(request),
                 detail={"sample_id": sample_id, "task_type": payload.task_type})

    from app.workers.tasks import enqueue_analysis

    enqueue_analysis(task.id)
    db.refresh(task)
    return task


@router.get("/tasks", summary="任务列表")
def list_tasks(
    sample_id: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission("analysis:read")),
):
    stmt = select(models.AnalysisTask)
    if sample_id:
        stmt = stmt.where(models.AnalysisTask.sample_id == sample_id)
    if status_filter:
        stmt = stmt.where(models.AnalysisTask.status == status_filter)
    total = len(db.scalars(stmt).all())
    stmt = stmt.order_by(models.AnalysisTask.created_at.desc()).limit(limit).offset(offset)
    return {"total": total, "items": [TaskOut.model_validate(t) for t in db.scalars(stmt).all()]}


@router.get("/tasks/{task_id}", response_model=TaskOut, summary="任务详情")
def get_task(task_id: str, db: Session = Depends(get_db),
             _: models.User = Depends(require_permission("analysis:read"))):
    task = db.get(models.AnalysisTask, task_id)
    if not task:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "任务不存在")
    return task


@router.get("/{sample_id}/static", response_model=StaticFull, summary="静态分析结果")
def get_static(sample_id: str, db: Session = Depends(get_db),
               _: models.User = Depends(require_permission("analysis:read"))):
    _get_sample(db, sample_id)
    result = db.scalar(
        select(models.StaticAnalysis)
        .where(models.StaticAnalysis.sample_id == sample_id)
        .order_by(models.StaticAnalysis.id.desc())
    )
    if not result:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "该样本暂无静态分析结果")
    return result


@router.get("/{sample_id}/dynamic", response_model=DynamicFull, summary="动态分析结果")
def get_dynamic(sample_id: str, db: Session = Depends(get_db),
                _: models.User = Depends(require_permission("analysis:read"))):
    _get_sample(db, sample_id)
    result = db.scalar(
        select(models.DynamicAnalysis)
        .where(models.DynamicAnalysis.sample_id == sample_id)
        .order_by(models.DynamicAnalysis.id.desc())
    )
    if not result:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "该样本暂无动态分析结果")
    return result
