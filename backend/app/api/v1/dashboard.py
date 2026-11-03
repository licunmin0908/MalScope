"""仪表盘统计接口。"""

from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db import models
from app.db.session import get_db
from app.schemas import DashboardStats, IoCOut, SampleOut

router = APIRouter(prefix="/dashboard", tags=["仪表盘"])


@router.get("/stats", response_model=DashboardStats, summary="平台总览统计")
def stats(db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
    total_samples = db.scalar(select(func.count(models.Sample.id))) or 0

    level_counts = dict(
        db.execute(
            select(models.Sample.threat_level, func.count(models.Sample.id))
            .group_by(models.Sample.threat_level)
        ).all()
    )
    kind_counts = dict(
        db.execute(
            select(models.Sample.file_kind, func.count(models.Sample.id))
            .group_by(models.Sample.file_kind)
        ).all()
    )
    total_tasks = db.scalar(select(func.count(models.AnalysisTask.id))) or 0
    running_tasks = db.scalar(
        select(func.count(models.AnalysisTask.id)).where(models.AnalysisTask.status == "running")
    ) or 0
    total_iocs = db.scalar(select(func.count(models.IOC.id))) or 0
    c2_iocs = db.scalar(
        select(func.count(models.IOC.id)).where(models.IOC.ioc_type == "c2")
    ) or 0

    recent = list(
        db.scalars(
            select(models.Sample).order_by(models.Sample.created_at.desc()).limit(10)
        ).all()
    )
    top_iocs = list(
        db.scalars(select(models.IOC).order_by(models.IOC.threat_score.desc()).limit(10)).all()
    )

    # ATT&CK 分布
    attck_counter: Counter = Counter()
    for dy in db.scalars(select(models.DynamicAnalysis)).all():
        for t in (dy.attck_techniques or []):
            attck_counter[t.get("name", "未知")] += 1
    attck_distribution = [{"name": k, "count": v} for k, v in attck_counter.most_common(15)]

    return DashboardStats(
        total_samples=total_samples,
        malicious_samples=level_counts.get("malicious", 0),
        suspicious_samples=level_counts.get("suspicious", 0),
        clean_samples=level_counts.get("clean", 0),
        total_tasks=total_tasks,
        running_tasks=running_tasks,
        total_iocs=total_iocs,
        c2_iocs=c2_iocs,
        by_file_kind=kind_counts,
        by_threat_level=level_counts,
        recent_samples=[SampleOut.model_validate(s) for s in recent],
        top_iocs=[IoCOut.model_validate(i) for i in top_iocs],
        attck_distribution=attck_distribution,
    )
