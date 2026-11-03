"""报告接口：生成、列表、预览与下载。"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_client_ip, require_permission
from app.db import models
from app.db.session import get_db
from app.schemas import ReportOut
from app.services import audit, report_service

router = APIRouter(prefix="/reports", tags=["报告"])


@router.post("/generate", response_model=ReportOut, summary="生成安全分析报告")
def generate(
    request: Request,
    sample_id: str = Query(...),
    format: str = Query("html", pattern="^(html|pdf|json)$"),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_permission("report:generate")),
):
    sample = db.get(models.Sample, sample_id)
    if not sample:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "样本不存在")
    report = report_service.generate_report(db, sample, fmt=format, user=user)
    audit.record(db, action="report_generate", user=user, resource_type="report",
                 resource_id=report.id, ip=get_client_ip(request),
                 detail={"sample_id": sample_id, "format": format})
    return report


@router.get("", summary="报告列表")
def list_reports(
    sample_id: str | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission("report:read")),
):
    stmt = select(models.Report)
    if sample_id:
        stmt = stmt.where(models.Report.sample_id == sample_id)
    total = len(db.scalars(stmt).all())
    stmt = stmt.order_by(models.Report.created_at.desc()).limit(limit).offset(offset)
    return {"total": total, "items": [ReportOut.model_validate(r) for r in db.scalars(stmt).all()]}


@router.get("/{report_id}/download", summary="下载报告文件")
def download(report_id: str, db: Session = Depends(get_db),
             _: models.User = Depends(require_permission("report:read"))):
    report = db.get(models.Report, report_id)
    if not report or not report.file_path:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "报告不存在")
    path = Path(report.file_path)
    if not path.exists():
        raise HTTPException(status.HTTP_410_GONE, "报告文件已丢失")
    media = {"html": "text/html", "pdf": "application/pdf", "json": "application/json"}.get(
        report.format, "application/octet-stream"
    )
    return FileResponse(str(path), filename=f"{report.title}.{report.format}", media_type=media)


@router.get("/{report_id}/preview", response_class=HTMLResponse, summary="在线预览 HTML 报告")
def preview(report_id: str, db: Session = Depends(get_db),
            _: models.User = Depends(require_permission("report:read"))):
    report = db.get(models.Report, report_id)
    if not report:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "报告不存在")
    if report.format != "html":
        # 非 HTML 报告即时渲染 HTML 预览
        sample = db.get(models.Sample, report.sample_id)
        if not sample:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "样本不存在")
        return HTMLResponse(report_service.render_html(db, sample))
    return HTMLResponse(Path(report.file_path).read_text(encoding="utf-8"))
