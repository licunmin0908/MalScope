"""样本库接口：上传、检索、下载（二次授权）、删除、相似样本关联。"""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_client_ip, require_permission
from app.core.config import settings
from app.core.logging import get_logger
from app.db import models
from app.db.session import get_db
from app.engines.static_analysis.hashing import fuzzy_compare
from app.schemas import SampleOut, SampleUpdate
from app.services import audit, sample_service, storage
from app.services.security_checks import UploadRejected, validate_upload

logger = get_logger("api.samples")
router = APIRouter(prefix="/samples", tags=["样本库"])


@router.post("/upload", response_model=SampleOut, summary="上传样本（加密入库 + 哈希去重）")
async def upload_sample(
    request: Request,
    file: UploadFile = File(...),
    description: str | None = Form(None),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_permission("sample:upload")),
):
    tmp_path = settings.TMP_DIR / f"upload_{uuid.uuid4().hex}"
    size = 0
    try:
        with tmp_path.open("wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > settings.MAX_UPLOAD_SIZE:
                    raise UploadRejected(f"文件超过上限 {settings.MAX_UPLOAD_SIZE} 字节")
                out.write(chunk)
        archive_info = validate_upload(file.filename or "sample.bin", size, tmp_path)
        sample, created = sample_service.create_sample(
            db, tmp_path, file.filename or "sample.bin",
            uploader=user, upload_ip=get_client_ip(request), description=description,
        )
        audit.record(
            db, action="sample_upload", user=user, resource_type="sample", resource_id=sample.id,
            ip=get_client_ip(request), result="success",
            detail={"filename": file.filename, "size": size, "dedup": not created,
                    "archive": archive_info if archive_info.get("is_archive") else None},
        )
        return sample
    except UploadRejected as exc:
        audit.record(db, action="sample_upload", user=user, resource_type="sample",
                     ip=get_client_ip(request), result="rejected", detail={"reason": str(exc)})
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


@router.get("", summary="样本检索")
def list_samples(
    keyword: str | None = Query(None),
    file_kind: str | None = Query(None),
    threat_level: str | None = Query(None),
    family: str | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission("sample:read")),
):
    items, total = sample_service.search_samples(
        db, keyword=keyword, file_kind=file_kind, threat_level=threat_level,
        family=family, limit=limit, offset=offset,
    )
    return {"total": total, "items": [SampleOut.model_validate(s) for s in items]}


@router.get("/{sample_id}", response_model=SampleOut, summary="样本详情")
def get_sample(sample_id: str, db: Session = Depends(get_db),
               _: models.User = Depends(require_permission("sample:read"))):
    sample = sample_service.get_sample(db, sample_id)
    if not sample:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "样本不存在")
    return sample


@router.put("/{sample_id}", response_model=SampleOut, summary="更新样本标注")
def update_sample(sample_id: str, payload: SampleUpdate, db: Session = Depends(get_db),
                  user: models.User = Depends(require_permission("sample:upload"))):
    sample = sample_service.get_sample(db, sample_id)
    if not sample:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "样本不存在")
    for field in ("family", "tags", "description", "threat_level"):
        value = getattr(payload, field)
        if value is not None:
            setattr(sample, field, value)
    db.commit()
    db.refresh(sample)
    return sample


@router.get("/{sample_id}/download", summary="下载样本（需二次授权确认）")
def download_sample(
    sample_id: str,
    request: Request,
    confirm: bool = Query(False, description="二次授权确认，必须为 true"),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_permission("sample:download")),
):
    sample = sample_service.get_sample(db, sample_id)
    if not sample:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "样本不存在")
    if not confirm:
        audit.record(db, action="sample_download", user=user, resource_type="sample",
                     resource_id=sample_id, result="denied",
                     ip=get_client_ip(request), detail={"reason": "未二次授权"})
        raise HTTPException(status.HTTP_403_FORBIDDEN, "下载样本需二次授权（confirm=true）")

    out_dir = settings.TMP_DIR / f"dl_{uuid.uuid4().hex}"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / Path(sample.original_filename).name
    from app.core import crypto

    crypto.decrypt_file(sample.storage_path, out_path, settings.AES_KEY_BYTES)

    audit.record(db, action="sample_download", user=user, resource_type="sample",
                 resource_id=sample_id, result="success", ip=get_client_ip(request))

    from starlette.background import BackgroundTask

    def _cleanup():
        shutil.rmtree(out_dir, ignore_errors=True)

    return FileResponse(
        str(out_path),
        filename=sample.original_filename,
        media_type="application/octet-stream",
        background=BackgroundTask(_cleanup),
    )


@router.delete("/{sample_id}", summary="删除样本")
def delete_sample(sample_id: str, request: Request, db: Session = Depends(get_db),
                  user: models.User = Depends(require_permission("sample:delete"))):
    ok = sample_service.delete_sample(db, sample_id)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "样本不存在")
    audit.record(db, action="sample_delete", user=user, resource_type="sample",
                 resource_id=sample_id, ip=get_client_ip(request))
    return {"message": "样本已删除"}


@router.get("/{sample_id}/similar", summary="同源/相似样本关联")
def similar_samples(sample_id: str, db: Session = Depends(get_db),
                    _: models.User = Depends(require_permission("sample:read"))):
    sample = sample_service.get_sample(db, sample_id)
    if not sample:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "样本不存在")

    stmt = select(models.Sample).where(models.Sample.id != sample_id)
    if sample.imphash:
        stmt = stmt.where(or_(models.Sample.imphash == sample.imphash,
                              models.Sample.file_kind == sample.file_kind))
    else:
        stmt = stmt.where(models.Sample.file_kind == sample.file_kind)
    candidates = list(db.scalars(stmt.limit(300)).all())

    results = []
    for cand in candidates:
        similarity = 0
        reason = []
        if sample.imphash and cand.imphash == sample.imphash:
            similarity = max(similarity, 95)
            reason.append("imphash 相同（同一构建/加壳特征）")
        if sample.ssdeep and cand.ssdeep:
            ratio = fuzzy_compare(sample.ssdeep, cand.ssdeep)
            similarity = max(similarity, ratio)
            if ratio >= 50:
                reason.append(f"SSDEEP 相似度 {ratio}%")
        if similarity >= 40:
            results.append({
                "sample": SampleOut.model_validate(cand).model_dump(),
                "similarity": similarity,
                "reason": "；".join(reason),
            })
    results.sort(key=lambda r: r["similarity"], reverse=True)
    return {"total": len(results), "items": results[:50]}
