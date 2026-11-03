"""威胁情报 / IOC 接口：检索、格式导出、MISP 推送。"""

from __future__ import annotations

import datetime as dt
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.orm import Session

from app.api.deps import get_client_ip, require_permission
from app.db import models
from app.db.session import get_db
from app.engines.threat_intel import exporters
from app.engines.threat_intel.intel_client import MISPClient
from app.schemas import ExportRequest, IoCOut, MispPushRequest
from app.services import audit, ioc_service

router = APIRouter(prefix="/iocs", tags=["威胁情报"])

_MEDIA = {
    "csv": "text/csv",
    "json": "application/json",
    "stix": "application/json",
    "openioc": "application/xml",
}


@router.get("", summary="IOC 列表")
def list_iocs(
    sample_id: str | None = Query(None),
    ioc_type: str | None = Query(None),
    min_score: int | None = Query(None),
    limit: int = Query(200, le=1000),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_permission("ioc:read")),
):
    items, total = ioc_service.list_iocs(
        db, sample_id=sample_id, ioc_type=ioc_type, min_score=min_score,
        limit=limit, offset=offset,
    )
    return {"total": total, "items": [IoCOut.model_validate(i) for i in items]}


@router.post("/export", summary="导出 IOC（CSV/JSON/STIX/OpenIOC）")
def export_iocs(
    payload: ExportRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_permission("ioc:export")),
):
    items, _ = ioc_service.list_iocs(
        db, sample_id=payload.sample_id, ioc_type=payload.ioc_type,
        min_score=payload.min_score, limit=5000,
    )
    rows = ioc_service.to_export_rows(items)
    try:
        content = exporters.export(rows, payload.format)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    audit.record(db, action="ioc_export", user=user, resource_type="ioc",
                 ip=get_client_ip(request), detail={"format": payload.format, "count": len(rows)})

    filename = f"malscope_iocs_{dt.datetime.now():%Y%m%d_%H%M%S}.{payload.format}"
    return Response(
        content=content.encode("utf-8") if isinstance(content, str) else content,
        media_type=_MEDIA.get(payload.format, "application/octet-stream"),
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/misp-push", summary="推送样本 IOC 至 MISP")
def push_to_misp(
    payload: MispPushRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_permission("ioc:export")),
):
    sample = db.get(models.Sample, payload.sample_id)
    if not sample:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "样本不存在")
    client = MISPClient()
    if not client.enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "未配置 MISP 服务地址或 API Key")

    attributes = []
    type_map = {
        "md5": "md5", "sha1": "sha1", "sha256": "sha256", "ip": "ip-dst",
        "domain": "domain", "url": "url", "email": "email-src",
        "registry": "regkey", "filepath": "filename", "mutex": "mutex",
    }
    for ioc in sample.iocs:
        misp_type = type_map.get(ioc.ioc_type)
        if misp_type:
            attributes.append({
                "type": misp_type,
                "value": ioc.value,
                "category": "Payload delivery" if misp_type in ("md5", "sha1", "sha256", "filename") else "Network activity",
                "to_ids": ioc.threat_score >= 50,
                "comment": ioc.context,
            })
    info = payload.event_info or f"MalScope 样本 {sample.sha256[:16]} 威胁指标"
    result = client.push_event(info, attributes)
    if result is None:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "MISP 推送失败，请检查配置与网络")
    audit.record(db, action="misp_push", user=user, resource_type="sample",
                 resource_id=sample.id, ip=get_client_ip(request),
                 detail={"attributes": len(attributes)})
    return {"message": "已推送至 MISP", "event": result}
