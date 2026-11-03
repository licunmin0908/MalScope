"""检测规则接口：YARA 规则管理与壳特征库查询。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_client_ip, require_permission
from app.db import models
from app.db.session import get_db
from app.schemas import PackerSignatureOut, YaraRuleCreate, YaraRuleOut
from app.services import audit

router = APIRouter(prefix="/rules", tags=["规则库"])


@router.get("/yara", response_model=list[YaraRuleOut], summary="YARA 规则列表")
def list_yara(db: Session = Depends(get_db),
              _: models.User = Depends(require_permission("analysis:read"))):
    return list(db.scalars(select(models.YaraRule).order_by(models.YaraRule.id)).all())


@router.post("/yara", response_model=YaraRuleOut, summary="新增 YARA 规则")
def create_yara(payload: YaraRuleCreate, request: Request, db: Session = Depends(get_db),
                user: models.User = Depends(require_permission("rule:manage"))):
    if db.scalar(select(models.YaraRule).where(models.YaraRule.name == payload.name)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "规则名已存在")
    # 编译校验
    try:
        import yara

        yara.compile(source=payload.rules_text)
    except ImportError:
        pass
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"YARA 规则编译失败：{exc}")

    rule = models.YaraRule(
        name=payload.name, description=payload.description, rules_text=payload.rules_text,
        author=payload.author, severity=payload.severity, tags=payload.tags,
        is_enabled=payload.is_enabled, is_builtin=False, source="custom",
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    audit.record(db, action="rule_create", user=user, resource_type="yara_rule",
                 resource_id=rule.id, ip=get_client_ip(request))
    return rule


@router.put("/yara/{rule_id}/toggle", response_model=YaraRuleOut, summary="启用/停用 YARA 规则")
def toggle_yara(rule_id: int, db: Session = Depends(get_db),
                user: models.User = Depends(require_permission("rule:manage"))):
    rule = db.get(models.YaraRule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "规则不存在")
    rule.is_enabled = not rule.is_enabled
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/yara/{rule_id}", summary="删除 YARA 规则")
def delete_yara(rule_id: int, db: Session = Depends(get_db),
                user: models.User = Depends(require_permission("rule:manage"))):
    rule = db.get(models.YaraRule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "规则不存在")
    if rule.is_builtin:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "内置规则不可删除")
    db.delete(rule)
    db.commit()
    return {"message": "规则已删除"}


@router.get("/packers", response_model=list[PackerSignatureOut], summary="壳特征库")
def list_packers(db: Session = Depends(get_db),
                 _: models.User = Depends(require_permission("analysis:read"))):
    return list(db.scalars(select(models.PackerSignature).order_by(models.PackerSignature.id)).all())
