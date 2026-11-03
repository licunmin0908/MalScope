"""初始化数据：权限、角色、默认管理员、内置壳签名与 YARA 规则。"""

from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import DEFAULT_ADMIN, DEFAULT_ROLES, PACKER_SIGNATURES, PERMISSIONS
from app.core.logging import get_logger
from app.core.security import hash_password
from app.db import models

logger = get_logger("db.init")


def seed_permissions(db: Session) -> dict[str, models.Permission]:
    existing = {p.code: p for p in db.scalars(select(models.Permission)).all()}
    for item in PERMISSIONS:
        if item["code"] not in existing:
            perm = models.Permission(
                code=item["code"], name=item["name"], module=item.get("module")
            )
            db.add(perm)
            existing[item["code"]] = perm
    db.commit()
    return existing


def seed_roles(db: Session, perms: dict[str, models.Permission]) -> None:
    existing = {r.name: r for r in db.scalars(select(models.Role)).all()}
    for item in DEFAULT_ROLES:
        role = existing.get(item["name"])
        if role is None:
            role = models.Role(name=item["name"], description=item["description"])
            db.add(role)
            existing[item["name"]] = role
        role.permissions = [perms[c] for c in item["permissions"] if c in perms]
    db.commit()


def seed_admin(db: Session) -> None:
    user = db.scalar(select(models.User).where(models.User.username == DEFAULT_ADMIN["username"]))
    if user is not None:
        return
    admin = models.User(
        username=DEFAULT_ADMIN["username"],
        email=DEFAULT_ADMIN["email"],
        display_name=DEFAULT_ADMIN["display_name"],
        hashed_password=hash_password(DEFAULT_ADMIN["password"]),
        is_active=True,
        is_superuser=True,
    )
    admin_role = db.scalar(select(models.Role).where(models.Role.name == "超级管理员"))
    if admin_role:
        admin.roles.append(admin_role)
    db.add(admin)
    db.commit()
    logger.info("已创建默认管理员账号：%s", DEFAULT_ADMIN["username"])


def seed_packers(db: Session) -> None:
    existing = {p.name for p in db.scalars(select(models.PackerSignature)).all()}
    # 优先从规则文件加载，便于按需扩展
    source = PACKER_SIGNATURES
    if settings.PACKER_SIGNATURE_FILE.exists():
        try:
            source = json.loads(settings.PACKER_SIGNATURE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:  # pragma: no cover
            logger.warning("壳签名文件解析失败，回退内置定义：%s", exc)
    for item in source:
        if item["name"] in existing:
            continue
        db.add(
            models.PackerSignature(
                name=item["name"],
                category=item.get("category", "packer"),
                section_names=item.get("section_names", []),
                entry_pattern=item.get("entry_pattern"),
                description=item.get("description"),
                severity=item.get("severity", "medium"),
            )
        )
    db.commit()


def seed_yara_rules(db: Session) -> None:
    """将 backend/rules/yara/*.yar 载入规则表（内置规则只读）。"""
    existing = {r.name for r in db.scalars(select(models.YaraRule)).all()}
    rule_dir = settings.YARA_RULE_DIR
    if not rule_dir.exists():
        return
    for yar in sorted(rule_dir.glob("*.yar")):
        text = yar.read_text(encoding="utf-8", errors="ignore")
        name = yar.stem
        if name in existing:
            continue
        db.add(
            models.YaraRule(
                name=name,
                description=f"内置规则文件 {yar.name}",
                source=str(yar.relative_to(settings.YARA_RULE_DIR.parent.parent)),
                rules_text=text,
                author="MalScope",
                severity="medium",
                is_builtin=True,
                is_enabled=True,
            )
        )
    db.commit()


def seed_all(db: Session) -> None:
    perms = seed_permissions(db)
    seed_roles(db, perms)
    seed_admin(db)
    seed_packers(db)
    seed_yara_rules(db)
    logger.info("初始化数据完成：权限 %d 项", len(perms))
