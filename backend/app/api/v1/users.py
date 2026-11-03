"""用户与权限管理接口（RBAC）。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_client_ip, get_current_user, require_permission
from app.core.security import hash_password
from app.db import models
from app.db.session import get_db
from app.schemas import PermissionOut, RoleOut, UserCreate, UserOut, UserUpdate
from app.services import audit

router = APIRouter(tags=["用户与权限"])


@router.get("/users", response_model=list[UserOut], summary="用户列表")
def list_users(db: Session = Depends(get_db), _: models.User = Depends(require_permission("user:manage"))):
    return list(db.scalars(select(models.User).order_by(models.User.id)).all())


@router.post("/users", response_model=UserOut, summary="创建用户")
def create_user(payload: UserCreate, request: Request, db: Session = Depends(get_db),
                actor: models.User = Depends(require_permission("user:manage"))):
    if db.scalar(select(models.User).where(models.User.username == payload.username)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "用户名已存在")
    user = models.User(
        username=payload.username,
        email=payload.email,
        display_name=payload.display_name,
        hashed_password=hash_password(payload.password),
        is_active=True,
    )
    for role_name in payload.role_names:
        role = db.scalar(select(models.Role).where(models.Role.name == role_name))
        if role:
            user.roles.append(role)
    db.add(user)
    db.commit()
    db.refresh(user)
    audit.record(db, action="user_create", user=actor, resource_type="user",
                 resource_id=user.id, ip=get_client_ip(request))
    return user


@router.put("/users/{user_id}", response_model=UserOut, summary="修改用户")
def update_user(user_id: int, payload: UserUpdate, request: Request,
                db: Session = Depends(get_db),
                actor: models.User = Depends(require_permission("user:manage"))):
    user = db.get(models.User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "用户不存在")
    if payload.email is not None:
        user.email = payload.email
    if payload.display_name is not None:
        user.display_name = payload.display_name
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.password:
        user.hashed_password = hash_password(payload.password)
    if payload.role_names is not None:
        user.roles = []
        for role_name in payload.role_names:
            role = db.scalar(select(models.Role).where(models.Role.name == role_name))
            if role:
                user.roles.append(role)
    db.commit()
    db.refresh(user)
    audit.record(db, action="user_update", user=actor, resource_type="user",
                 resource_id=user.id, ip=get_client_ip(request))
    return user


@router.get("/roles", response_model=list[RoleOut], summary="角色列表")
def list_roles(db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
    return list(db.scalars(select(models.Role).order_by(models.Role.id)).all())


@router.get("/permissions", response_model=list[PermissionOut], summary="权限列表")
def list_permissions(db: Session = Depends(get_db), _: models.User = Depends(get_current_user)):
    return list(db.scalars(select(models.Permission).order_by(models.Permission.id)).all())
