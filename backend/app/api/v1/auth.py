"""认证接口：登录、当前用户信息。"""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_client_ip, get_current_user, get_user_by_username
from app.core.config import settings
from app.core.security import create_access_token, verify_password
from app.db import models
from app.db.session import get_db
from app.schemas import LoginRequest, Token, UserOut
from app.services import audit

router = APIRouter(prefix="/auth", tags=["认证"])


@router.post("/login", response_model=Token, summary="用户登录")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = get_user_by_username(db, payload.username)
    if user is None or not verify_password(payload.password, user.hashed_password):
        audit.record(db, action="login", user=None,
                     resource_type="auth", result="failed",
                     ip=get_client_ip(request), detail={"username": payload.username})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "用户名或密码错误")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "账号已被禁用")

    user.last_login_at = dt.datetime.now(dt.timezone.utc)
    user.last_login_ip = get_client_ip(request)
    db.commit()
    db.refresh(user)

    token = create_access_token(
        user.id, extra={"username": user.username, "is_superuser": user.is_superuser}
    )
    audit.record(db, action="login", user=user, resource_type="auth", result="success",
                 ip=get_client_ip(request))
    return Token(
        access_token=token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserOut.model_validate(user),
    )


@router.get("/me", response_model=UserOut, summary="获取当前登录用户")
def me(user: models.User = Depends(get_current_user)):
    return user


@router.post("/logout", summary="退出登录（客户端清除令牌）")
def logout(request: Request, user: models.User = Depends(get_current_user),
           db: Session = Depends(get_db)):
    audit.record(db, action="logout", user=user, resource_type="auth",
                 ip=get_client_ip(request))
    return {"message": "已退出登录"}
