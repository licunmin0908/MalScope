"""认证与授权基础：密码哈希（bcrypt）、JWT 签发与校验。"""

from __future__ import annotations

import datetime as dt
from typing import Any

import bcrypt
import jwt

from app.core.config import settings

# bcrypt 仅取前 72 字节
_BCRYPT_MAX = 72


def hash_password(password: str) -> str:
    """使用 bcrypt 生成密码哈希。"""
    pwd = password.encode("utf-8")[:_BCRYPT_MAX]
    return bcrypt.hashpw(pwd, bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """校验密码。"""
    try:
        pwd = password.encode("utf-8")[:_BCRYPT_MAX]
        return bcrypt.checkpw(pwd, hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(
    subject: str | int,
    extra: dict[str, Any] | None = None,
    expires_minutes: int | None = None,
) -> str:
    """签发 JWT 访问令牌。subject 一般为用户 ID。"""
    now = dt.datetime.now(dt.timezone.utc)
    expire = now + dt.timedelta(
        minutes=expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload: dict[str, Any] = {
        "sub": str(subject),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "iss": "malscope",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """解码并校验 JWT，失败抛出 jwt.PyJWTError。"""
    return jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        issuer="malscope",
    )
