"""Зависимости FastAPI: текущий пользователь и проверка ролей."""
import time

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import AuditLog, RevokedToken, User
from .security import decode_access_token

bearer = HTTPBearer(auto_error=False)

ROLE_LEVEL = {"viewer": 1, "operator": 2, "admin": 3}


# Эти адреса доступны, даже если пользователь обязан сменить пароль
PASSWORD_CHANGE_ALLOWED = ("/api/auth/me", "/api/auth/change-password", "/api/auth/policy", "/api/auth/logout-all",
                           "/api/auth/logout")


def get_current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Требуется авторизация")
    try:
        payload = decode_access_token(creds.credentials)
        user = db.get(User, int(payload["sub"]))
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Недействительный токен")
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Пользователь отключён")
    if int(payload.get("ver", 0)) != (user.token_version or 0):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Сессия завершена: войдите снова")
    if time.time() - int(payload.get("auth", 0)) > get_settings().session_max_hours * 3600:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Сессия истекла: войдите снова")
    if payload.get("jti") and db.get(RevokedToken, payload["jti"]) is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Сессия завершена: войдите снова")
    request.state.token = payload
    if user.must_change_password and request.url.path not in PASSWORD_CHANGE_ALLOWED:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Требуется сменить пароль")
    return user


def require(role: str):
    """Зависимость: пользователь с ролью не ниже указанной."""

    def checker(user: User = Depends(get_current_user)) -> User:
        if ROLE_LEVEL.get(user.role, 0) < ROLE_LEVEL[role]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Недостаточно прав")
        return user

    return checker


viewer = require("viewer")
operator = require("operator")
admin = require("admin")


def audit(
    db: Session,
    user: User | None,
    action: str,
    object_type: str = "",
    object_id: object = "",
    details: dict | None = None,
    request: Request | None = None,
) -> None:
    """Записать действие пользователя в журнал аудита (коммит — на вызывающей стороне)."""
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            # для неудачных входов — имя, под которым пытались войти
            username=user.username if user else str((details or {}).get("username", ""))[:64],
            action=action,
            object_type=object_type,
            object_id=str(object_id) if object_id is not None else "",
            details=details or {},
            client_ip=(request.client.host if request and request.client else ""),
        )
    )