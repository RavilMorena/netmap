"""Вход, пользователи, защита от подбора пароля и журнал аудита."""
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..deps import admin, audit, get_current_user
from ..models import Alert, AuditLog, RevokedToken, User, utcnow
from ..schemas import (
    AuditOut,
    LoginIn,
    PasswordChange,
    PasswordPolicy,
    TokenOut,
    TotpCode,
    TotpDisable,
    TotpSetupIn,
    TotpSetupOut,
    UserCreate,
    UserOut,
    UserUpdate,
)
from ..security import (
    DUMMY_HASH,
    create_access_token,
    decrypt_secret,
    encrypt_secret,
    hash_password,
    password_problems,
    totp_new_secret,
    totp_uri,
    totp_verify,
    verify_password,
)

router = APIRouter()

GENERIC_LOGIN_ERROR = "Неверное имя пользователя или пароль"


# ------------------------------------------------------------------ ограничение попыток по IP

class IpLimiter:
    """Неудачные попытки входа с одного адреса за скользящее окно (в памяти процесса API)."""

    def __init__(self):
        self.fails: dict[str, deque[float]] = defaultdict(deque)
        self.alerted: dict[str, float] = {}
        self.logged: dict[str, float] = {}
        self.lock = threading.Lock()

    def _trim(self, ip: str, window: float) -> deque[float]:
        q = self.fails[ip]
        now = time.monotonic()
        while q and now - q[0] > window:
            q.popleft()
        return q

    def attempt(self, ip: str) -> bool:
        """Занять попытку входа до проверки пароля (проверка и запись — атомарно, под блокировкой).
        False — лимит исчерпан. Попытка снимается только при успешном входе (reset)."""
        s = get_settings()
        with self.lock:
            q = self._trim(ip, s.login_ip_window_minutes * 60)
            if len(q) >= s.login_ip_max_attempts:
                return False
            q.append(time.monotonic())
            return True

    def fail(self, ip: str) -> bool:
        """Попытка оказалась неудачной. True — порог только что достигнут (нужно оповещение)."""
        s = get_settings()
        with self.lock:
            q = self._trim(ip, s.login_ip_window_minutes * 60)
            if len(q) >= s.login_ip_max_attempts and time.monotonic() - self.alerted.get(ip, -1e9) > 600:
                self.alerted[ip] = time.monotonic()
                return True
            return False

    def release(self, ip: str) -> None:
        """Успешный вход снимает только свою резервацию: прошлые неудачи с адреса остаются в окне,
        иначе своей учётной записью можно было бы обнулять счётчик и перебирать чужие имена."""
        with self.lock:
            q = self.fails.get(ip)
            if q:
                q.pop()

    def first_block(self, ip: str) -> bool:
        """True — первый отказ этому адресу в текущем окне (в аудит пишется один раз, а не на каждый запрос)."""
        s = get_settings()
        with self.lock:
            now = time.monotonic()
            if now - self.logged.get(ip, -1e9) > s.login_ip_window_minutes * 60:
                self.logged[ip] = now
                return True
            return False

    def reset(self, ip: str) -> None:
        with self.lock:
            self.fails.pop(ip, None)


ip_limiter = IpLimiter()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _policy() -> PasswordPolicy:
    s = get_settings()
    return PasswordPolicy(
        min_length=s.password_min_length,
        rules=[f"не короче {s.password_min_length} символов", "буквы и цифры",
               "не из списка распространённых паролей", "не содержит имя пользователя"],
        max_attempts=s.login_max_attempts, lock_minutes=s.login_lock_minutes, idle_minutes=s.session_idle_minutes,
    )


def _check_password(password: str, username: str) -> None:
    problems = password_problems(password, username)
    if problems:
        raise HTTPException(422, "Пароль не подходит: " + "; ".join(problems))


def _token(user: User, auth_time: int | None = None) -> TokenOut:
    return TokenOut(access_token=create_access_token(user.id, user.role, user.token_version or 0, auth_time),
                    user=UserOut.model_validate(user), idle_minutes=get_settings().session_idle_minutes)


def _password_failed(db: Session, user: User, request: Request, action: str) -> None:
    """Неверный текущий пароль в уже открытой сессии (смена пароля, 2FA): считается так же, как неудачный
    вход — иначе с украденным токеном пароль можно подбирать без блокировки."""
    s = get_settings()
    ip = _client_ip(request)
    user.failed_logins = (user.failed_logins or 0) + 1
    audit(db, user, action, "user", user.id, {}, request)
    if user.failed_logins >= s.login_max_attempts:
        user.failed_logins = 0
        user.locked_until = utcnow() + timedelta(minutes=s.login_lock_minutes)
        user.token_version = (user.token_version or 0) + 1  # текущая сессия тоже завершается
        db.add(Alert(kind="auth_bruteforce", severity="critical",
                     message=f"Учётная запись «{user.username}» заблокирована на {s.login_lock_minutes} мин: "
                             f"{s.login_max_attempts} неверных текущих паролей в открытой сессии, адрес {ip}",
                     details={"ip": ip, "username": user.username}))
        audit(db, None, "user_locked", "user", user.id, {"username": user.username, "ip": ip}, request)
    db.commit()


# ------------------------------------------------------------------ вход

@router.get("/auth/policy", response_model=PasswordPolicy, tags=["Авторизация"], summary="Политика паролей и сессий")
def policy():
    return _policy()


@router.post("/auth/login", response_model=TokenOut, tags=["Авторизация"])
def login(payload: LoginIn, request: Request, db: Session = Depends(get_db)):
    s = get_settings()
    ip = _client_ip(request)
    if not ip_limiter.attempt(ip):
        if ip_limiter.first_block(ip):
            audit(db, None, "login_blocked_ip", "user", "", {"username": payload.username[:64]}, request)
            db.commit()
        raise HTTPException(429, f"Слишком много неудачных попыток входа с вашего адреса. "
                                 f"Повторите через {s.login_ip_window_minutes} мин.")

    # строка пользователя блокируется до конца запроса: параллельные попытки идут по очереди,
    # и счётчик неверных паролей не «проскакивает» порог
    user = db.scalar(select(User).where(User.username == payload.username).with_for_update())
    now = utcnow()

    if user is not None and user.locked_until and user.locked_until > now:
        verify_password(payload.password, DUMMY_HASH)  # одинаковое время ответа
        audit(db, None, "login_locked", "user", user.id, {"username": user.username}, request)
        db.commit()
        # тот же ответ, что и на неверный пароль: по нему нельзя узнать, существует ли имя и заблокировано ли оно
        raise HTTPException(401, GENERIC_LOGIN_ERROR)

    ok = verify_password(payload.password, user.password_hash if user else DUMMY_HASH)
    otp_failed = False
    if user is not None and ok and user.is_active and user.totp_enabled:
        # второй шаг: пароль верен, нужен код из приложения-аутентификатора
        if not payload.otp:
            raise HTTPException(428, "Введите шестизначный код из приложения-аутентификатора")
        step = totp_verify(_totp_secret(user), payload.otp, user.totp_last_step or 0)
        if step is None:
            ok, otp_failed = False, True
        else:
            user.totp_last_step = step
    if user is None or not ok or not user.is_active:
        if ip_limiter.fail(ip):
            db.add(Alert(kind="auth_bruteforce", severity="critical",
                         message=f"Подбор пароля: {s.login_ip_max_attempts} неудачных попыток входа с адреса {ip} "
                                 f"за {s.login_ip_window_minutes} мин", details={"ip": ip}))
        if user is not None and ok is False:
            user.failed_logins = (user.failed_logins or 0) + 1
            if user.failed_logins >= s.login_max_attempts:
                user.locked_until = now + timedelta(minutes=s.login_lock_minutes)
                user.failed_logins = 0
                db.add(Alert(kind="auth_bruteforce", severity="critical",
                             message=f"Учётная запись «{user.username}» заблокирована на {s.login_lock_minutes} мин: "
                                     f"{s.login_max_attempts} неверных паролей подряд, последний — с адреса {ip}",
                             details={"ip": ip, "username": user.username}))
                audit(db, None, "user_locked", "user", user.id, {"username": user.username, "ip": ip}, request)
        audit(db, None, "login_failed_otp" if otp_failed else "login_failed", "user", user.id if user else "",
              {"username": payload.username}, request)
        db.commit()
        raise HTTPException(401, "Неверный код подтверждения" if otp_failed else GENERIC_LOGIN_ERROR)

    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now
    user.last_login_ip = ip
    ip_limiter.release(ip)
    audit(db, user, "login", "user", user.id, {}, request)
    db.commit()
    return _token(user)


@router.post("/auth/refresh", response_model=TokenOut, tags=["Авторизация"],
             summary="Продлить сессию: новый короткий токен взамен действующего")
def refresh(request: Request, user: User = Depends(get_current_user)):
    """Интерфейс продлевает токен, пока пользователь активен. Момент входа переносится в новый токен:
    сессия длится не дольше NETMAP_SESSION_MAX_HOURS, потом нужен пароль."""
    return _token(user, int(request.state.token.get("auth", 0)) or None)


@router.post("/auth/logout", tags=["Авторизация"], summary="Выйти: отозвать текущий токен")
def logout(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    tok = request.state.token
    if tok.get("jti"):
        now = utcnow()
        db.execute(delete(RevokedToken).where(RevokedToken.expires_at < now))  # истёкшие уже не нужны
        db.merge(RevokedToken(jti=tok["jti"], expires_at=datetime.fromtimestamp(int(tok["exp"]), timezone.utc)))
    audit(db, user, "logout", "user", user.id, {}, request)
    db.commit()
    return {"ok": True}


@router.get("/auth/me", response_model=UserOut, tags=["Авторизация"])
def me(user: User = Depends(get_current_user)):
    return user


@router.post("/auth/change-password", response_model=TokenOut, tags=["Авторизация"],
             summary="Сменить свой пароль (возвращает новый токен, остальные сессии завершаются)")
def change_password(payload: PasswordChange, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(get_current_user)):
    if not verify_password(payload.old_password, user.password_hash):
        _password_failed(db, user, request, "change_password_failed")
        raise HTTPException(400, "Текущий пароль указан неверно")
    if payload.new_password == payload.old_password:
        raise HTTPException(422, "Новый пароль должен отличаться от текущего")
    _check_password(payload.new_password, user.username)
    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False
    user.password_changed_at = utcnow()
    user.token_version = (user.token_version or 0) + 1
    audit(db, user, "change_password", "user", user.id, {}, request)
    db.commit()
    return _token(user)


# ------------------------------------------------------------------ двухфакторный вход

def _totp_secret(user: User) -> str:
    return decrypt_secret(user.totp_secret_enc).get("secret", "") if user.totp_secret_enc else ""


@router.post("/auth/totp/setup", response_model=TotpSetupOut, tags=["Авторизация"],
             summary="Начать подключение двухфакторного входа: новый секрет для приложения-аутентификатора")
def totp_setup(payload: TotpSetupIn, request: Request, db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    if user.totp_enabled:
        raise HTTPException(409, "Двухфакторный вход уже включён")
    if not verify_password(payload.password, user.password_hash):
        _password_failed(db, user, request, "totp_setup_failed")
        raise HTTPException(400, "Пароль указан неверно")
    secret = totp_new_secret()
    user.totp_secret_enc = encrypt_secret({"secret": secret})
    db.commit()
    return TotpSetupOut(secret=secret, uri=totp_uri(secret, user.username))


@router.post("/auth/totp/enable", response_model=TokenOut, tags=["Авторизация"],
             summary="Включить двухфакторный вход, подтвердив код из приложения")
def totp_enable(payload: TotpCode, request: Request, db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    secret = _totp_secret(user)
    if user.totp_enabled or not secret:
        raise HTTPException(409, "Сначала получите новый секрет")
    step = totp_verify(secret, payload.code)
    if step is None:
        raise HTTPException(400, "Код не подошёл. Проверьте время на телефоне и введите текущий код")
    user.totp_enabled, user.totp_last_step = True, step
    # остальные сессии, открытые без второго фактора, завершаются; эта получает новый токен
    user.token_version = (user.token_version or 0) + 1
    audit(db, user, "totp_enabled", "user", user.id, {}, request)
    db.commit()
    return _token(user)


@router.post("/auth/totp/disable", response_model=TokenOut, tags=["Авторизация"],
             summary="Отключить свой двухфакторный вход (нужны пароль и текущий код)")
def totp_disable(payload: TotpDisable, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)):
    step = totp_verify(_totp_secret(user), payload.code, user.totp_last_step or 0) if user.totp_enabled else None
    if not verify_password(payload.password, user.password_hash) or step is None:
        _password_failed(db, user, request, "totp_disable_failed")
        raise HTTPException(400, "Пароль или код указаны неверно")
    user.totp_enabled, user.totp_secret_enc, user.totp_last_step = False, "", 0
    user.token_version = (user.token_version or 0) + 1  # защита ослаблена — прочие сессии завершаются
    audit(db, user, "totp_disabled", "user", user.id, {}, request)
    db.commit()
    return _token(user)


@router.post("/auth/logout-all", tags=["Авторизация"], summary="Завершить все свои сессии")
def logout_all(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    user.token_version = (user.token_version or 0) + 1
    audit(db, user, "logout_all", "user", user.id, {}, request)
    db.commit()
    return {"ok": True}


# ------------------------------------------------------------------ пользователи

@router.get("/users", response_model=list[UserOut], tags=["Пользователи"])
def list_users(db: Session = Depends(get_db), _: User = Depends(admin)):
    return db.scalars(select(User).order_by(User.username)).all()


@router.post("/users", response_model=UserOut, status_code=201, tags=["Пользователи"])
def create_user(payload: UserCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    _check_password(payload.password, payload.username)
    u = User(username=payload.username, full_name=payload.full_name, role=payload.role,
             is_active=payload.is_active, password_hash=hash_password(payload.password),
             must_change_password=payload.must_change_password, password_changed_at=utcnow())
    db.add(u)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Пользователь с таким именем уже существует")
    audit(db, user, "create", "user", u.id, {"username": u.username, "role": u.role}, request)
    db.commit()
    return u


@router.patch("/users/{user_id}", response_model=UserOut, tags=["Пользователи"])
def update_user(user_id: int, payload: UserUpdate, request: Request, db: Session = Depends(get_db),
                user: User = Depends(admin)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "Не найдено")
    data = {k: v for k, v in payload.model_dump(exclude_unset=True).items() if v is not None}  # null — «не менять»
    if u.id == user.id and (data.get("role", "admin") != "admin" or data.get("is_active") is False):
        raise HTTPException(400, "Нельзя понизить или отключить самого себя")
    details = {k: v for k, v in data.items() if k not in ("password", "reset_totp")}
    revoke = False
    pw = data.pop("password", None)
    if pw:
        _check_password(pw, u.username)
        u.password_hash = hash_password(pw)
        u.password_changed_at = utcnow()
        u.must_change_password = data.pop("must_change_password", True)  # пароль, выданный администратором
        details["password"] = "сброшен администратором"
        revoke = True
    if "role" in data and data["role"] != u.role or data.get("is_active") is False:
        revoke = True
    if data.pop("reset_totp", None) and u.totp_enabled:
        u.totp_enabled, u.totp_secret_enc, u.totp_last_step = False, "", 0
        details["reset_totp"] = "двухфакторный вход сброшен администратором"
        revoke = True
    for k, v in data.items():
        setattr(u, k, v)
    if revoke:
        u.token_version = (u.token_version or 0) + 1  # прежние токены пользователя перестают действовать
    audit(db, user, "update", "user", u.id, details, request)
    db.commit()
    return u


@router.post("/users/{user_id}/unlock", response_model=UserOut, tags=["Пользователи"],
             summary="Снять блокировку после неудачных попыток входа")
def unlock_user(user_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "Не найдено")
    u.locked_until, u.failed_logins = None, 0
    audit(db, user, "unlock", "user", u.id, {"username": u.username}, request)
    db.commit()
    return u


@router.post("/users/{user_id}/revoke-sessions", response_model=UserOut, tags=["Пользователи"],
             summary="Завершить все сессии пользователя")
def revoke_sessions(user_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "Не найдено")
    u.token_version = (u.token_version or 0) + 1
    audit(db, user, "revoke_sessions", "user", u.id, {"username": u.username}, request)
    db.commit()
    return u


@router.delete("/users/{user_id}", status_code=204, tags=["Пользователи"])
def delete_user(user_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "Не найдено")
    if u.id == user.id:
        raise HTTPException(400, "Нельзя удалить самого себя")
    db.delete(u)
    audit(db, user, "delete", "user", user_id, {"username": u.username}, request)
    db.commit()
    return Response(status_code=204)


# ------------------------------------------------------------------ аудит

@router.get("/audit", response_model=list[AuditOut], tags=["Журнал аудита"])
def audit_log(response: Response, username: str | None = None, action: str | None = None,
              since: datetime | None = None, limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0),
              db: Session = Depends(get_db), _: User = Depends(admin)):
    q = select(AuditLog)
    if username:
        q = q.where(AuditLog.username == username)
    if action:
        q = q.where(AuditLog.action == action)
    if since:
        q = q.where(AuditLog.ts >= since)
    response.headers["X-Total-Count"] = str(db.scalar(select(func.count()).select_from(q.subquery())))
    return db.scalars(q.order_by(AuditLog.ts.desc()).offset(offset).limit(limit)).all()
