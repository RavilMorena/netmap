"""Пароли, JWT и шифрование учётных данных устройств."""
import base64
import uuid
import hashlib
import hmac
import json
import os
import struct
import time
from urllib.parse import quote
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings

ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


# Хэш для «пустой» проверки пароля несуществующего пользователя: время ответа одинаковое,
# поэтому по задержке нельзя узнать, существует ли такое имя.
DUMMY_HASH = bcrypt.hashpw(b"netmap-dummy-password", bcrypt.gensalt()).decode()

COMMON_PASSWORDS = {
    "password", "password1", "password123", "qwerty", "qwerty123", "qwertyuiop", "12345678", "123456789",
    "1234567890", "11111111", "00000000", "admin", "admin123", "admin1234", "administrator", "letmein",
    "welcome", "welcome1", "iloveyou", "p@ssw0rd", "passw0rd", "changeme", "netmap", "netmap123", "cisco",
    "cisco123", "mikrotik", "root", "toor", "test1234", "user1234", "qazwsx", "1q2w3e4r", "1qaz2wsx",
}


def password_problems(password: str, username: str = "") -> list[str]:
    """Нарушения политики паролей (пустой список — пароль подходит)."""
    s = get_settings()
    errs = []
    if len(password) < s.password_min_length:
        errs.append(f"не короче {s.password_min_length} символов")
    if len(password.encode()) > 72:
        # bcrypt учитывает только первые 72 байта; кириллица занимает 2 байта на букву
        errs.append("не длиннее 72 байт (около 72 латинских букв или 36 русских)")
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        errs.append("должен содержать буквы и цифры")
    if password.lower() in COMMON_PASSWORDS:
        errs.append("слишком распространённый пароль")
    if username and username.lower() in password.lower():
        errs.append("не должен содержать имя пользователя")
    return errs


def create_access_token(user_id: int, role: str, version: int = 0, auth_time: int | None = None) -> str:
    """auth_time — момент входа по паролю (секунды UTC); при продлении сессии переносится в новый токен,
    поэтому сессию нельзя продлевать бесконечно (NETMAP_SESSION_MAX_HOURS). jti — для отзыва при выходе."""
    s = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": role,
        "ver": version,
        "iat": now,
        "exp": now + timedelta(minutes=s.access_token_minutes),
        "auth": int(auth_time if auth_time is not None else now.timestamp()),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, s.secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, get_settings().secret_key, algorithms=[ALGORITHM])


# --- шифрование секретов ------------------------------------------------------


def _fernet() -> Fernet:
    raw = get_settings().encryption_key.encode()
    key = base64.urlsafe_b64encode(hashlib.sha256(raw).digest())
    return Fernet(key)


def encrypt_secret(data: dict) -> str:
    return _fernet().encrypt(json.dumps(data).encode()).decode()


def decrypt_secret(token: str) -> dict:
    try:
        return json.loads(_fernet().decrypt(token.encode()))
    except InvalidToken as e:  # ключ шифрования сменили — расшифровать нельзя
        raise ValueError("Не удалось расшифровать учётные данные: неверный ключ шифрования") from e


SECRET_FIELDS = {"community", "password", "auth_key", "priv_key", "enable_password", "bot_token"}


def mask_secret(data: dict) -> dict:
    """Версия секрета для отдачи в API: пароли и ключи заменены звёздочками."""
    return {k: ("••••••" if k in SECRET_FIELDS and v else v) for k, v in data.items()}


# --- двухфакторный вход: TOTP (RFC 6238, HMAC-SHA1, 6 цифр, шаг 30 с) -----------------

TOTP_STEP = 30


def totp_new_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode()


def totp_code(secret: str, step: int) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def totp_verify(secret: str, code: str, last_step: int = 0, now: float | None = None) -> int | None:
    """Номер шага, если код верен (допуск ±1 шаг на расхождение часов), иначе None.
    Код с уже использованным шагом отвергается — перехваченный код нельзя применить повторно."""
    code = "".join(ch for ch in code if ch.isdigit())
    if len(code) != 6:
        return None
    current = int((time.time() if now is None else now) // TOTP_STEP)
    for step in (current - 1, current, current + 1):
        if step > last_step and hmac.compare_digest(totp_code(secret, step), code):
            return step
    return None


def totp_uri(secret: str, username: str, issuer: str = "NetMap") -> str:
    return (f"otpauth://totp/{quote(issuer)}:{quote(username)}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits=6&period={TOTP_STEP}")