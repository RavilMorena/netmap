"""Настройки приложения из переменных окружения (.env)."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="NETMAP_", extra="ignore")

    database_url: str = "postgresql+psycopg://netmap:netmap@db:5432/netmap"

    # Ключ подписи JWT-токенов и ключ шифрования учётных данных SNMP/SSH (из него выводится ключ Fernet).
    # Обязательны: случайные строки не короче 32 символов (openssl rand -hex 32). Без них система не стартует.
    secret_key: str = ""
    encryption_key: str = ""
    # Срок токена входа. Интерфейс продлевает его, пока пользователь активен (POST /auth/refresh),
    # поэтому короткий срок не мешает работе, а украденный токен быстро становится бесполезным.
    access_token_minutes: int = 30
    # Предельная длина сессии: после неё нужно снова ввести пароль, даже если пользователь активен
    session_max_hours: int = 12
    # Выход из интерфейса после бездействия, минут (0 — не выходить)
    session_idle_minutes: int = 30

    # Защита входа: после N неудачных попыток учётная запись блокируется на M минут
    login_max_attempts: int = 5
    login_lock_minutes: int = 15
    # С одного IP-адреса — не больше N неудачных попыток за окно (защита от перебора имён)
    login_ip_max_attempts: int = 20
    login_ip_window_minutes: int = 15
    password_min_length: int = 8

    # Адрес интерфейса для ссылок в Telegram, например http://192.168.1.10:8080
    public_url: str = ""

    # Первый администратор создаётся при старте, если пользователей ещё нет.
    admin_username: str = "admin"
    admin_password: str = "admin"

    # Приёмники событий (воркер).
    trap_port: int = 162
    syslog_port: int = 514

    # Как часто воркер проверяет очередь запусков обнаружения, секунд.
    queue_poll_seconds: float = 3.0

    cors_origins: str = ""  # через запятую; пусто — запросы только с того же адреса
    api_docs: bool = False  # описание API на /api/docs (видно без входа)

    # Демо-стенд (docker-compose.lab.yml): адрес первого симулированного устройства.
    # Если задан и учётных данных ещё нет — при старте создаются community public и настройки обхода.
    demo_seed: str = ""
    demo_snmp_port: int = 1161


# значения-заглушки из примеров и прежних версий: с ними токен входа может подделать кто угодно
KEY_PLACEHOLDERS = ("change-me", "replace-with", "changeme", "secret", "netmap")


def key_problems(s: Settings) -> list[str]:
    """Почему ключи NETMAP_SECRET_KEY / NETMAP_ENCRYPTION_KEY нельзя использовать (пусто — можно)."""
    out = []
    for name, value in (("NETMAP_SECRET_KEY", s.secret_key), ("NETMAP_ENCRYPTION_KEY", s.encryption_key)):
        v = value.strip()
        if len(v) < 32:
            out.append(f"{name} короче 32 символов")
        elif v.lower().startswith(KEY_PLACEHOLDERS):
            out.append(f"{name} — значение-заглушка из примера")
    if s.secret_key.strip() and s.secret_key == s.encryption_key:
        out.append("NETMAP_SECRET_KEY и NETMAP_ENCRYPTION_KEY совпадают")
    return out


@lru_cache
def get_settings() -> Settings:
    return Settings()
