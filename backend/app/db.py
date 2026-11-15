from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_settings = get_settings()
engine = create_engine(_settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Простые миграции для уже существующих баз: create_all создаёт только новые таблицы,
# а новые колонки старых таблиц добавляются здесь. Для развития проекта стоит перейти на Alembic.
MIGRATIONS = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_logins INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_ip VARCHAR(45) NOT NULL DEFAULT ''",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS notified_at TIMESTAMPTZ",
    "ALTER TABLE devices ADD COLUMN IF NOT EXISTS missed_polls INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_enc TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT false",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step INTEGER NOT NULL DEFAULT 0",
    # размещение в стойках (таблица racks к этому моменту уже создана create_all)
    "ALTER TABLE devices ADD COLUMN IF NOT EXISTS rack_id INTEGER REFERENCES racks(id) ON DELETE SET NULL",
    "ALTER TABLE devices ADD COLUMN IF NOT EXISTS rack_position INTEGER",
    "ALTER TABLE devices ADD COLUMN IF NOT EXISTS rack_face VARCHAR(8) NOT NULL DEFAULT 'front'",
    "ALTER TABLE devices ADD COLUMN IF NOT EXISTS u_height INTEGER NOT NULL DEFAULT 1",
    "ALTER TABLE devices ADD COLUMN IF NOT EXISTS full_depth BOOLEAN NOT NULL DEFAULT true",
    "CREATE INDEX IF NOT EXISTS ix_devices_rack_id ON devices (rack_id)",
    # community больше не хранится в принятых trap (раньше была видна наблюдателю через /api/events)
    # CASE гарантирует порядок: строки с \u0000 (их не принимает jsonb) не приводятся к jsonb вовсе
    "UPDATE events SET data = (data::jsonb - 'community')::json WHERE kind = 'trap' AND "
    "CASE WHEN position('\\u0000' in data::text) = 0 THEN (data::jsonb) ? 'community' ELSE false END",
]


def init_db() -> None:
    from sqlalchemy import text

    from . import models  # noqa: F401  (регистрирует модели)

    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        for stmt in MIGRATIONS:
            conn.execute(text(stmt))
