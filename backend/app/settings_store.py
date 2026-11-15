import logging

from pydantic import ValidationError
from sqlalchemy.orm import Session

from .models import Setting
from .schemas import DiscoverySettings

KEY = "discovery"
log = logging.getLogger(__name__)


def get_discovery_settings(db: Session) -> DiscoverySettings:
    row = db.get(Setting, KEY)
    value = dict(row.value or {}) if row else {}
    try:
        return DiscoverySettings(**value)
    except ValidationError as e:
        # сохранено старой версией без проверок: негодные поля — по умолчанию, остальное как было
        bad = {err["loc"][0] for err in e.errors() if err.get("loc")}
        log.warning("Настройки обнаружения: поля %s некорректны и заменены значениями по умолчанию", sorted(bad))
        return DiscoverySettings(**{k: v for k, v in value.items() if k not in bad})


def save_discovery_settings(db: Session, s: DiscoverySettings) -> None:
    row = db.get(Setting, KEY)
    if row is None:
        db.add(Setting(key=KEY, value=s.model_dump()))
    else:
        row.value = s.model_dump()
