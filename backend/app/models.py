"""Модель данных.

Две группы таблиц:
* инвентарь (аналог NetBox): площадки, устройства, интерфейсы, VLAN, подсети, IP-адреса, связи;
* оперативные данные обнаружения: таблицы MAC/ARP/маршрутов, запуски, снимки, изменения,
  оповещения, события (traps/syslog), журнал аудита.
"""
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


TS = DateTime(timezone=True)


# ---------------------------------------------------------------- пользователи


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    password_hash: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # admin | operator | viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    # защита входа
    failed_logins: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    locked_until: Mapped[datetime | None] = mapped_column(TS)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    # увеличивается при смене пароля, роли, отключении и «выйти везде» — старые токены перестают действовать
    token_version: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_login_at: Mapped[datetime | None] = mapped_column(TS)
    last_login_ip: Mapped[str] = mapped_column(String(45), default="", server_default="")
    password_changed_at: Mapped[datetime | None] = mapped_column(TS)
    # двухфакторный вход (TOTP, RFC 6238): секрет хранится зашифрованным
    totp_secret_enc: Mapped[str] = mapped_column(Text, default="", server_default="")
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0, server_default="0")  # защита от повтора кода


class EquipmentImage(Base):
    """Фото лицевой или тыльной панели: для одного устройства или для всех устройств модели.

    Хранится в базе (резервная копия базы — это и копия фото), уже перекодированным в WebP без метаданных."""

    __tablename__ = "equipment_images"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    model_key: Mapped[str] = mapped_column(String(200), default="", index=True)  # «производитель|модель»
    face: Mapped[str] = mapped_column(String(8))  # front | rear
    mime: Mapped[str] = mapped_column(String(32), default="image/webp")
    data: Mapped[bytes] = mapped_column(LargeBinary)
    width: Mapped[int] = mapped_column(Integer)
    height: Mapped[int] = mapped_column(Integer)
    uploaded_by: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(TS, default=utcnow, onupdate=utcnow)


class RevokedToken(Base):
    """Отозванные токены входа (выход из системы) — до истечения их срока."""

    __tablename__ = "revoked_tokens"
    jti: Mapped[str] = mapped_column(String(32), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(TS, index=True)


# ---------------------------------------------------------------- инвентарь


class Site(Base):
    __tablename__ = "sites"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    address: Mapped[str] = mapped_column(String(255), default="")


class Rack(Base):
    """Стойка: высота в юнитах (U). Нумерация снизу вверх, как принято у большинства производителей стоек."""

    __tablename__ = "racks"
    __table_args__ = (UniqueConstraint("site_id", "name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"))
    location: Mapped[str] = mapped_column(String(128), default="")  # помещение, ряд
    u_height: Mapped[int] = mapped_column(Integer, default=42)
    desc_units: Mapped[bool] = mapped_column(Boolean, default=False)  # нумерация сверху вниз
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)

    site: Mapped[Site | None] = relationship()


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"))
    manufacturer: Mapped[str] = mapped_column(String(64), default="")
    model: Mapped[str] = mapped_column(String(128), default="")
    # router | switch | firewall | server | host | ap | phone | printer | endpoint | other
    role: Mapped[str] = mapped_column(String(32), default="other")
    # active | offline | planned | decommissioned
    status: Mapped[str] = mapped_column(String(32), default="active")
    platform: Mapped[str] = mapped_column(String(32), default="")  # routeros | linux | ios | ...
    os_version: Mapped[str] = mapped_column(String(128), default="")
    serial: Mapped[str] = mapped_column(String(64), default="")
    sys_descr: Mapped[str] = mapped_column(Text, default="")
    sys_object_id: Mapped[str] = mapped_column(String(128), default="")
    chassis_id: Mapped[str] = mapped_column(String(64), default="", index=True)  # MAC или иной идентификатор LLDP
    primary_ip: Mapped[str] = mapped_column(String(64), default="")
    # managed=True: устройство опрашивается по SNMP/SSH; False: конечный узел, найденный косвенно
    managed: Mapped[bool] = mapped_column(Boolean, default=False)
    # Одобрено администратором. Новые устройства из обнаружения приходят с False ⇒ оповещение.
    is_known: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(16), default="manual")  # manual | discovered
    credential_id: Mapped[int | None] = mapped_column(ForeignKey("credentials.id", ondelete="SET NULL"))
    notes: Mapped[str] = mapped_column(Text, default="")
    map_x: Mapped[float | None] = mapped_column(Float)
    map_y: Mapped[float | None] = mapped_column(Float)
    first_seen: Mapped[datetime | None] = mapped_column(TS)
    last_seen: Mapped[datetime | None] = mapped_column(TS)
    missed_polls: Mapped[int] = mapped_column(Integer, default=0, server_default="0")  # пропущенных опросов подряд
    # размещение в стойке: rack_position — нижний занятый юнит; None при rack_id — «в стойке, место не задано»
    rack_id: Mapped[int | None] = mapped_column(ForeignKey("racks.id", ondelete="SET NULL"), index=True)
    rack_position: Mapped[int | None] = mapped_column(Integer)
    rack_face: Mapped[str] = mapped_column(String(8), default="front", server_default="front")  # front | rear
    u_height: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    full_depth: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")  # занимает обе стороны
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(TS, default=utcnow, onupdate=utcnow)

    site: Mapped[Site | None] = relationship()
    interfaces: Mapped[list["Interface"]] = relationship(
        back_populates="device", cascade="all, delete-orphan", order_by="Interface.name"
    )


interface_tagged_vlans = Table(
    "interface_tagged_vlans",
    Base.metadata,
    Column("interface_id", ForeignKey("interfaces.id", ondelete="CASCADE"), primary_key=True),
    Column("vlan_id", ForeignKey("vlans.id", ondelete="CASCADE"), primary_key=True),
)


class Interface(Base):
    __tablename__ = "interfaces"
    __table_args__ = (UniqueConstraint("device_id", "name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(String(255), default="")
    if_index: Mapped[int | None] = mapped_column(Integer)
    type: Mapped[str] = mapped_column(String(32), default="")  # ethernet | vlan | bridge | loopback | ...
    mac: Mapped[str] = mapped_column(String(17), default="", index=True)
    speed_mbps: Mapped[int | None] = mapped_column(Integer)
    admin_up: Mapped[bool | None] = mapped_column(Boolean)
    oper_up: Mapped[bool | None] = mapped_column(Boolean)
    mode: Mapped[str] = mapped_column(String(16), default="")  # access | trunk | routed | ""
    untagged_vlan_id: Mapped[int | None] = mapped_column(ForeignKey("vlans.id", ondelete="SET NULL"))
    source: Mapped[str] = mapped_column(String(16), default="manual")
    last_seen: Mapped[datetime | None] = mapped_column(TS)

    device: Mapped[Device] = relationship(back_populates="interfaces")
    untagged_vlan: Mapped["VLAN | None"] = relationship(foreign_keys=[untagged_vlan_id])
    tagged_vlans: Mapped[list["VLAN"]] = relationship(secondary=interface_tagged_vlans)


class VLAN(Base):
    __tablename__ = "vlans"
    __table_args__ = (UniqueConstraint("site_id", "vid"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    vid: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(64), default="")
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(16), default="manual")


class Prefix(Base):
    __tablename__ = "prefixes"
    id: Mapped[int] = mapped_column(primary_key=True)
    prefix: Mapped[str] = mapped_column(String(64), unique=True)  # 10.0.0.0/24
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"))
    vlan_id: Mapped[int | None] = mapped_column(ForeignKey("vlans.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(16), default="active")
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(16), default="manual")


class IPAddress(Base):
    __tablename__ = "ip_addresses"
    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True)  # адрес хоста без маски
    prefix_len: Mapped[int] = mapped_column(Integer, default=32)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    interface_id: Mapped[int | None] = mapped_column(ForeignKey("interfaces.id", ondelete="SET NULL"))
    mac: Mapped[str] = mapped_column(String(17), default="")
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | reserved | deprecated
    dns_name: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(16), default="manual")  # manual | discovered | arp
    last_seen: Mapped[datetime | None] = mapped_column(TS)


class Link(Base):
    """Связь между двумя интерфейсами (кабель или логический сосед).

    a_interface_id < b_interface_id — пара хранится в нормализованном порядке.
    """

    __tablename__ = "links"
    __table_args__ = (UniqueConstraint("a_interface_id", "b_interface_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    a_interface_id: Mapped[int] = mapped_column(ForeignKey("interfaces.id", ondelete="CASCADE"), index=True)
    b_interface_id: Mapped[int] = mapped_column(ForeignKey("interfaces.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16), default="manual")  # lldp | cdp | mndp | fdb | manual
    description: Mapped[str] = mapped_column(String(255), default="")
    first_seen: Mapped[datetime | None] = mapped_column(TS, default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(TS, default=utcnow)

    a_interface: Mapped[Interface] = relationship(foreign_keys=[a_interface_id])
    b_interface: Mapped[Interface] = relationship(foreign_keys=[b_interface_id])


# ---------------------------------------------------------------- оперативные таблицы


class MacEntry(Base):
    """Текущая таблица коммутации (FDB) опрошенных устройств."""

    __tablename__ = "mac_entries"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    interface_id: Mapped[int | None] = mapped_column(ForeignKey("interfaces.id", ondelete="CASCADE"))
    mac: Mapped[str] = mapped_column(String(17), index=True)
    vid: Mapped[int | None] = mapped_column(Integer)
    last_seen: Mapped[datetime] = mapped_column(TS, default=utcnow)


class ArpEntry(Base):
    __tablename__ = "arp_entries"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    interface_name: Mapped[str] = mapped_column(String(128), default="")
    ip: Mapped[str] = mapped_column(String(45), index=True)
    mac: Mapped[str] = mapped_column(String(17), index=True)
    last_seen: Mapped[datetime] = mapped_column(TS, default=utcnow)


class Route(Base):
    __tablename__ = "routes"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    destination: Mapped[str] = mapped_column(String(64))
    next_hop: Mapped[str] = mapped_column(String(45), default="")
    interface_name: Mapped[str] = mapped_column(String(128), default="")
    protocol: Mapped[str] = mapped_column(String(32), default="")
    last_seen: Mapped[datetime] = mapped_column(TS, default=utcnow)


class Credential(Base):
    """Учётные данные для опроса. Секреты хранятся только в зашифрованном виде (Fernet)."""

    __tablename__ = "credentials"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    kind: Mapped[str] = mapped_column(String(16))  # snmp_v2c | snmp_v3 | ssh
    secret_enc: Mapped[str] = mapped_column(Text)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict | list | str | int | float | bool | None] = mapped_column(JSON)


class DiscoveryRun(Base):
    __tablename__ = "discovery_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), default="full")  # full | device
    trigger: Mapped[str] = mapped_column(String(16), default="manual")  # manual | schedule | trap | syslog
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending|running|done|failed
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    requested_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(TS)
    finished_at: Mapped[datetime | None] = mapped_column(TS)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    log: Mapped[str] = mapped_column(Text, default="")


class Snapshot(Base):
    """Снимок состояния сети после запуска обнаружения (для сравнения и просмотра истории)."""

    __tablename__ = "snapshots"
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int | None] = mapped_column(ForeignKey("discovery_runs.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow, index=True)
    data: Mapped[dict] = mapped_column(JSON)


class ChangeEvent(Base):
    __tablename__ = "change_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(TS, default=utcnow, index=True)
    run_id: Mapped[int | None] = mapped_column(ForeignKey("discovery_runs.id", ondelete="SET NULL"))
    snapshot_id: Mapped[int | None] = mapped_column(ForeignKey("snapshots.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(16))  # added | removed | moved | changed
    object_type: Mapped[str] = mapped_column(String(16))  # device | interface | link | endpoint | ip | vlan
    object_key: Mapped[str] = mapped_column(String(128), default="")
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), index=True)
    summary: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(TS, default=utcnow, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="warning")  # info | warning | critical
    # unknown_device | device_down | link_down | mac_moved | ip_moved | ip_conflict | trap | syslog |
    # arp_spoof | arp_change | arp_multi_ip | mac_flapping | auth_bruteforce | rogue_switch |
    # baseline_deviation | vulnerable_firmware | neighbor_spoof | identity_conflict
    kind: Mapped[str] = mapped_column(String(32))
    message: Mapped[str] = mapped_column(Text)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), index=True)
    is_ack: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    ack_by: Mapped[str] = mapped_column(String(64), default="")
    ack_at: Mapped[datetime | None] = mapped_column(TS)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    notified_at: Mapped[datetime | None] = mapped_column(TS)  # отправлено во внешний канал (Telegram)


class Event(Base):
    """Сырые события от устройств: SNMP traps и сообщения syslog."""

    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(TS, default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(16))  # trap | syslog
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    severity: Mapped[str] = mapped_column(String(16), default="info")
    message: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON, default=dict)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(TS, default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    username: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(32))
    object_type: Mapped[str] = mapped_column(String(32), default="")
    object_id: Mapped[str] = mapped_column(String(64), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    client_ip: Mapped[str] = mapped_column(String(45), default="")
