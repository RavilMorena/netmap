"""Pydantic-схемы REST API."""
import ipaddress
import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator

_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_CTRL_ML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")  # в многострочном тексте можно \n, \r, \t


def _line(v: str) -> str:
    if _CTRL.search(v):
        raise ValueError("Недопустимые управляющие символы")
    return v.strip()


def _text(v: str) -> str:
    if _CTRL_ML.search(v):
        raise ValueError("Недопустимые управляющие символы")
    return v


def _ifname(v: str) -> str:
    v = _line(v)
    if "|" in v:
        raise ValueError("Символ «|» в имени интерфейса недопустим")
    return v


def _ip_or_empty(v: str) -> str:
    v = v.strip()
    if not v:
        return ""
    try:
        return str(ipaddress.ip_address(v))
    except ValueError as e:
        raise ValueError(f"Некорректный IP-адрес: {v}") from e


def _mac_or_empty(v: str) -> str:
    v = v.strip().lower().replace("-", ":")
    if v and not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", v):
        raise ValueError(f"Некорректный MAC-адрес: {v}")
    return v


def Line(n: int, min_len: int = 0):  # noqa: N802 — фабрика типа: однострочная строка не длиннее n
    return Annotated[str, Field(min_length=min_len, max_length=n), AfterValidator(_line)]


def Text(n: int):  # noqa: N802 — многострочный текст не длиннее n
    return Annotated[str, Field(max_length=n), AfterValidator(_text)]


IfName = Annotated[str, Field(min_length=1, max_length=128), AfterValidator(_ifname)]
IpOrEmpty = Annotated[str, Field(max_length=64), AfterValidator(_ip_or_empty)]
MacOrEmpty = Annotated[str, Field(max_length=17), AfterValidator(_mac_or_empty)]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ------------------------------------------------------------------ auth/users

Role = Literal["admin", "operator", "viewer"]


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)
    otp: str | None = Field(None, max_length=16)  # код из приложения-аутентификатора, если включён двухфакторный вход


class TotpSetupOut(BaseModel):
    secret: str
    uri: str


class TotpSetupIn(BaseModel):
    password: str = Field(max_length=256)  # подтверждение: украденного токена мало, чтобы привязать свой телефон


class TotpCode(BaseModel):
    code: str = Field(max_length=16)


class TotpDisable(BaseModel):
    password: str = Field(max_length=256)
    code: str = Field(max_length=16)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserOut"
    idle_minutes: int = 30


class UserOut(ORM):
    id: int
    username: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime
    must_change_password: bool = False
    failed_logins: int = 0
    locked_until: datetime | None = None
    last_login_at: datetime | None = None
    last_login_ip: str = ""
    password_changed_at: datetime | None = None
    totp_enabled: bool = False


class UserCreate(BaseModel):
    username: str = Field(min_length=2, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
    full_name: str = Field("", max_length=128)
    password: str = Field(max_length=256)
    role: Role = "viewer"
    is_active: bool = True
    must_change_password: bool = True  # новый пользователь меняет выданный пароль при первом входе


class UserUpdate(BaseModel):
    full_name: str | None = Field(None, max_length=128)
    password: str | None = Field(None, max_length=256)
    role: Role | None = None
    is_active: bool | None = None
    must_change_password: bool | None = None
    reset_totp: bool | None = None  # отключить двухфакторный вход (пользователь потерял телефон)


class PasswordChange(BaseModel):
    old_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class PasswordPolicy(BaseModel):
    min_length: int
    rules: list[str]
    max_attempts: int
    lock_minutes: int
    idle_minutes: int


# ------------------------------------------------------------------ sites


class SiteIn(BaseModel):
    name: Line(100, 1)
    description: Text(2000) = ""
    address: Line(255) = ""


class SiteUpdate(BaseModel):
    name: Line(100, 1) | None = None
    description: Text(2000) | None = None
    address: Line(255) | None = None


class SiteOut(ORM, SiteIn):
    id: int


# ------------------------------------------------------------------ devices

DeviceRole = Literal[
    "router", "switch", "firewall", "server", "host", "ap", "phone", "printer", "endpoint", "other"
]
DeviceStatus = Literal["active", "offline", "planned", "decommissioned"]


# Длины — по столбцам таблиц (models.py): лишнее отклоняется с 422, а не обрывается ошибкой базы
class DeviceIn(BaseModel):
    name: Line(128, 1)
    site_id: int | None = None
    manufacturer: Line(64) = ""
    model: Line(128) = ""
    role: DeviceRole = "other"
    status: DeviceStatus = "active"
    platform: Line(32) = ""
    os_version: Line(128) = ""
    serial: Line(64) = ""
    primary_ip: IpOrEmpty = ""
    managed: bool = False
    is_known: bool = True
    notes: Text(4000) = ""


class DeviceUpdate(BaseModel):
    name: Line(128, 1) | None = None
    site_id: int | None = None
    manufacturer: Line(64) | None = None
    model: Line(128) | None = None
    role: DeviceRole | None = None
    status: DeviceStatus | None = None
    platform: Line(32) | None = None
    os_version: Line(128) | None = None
    serial: Line(64) | None = None
    primary_ip: IpOrEmpty | None = None
    managed: bool | None = None
    is_known: bool | None = None
    notes: Text(4000) | None = None
    map_x: float | None = None
    map_y: float | None = None


class DeviceOut(ORM):
    id: int
    name: str
    site_id: int | None
    manufacturer: str
    model: str
    role: str
    status: str
    platform: str
    os_version: str
    serial: str
    sys_descr: str
    chassis_id: str
    primary_ip: str
    managed: bool
    is_known: bool
    source: str
    notes: str
    map_x: float | None
    map_y: float | None
    first_seen: datetime | None
    last_seen: datetime | None
    created_at: datetime
    updated_at: datetime
    rack_id: int | None = None
    rack_position: int | None = None
    rack_face: str = "front"
    u_height: int = 1
    full_depth: bool = True


# ------------------------------------------------------------------ interfaces


class InterfaceIn(BaseModel):
    device_id: int
    name: IfName
    description: Line(255) = ""
    type: Line(32) = "ethernet"
    mac: MacOrEmpty = ""
    speed_mbps: int | None = Field(None, ge=0, le=10_000_000)
    admin_up: bool | None = True
    oper_up: bool | None = None
    mode: Literal["", "access", "trunk", "routed"] = ""
    untagged_vlan_id: int | None = None
    tagged_vlan_ids: list[int] = Field([], max_length=4094)


class InterfaceUpdate(BaseModel):
    name: IfName | None = None
    description: Line(255) | None = None
    type: Line(32) | None = None
    mac: MacOrEmpty | None = None
    speed_mbps: int | None = Field(None, ge=0, le=10_000_000)
    admin_up: bool | None = None
    oper_up: bool | None = None
    mode: Literal["", "access", "trunk", "routed"] | None = None
    untagged_vlan_id: int | None = None
    tagged_vlan_ids: list[int] | None = Field(None, max_length=4094)


class InterfaceOut(ORM):
    id: int
    device_id: int
    name: str
    description: str
    if_index: int | None
    type: str
    mac: str
    speed_mbps: int | None
    admin_up: bool | None
    oper_up: bool | None
    mode: str
    untagged_vlan_id: int | None
    tagged_vlan_ids: list[int] = []
    source: str
    last_seen: datetime | None


# ------------------------------------------------------------------ VLAN / IPAM


class VLANIn(BaseModel):
    vid: int = Field(ge=1, le=4094)
    name: Line(64) = ""
    site_id: int | None = None
    description: Line(255) = ""


class VLANUpdate(BaseModel):
    vid: int | None = Field(default=None, ge=1, le=4094)
    name: Line(64) | None = None
    site_id: int | None = None
    description: Line(255) | None = None


class VLANOut(ORM, VLANIn):
    id: int
    source: str


def _check_prefix(v: str) -> str:
    try:
        return str(ipaddress.ip_network(v, strict=False))
    except ValueError as e:
        raise ValueError(f"Некорректная подсеть: {v}") from e


class PrefixIn(BaseModel):
    prefix: str
    site_id: int | None = None
    vlan_id: int | None = None
    status: Literal["active", "reserved", "deprecated"] = "active"
    description: Line(255) = ""

    _v = field_validator("prefix")(_check_prefix)


class PrefixUpdate(BaseModel):
    prefix: str | None = None
    site_id: int | None = None
    vlan_id: int | None = None
    status: Literal["active", "reserved", "deprecated"] | None = None
    description: Line(255) | None = None

    @field_validator("prefix")
    @classmethod
    def _p(cls, v):
        return _check_prefix(v) if v is not None else v


class PrefixOut(ORM):
    id: int
    prefix: str
    site_id: int | None
    vlan_id: int | None
    status: str
    description: str
    source: str
    used: int = 0
    size: int = 0


def _check_ip(v: str) -> str:
    try:
        return str(ipaddress.ip_address(v))
    except ValueError as e:
        raise ValueError(f"Некорректный IP-адрес: {v}") from e


class IPIn(BaseModel):
    ip: str
    prefix_len: int = Field(default=24, ge=0, le=128)
    device_id: int | None = None
    interface_id: int | None = None
    status: Literal["active", "reserved", "deprecated"] = "active"
    dns_name: Line(255) = ""
    description: Line(255) = ""

    _v = field_validator("ip")(_check_ip)


class IPUpdate(BaseModel):
    prefix_len: int | None = Field(default=None, ge=0, le=128)
    device_id: int | None = None
    interface_id: int | None = None
    status: Literal["active", "reserved", "deprecated"] | None = None
    dns_name: Line(255) | None = None
    description: Line(255) | None = None


class IPOut(ORM):
    id: int
    ip: str
    prefix_len: int
    device_id: int | None
    interface_id: int | None
    mac: str
    status: str
    dns_name: str
    description: str
    source: str
    last_seen: datetime | None


# ------------------------------------------------------------------ links


class LinkIn(BaseModel):
    a_interface_id: int
    b_interface_id: int
    description: Line(255) = ""


class LinkUpdate(BaseModel):
    description: Line(255) | None = None


class LinkOut(ORM):
    id: int
    a_interface_id: int
    b_interface_id: int
    kind: str
    description: str
    first_seen: datetime | None
    last_seen: datetime | None


# ------------------------------------------------------------------ credentials / discovery

CredKind = Literal["snmp_v2c", "snmp_v3", "ssh"]


class CredentialIn(BaseModel):
    name: Line(100, 1)
    kind: CredKind
    priority: int = Field(100, ge=0, le=100_000)
    enabled: bool = True
    # snmp_v2c: {community}; snmp_v3: {username, auth_protocol, auth_key, priv_protocol, priv_key, context?};
    # ssh: {username, password, port, platform?}
    secret: dict


class CredentialUpdate(BaseModel):
    name: Line(100, 1) | None = None
    priority: int | None = Field(None, ge=0, le=100_000)
    enabled: bool | None = None
    secret: dict | None = None  # пустые поля секрета не меняют сохранённые значения


class CredentialOut(ORM):
    id: int
    name: str
    kind: str
    priority: int
    enabled: bool
    created_at: datetime
    secret: dict = {}
    security: str = ""  # open | noauth | auth | priv — уровень защиты SNMP


def _ip_list(v: list[str]) -> list[str]:
    out = []
    for x in v:
        x = x.strip()
        if x:
            out.append(_check_ip(x))
    return out


def _net_list(v: list[str]) -> list[str]:
    return [_check_prefix(x.strip()) for x in v if x.strip()]


def _mac_list(v: list[str]) -> list[str]:
    from .discovery.util import norm_mac  # любые записи MAC: aa-bb-…, aabb.ccdd.eeff и т.п.
    out = []
    for x in (x.strip() for x in v):
        if x and not norm_mac(x):
            raise ValueError(f"Некорректный MAC-адрес: {x}")
        if x:
            out.append(norm_mac(x))
    return out


IpList = Annotated[list[Annotated[str, Field(max_length=64)]], Field(max_length=1000), AfterValidator(_ip_list)]
NetList = Annotated[list[Annotated[str, Field(max_length=64)]], Field(max_length=1000), AfterValidator(_net_list)]


class DiscoverySettings(BaseModel):
    """Настройки обнаружения. Адреса и подсети проверяются при сохранении: опечатка в начальном адресе
    или подсети отклоняется с 422, а не всплывает потом ошибкой опроса."""
    seeds: IpList = []
    include_subnets: NetList = []  # пусто ⇒ опрашиваются только начальные адреса (seeds), без соседей
    exclude_subnets: NetList = []
    scan_subnets: NetList = []  # подсети для ping-сканирования
    max_depth: int = Field(5, ge=0, le=32)
    max_devices: int = Field(200, ge=1, le=10_000)
    interval_minutes: int = Field(5, ge=1, le=10_080)
    schedule_enabled: bool = True
    snmp_port: int = Field(161, ge=1, le=65535)
    device_timeout: int = Field(180, ge=10, le=1800)  # общий срок сбора данных с одного устройства, секунд
    snmp_v3_only: bool = False  # не использовать SNMPv1/v2c (community передаётся открытым текстом)
    snmp_timeout: float = Field(2.0, gt=0, le=60)
    snmp_retries: int = Field(1, ge=0, le=10)
    ssh_timeout: float = Field(8.0, gt=0, le=120)
    auto_approve_managed: bool = False  # новые опрашиваемые устройства сразу считать известными
    alert_on_new_endpoint: bool = True
    resolve_dns: bool = True
    # контроль безопасности
    arp_watch: bool = True  # подмена ARP, конфликты IP, смена MAC у адреса
    arp_multi_ip_threshold: int = Field(3, ge=0, le=10_000)  # один MAC отвечает за N и более IP одной подсети — подозрение на ARP-атаку
    # MAC, которым много адресов положено (сервер с алиасами и т.п.)
    arp_multi_ip_ignore_macs: Annotated[list[Annotated[str, Field(max_length=32)]], Field(max_length=1000),
                                        AfterValidator(_mac_list)] = []
    mac_flap_threshold: int = Field(3, ge=0, le=1000)  # столько переездов узла за окно — «скачущий» MAC
    mac_flap_window_minutes: int = Field(60, ge=1, le=10_080)
    offline_after_misses: int = Field(2, ge=1, le=100)  # «недоступно» после N пропущенных полных опросов подряд
    rogue_port_threshold: int = Field(3, ge=0, le=1000)  # столько MAC за портом доступа — подозрение на чужой коммутатор (0 — выкл.)
    firmware_check: bool = True  # сверять версии ПО со списком известных уязвимостей
    # платформа → минимально допустимая версия ({"routeros": "7.15"})
    firmware_min_versions: dict[Line(32, 1), Line(32)] = Field({}, max_length=50)


class RunIn(BaseModel):
    kind: Literal["full", "device"] = "full"
    device_id: int | None = None


class RunOut(ORM):
    id: int
    kind: str
    trigger: str
    status: str
    params: dict
    requested_by: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    stats: dict
    log: str = ""


class ChangeOut(ORM):
    id: int
    ts: datetime
    run_id: int | None
    snapshot_id: int | None
    kind: str
    object_type: str
    object_key: str
    device_id: int | None
    summary: str
    details: dict


class AlertOut(ORM):
    id: int
    ts: datetime
    severity: str
    kind: str
    message: str
    device_id: int | None
    is_ack: bool
    ack_by: str
    ack_at: datetime | None
    details: dict


class EventOut(ORM):
    id: int
    ts: datetime
    kind: str
    source_ip: str
    device_id: int | None
    severity: str
    message: str
    data: dict


class AuditOut(ORM):
    id: int
    ts: datetime
    username: str
    action: str
    object_type: str
    object_id: str
    details: dict
    client_ip: str


class SnapshotOut(ORM):
    id: int
    run_id: int | None
    created_at: datetime
    counts: dict = {}


class Page(BaseModel):
    total: int
    items: list


# ------------------------------------------------------------------ стойки

RackFace = Literal["front", "rear"]


class RackIn(BaseModel):
    name: Line(100, 1)
    site_id: int | None = None
    location: Line(128) = ""
    u_height: int = Field(42, ge=1, le=60)
    desc_units: bool = False
    description: Text(2000) = ""


class RackUpdate(BaseModel):
    name: Line(100, 1) | None = None
    site_id: int | None = None
    location: Line(128) | None = None
    u_height: int | None = Field(None, ge=1, le=60)
    desc_units: bool | None = None
    description: Text(2000) | None = None


class RackOut(ORM):
    id: int
    name: str
    site_id: int | None
    location: str
    u_height: int
    desc_units: bool
    description: str


class PlacementIn(BaseModel):
    """Размещение устройства. rack_id=None — убрать из стойки; position=None — в стойке, место не задано."""
    rack_id: int | None = None
    position: int | None = Field(None, ge=1, le=60)
    face: RackFace = "front"
    u_height: int = Field(1, ge=1, le=60)
    full_depth: bool = True
