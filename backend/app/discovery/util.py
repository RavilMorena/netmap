"""Вспомогательные функции нормализации MAC, IP, имён интерфейсов."""
import ipaddress
import re

_HEX = re.compile(r"[0-9a-fA-F]")


_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clean(value, limit: int = 255, single_line: bool = True) -> str:
    """Строка с устройства → безопасная для базы и интерфейса: без управляющих символов (NUL ломает
    PostgreSQL), без переводов строк (для имён), не длиннее колонки."""
    if value is None:
        return ""
    s = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
    s = _CTRL.sub("", s)
    if single_line:
        s = " ".join(s.split())
    return s[:limit]


def clean_name(value, limit: int = 128) -> str:
    """Имя устройства или порта: ещё и без «|» — он разделяет концы связи в ключах снимков."""
    return clean(value, limit).replace("|", "/")


def norm_mac(value: str | bytes | None) -> str:
    """Привести MAC к виду aa:bb:cc:dd:ee:ff. Пустая строка, если это не MAC."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        if len(value) == 6:
            return ":".join(f"{b:02x}" for b in value)
        try:
            value = value.decode()
        except UnicodeDecodeError:
            return ""
    s = "".join(_HEX.findall(str(value)))
    if len(s) != 12:
        return ""
    s = s.lower()
    if s == "000000000000":
        return ""
    return ":".join(s[i : i + 2] for i in range(0, 12, 2))


def is_mac_like(value: str) -> bool:
    return bool(norm_mac(value)) and bool(re.fullmatch(r"[0-9a-fA-F:.\-\s]{12,17}", value.strip()))


def mac_from_oid_suffix(suffix: tuple[int, ...]) -> str:
    if len(suffix) < 6:
        return ""
    return ":".join(f"{b:02x}" for b in suffix[-6:])


def ip_from_oid_suffix(suffix: tuple[int, ...]) -> str:
    return ".".join(str(x) for x in suffix[-4:])


def mask_to_len(mask: str) -> int:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return 32


def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_usable_host_ip(value: str) -> bool:
    """Адрес, на который имеет смысл ходить при обходе сети."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_unspecified or ip.is_multicast or ip.is_link_local or
                (ip.is_loopback and not value.startswith("127.0.")))


def network_of(ip: str, prefix_len: int) -> str | None:
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False)
    except ValueError:
        return None
    if net.prefixlen >= (32 if net.version == 4 else 128) or ipaddress.ip_address(ip).is_loopback:
        return None
    return str(net)


def in_scope(ip: str, include: list[str], exclude: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for e in exclude:
        try:
            if addr in ipaddress.ip_network(e, strict=False):
                return False
        except ValueError:
            continue
    if not include:
        return True
    for i in include:
        try:
            if addr in ipaddress.ip_network(i, strict=False):
                return True
        except ValueError:
            continue
    return False


_ABBREV = [
    (r"^gigabitethernet", "gi"), (r"^gi(?=\d)", "gi"), (r"^fastethernet", "fa"), (r"^fa(?=\d)", "fa"),
    (r"^tengigabitethernet", "te"), (r"^te(?=\d)", "te"), (r"^ethernet", "eth"), (r"^eth(?=\d)", "eth"),
    (r"^et(?=\d)", "eth"), (r"^port-channel", "po"), (r"^po(?=\d)", "po"),
]


def iface_key(name: str) -> str:
    """Ключ для сопоставления имён интерфейсов из разных источников (Gi0/1 == GigabitEthernet0/1)."""
    s = name.strip().lower().replace(" ", "")
    for pat, rep in _ABBREV:
        if re.match(pat, s):
            s = re.sub(pat, rep, s, count=1)
            break
    return s


def iface_type_from_iana(if_type: int | None, name: str = "") -> str:
    m = {6: "ethernet", 117: "ethernet", 62: "ethernet", 24: "loopback", 135: "vlan", 136: "vlan",
         209: "bridge", 71: "wireless", 131: "tunnel", 53: "virtual", 161: "lag", 1: "other", 23: "ppp"}
    if if_type in m:
        return m[if_type]
    n = name.lower()
    if n.startswith(("lo", "loopback")):
        return "loopback"
    if n.startswith(("vlan", "vl")):
        return "vlan"
    if n.startswith(("br", "bridge")):
        return "bridge"
    return "other"
