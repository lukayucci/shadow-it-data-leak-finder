"""
Guard SSRF: valida que un host/URL apunte a destinos públicos.

Objetivo: evitar que un usuario use el scanner pasivo para alcanzar
servicios internos (loopback, redes privadas, link-local/metadata,
multicast, reservadas) o puertos no web.
"""
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Tuple
from urllib.parse import urlparse

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "instance-data.ec2.internal",
}

BLOCKED_SUFFIXES = (
    ".local",
    ".internal",
    ".localdomain",
    ".home.arpa",
    ".lan",
)

ALLOWED_PORTS = {None, 80, 443}
_DNS_TIMEOUT = 4.0


def _is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def resolve_host(host: str, port: int | None = None) -> list[str]:
    infos = socket.getaddrinfo(host, port or 0, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


def _resolve_with_timeout(host: str) -> list[str]:
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(resolve_host, host)
        return future.result(timeout=_DNS_TIMEOUT)


def validate_host(host: str) -> Tuple[bool, str]:
    """Devuelve (es_seguro, motivo)."""
    host = (host or "").strip().strip(".").lower()
    if not host:
        return False, "host vacío"

    if host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_SUFFIXES):
        return False, "host reservado o interno"

    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not _is_public_ip(host):
            return False, f"IP no pública: {host}"
        return True, "ok"

    try:
        ips = _resolve_with_timeout(host)
    except Exception as exc:
        return False, f"DNS no resuelve: {exc}"

    if not ips:
        return False, "DNS sin registros"

    for ip in ips:
        if not _is_public_ip(ip):
            return False, f"resuelve a IP no pública: {ip}"
    return True, "ok"


def validate_url(url: str) -> Tuple[bool, str]:
    """Valida scheme, puerto y host de una URL (o host suelto)."""
    raw = (url or "").strip()
    if not raw:
        return False, "URL vacía"
    if "://" not in raw:
        raw = f"https://{raw}"
    try:
        parsed = urlparse(raw)
    except Exception:
        return False, "URL inválida"

    if parsed.scheme not in ("http", "https"):
        return False, f"scheme no permitido: {parsed.scheme}"
    if parsed.port not in ALLOWED_PORTS:
        return False, f"puerto no permitido: {parsed.port}"

    host = parsed.hostname or ""
    return validate_host(host)
