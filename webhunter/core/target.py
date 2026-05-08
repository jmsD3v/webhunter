from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlparse


class ScopeError(Exception):
    pass


# Built-in in-scope ranges and patterns
_HTB_RANGES = [
    ipaddress.ip_network("10.10.10.0/24"),
    ipaddress.ip_network("10.10.11.0/24"),
]

_THM_RANGES = [
    ipaddress.ip_network("10.10.0.0/16"),
    ipaddress.ip_network("10.8.0.0/16"),
]

_RFC1918_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

_ALLOWED_SUFFIXES = (".htb", ".thm", ".local")
_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _is_ip_in_scope(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if addr.is_loopback:
        return True

    for network in _HTB_RANGES + _THM_RANGES + _RFC1918_RANGES:
        if addr in network:
            return True

    extra = os.getenv("AUTHORIZED_SCOPE", "")
    for entry in (e.strip() for e in extra.split(",") if e.strip()):
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            if entry == ip_str:
                return True

    return False


def _is_host_in_scope(host: str) -> bool:
    host = host.lower()

    if host in _ALLOWED_HOSTS:
        return True

    for suffix in _ALLOWED_SUFFIXES:
        if host.endswith(suffix):
            return True

    extra = os.getenv("AUTHORIZED_SCOPE", "")
    for entry in (e.strip() for e in extra.split(",") if e.strip()):
        entry_lower = entry.lower()
        if entry_lower == host or host.endswith("." + entry_lower):
            return True

    return False


class TargetURL:
    def __init__(
        self,
        raw: str,
        scheme: str,
        host: str,
        port: int | None,
        path: str,
        base_url: str,
    ) -> None:
        self.raw = raw
        self.scheme = scheme
        self.host = host
        self.port = port
        self.path = path
        self.base_url = base_url

    @classmethod
    def parse(cls, raw: str) -> TargetURL:
        raw = raw.strip()

        # Add scheme if missing
        if not re.match(r"^https?://", raw, re.IGNORECASE):
            raw_with_scheme = "http://" + raw
        else:
            raw_with_scheme = raw

        parsed = urlparse(raw_with_scheme)

        scheme = parsed.scheme.lower() or "http"
        host = parsed.hostname or ""
        port = parsed.port
        path = parsed.path or "/"

        if not host:
            raise ValueError(f"Cannot parse host from: {raw!r}")

        # Build canonical base URL (scheme + host + optional port)
        default_port = {"http": 80, "https": 443}.get(scheme)
        if port and port != default_port:
            base_url = f"{scheme}://{host}:{port}"
        else:
            base_url = f"{scheme}://{host}"

        return cls(
            raw=raw,
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            base_url=base_url,
        )

    def validate_scope(self, force: bool = False) -> None:
        if force:
            return

        # Try IP validation first
        try:
            ipaddress.ip_address(self.host)
            if _is_ip_in_scope(self.host):
                return
            raise ScopeError(
                f"{self.host!r} is not in authorized scope. "
                "Use --force-scope only if you have written authorization."
            )
        except ValueError:
            pass

        # Fall back to hostname validation
        if _is_host_in_scope(self.host):
            return

        raise ScopeError(
            f"{self.host!r} is not in authorized scope. "
            "Use --force-scope only if you have written authorization."
        )

    def url(self, path: str = "/") -> str:
        path = path if path.startswith("/") else "/" + path
        return self.base_url + path

    def __str__(self) -> str:
        return self.base_url

    def __repr__(self) -> str:
        return f"TargetURL(base_url={self.base_url!r}, host={self.host!r})"
