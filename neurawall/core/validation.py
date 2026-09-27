"""Schema and constraint primitives shared by every boundary crossing."""

from __future__ import annotations

import ipaddress
import re
from typing import Annotated

from pydantic import AfterValidator, Field

from neurawall.core.errors import ModelFault, ValidationFailure

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_-]{1,63}\.?$"
)
_RULE_ID_RE = re.compile(r"^R-[0-9]{6}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value!r}") from exc


def _cidr(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise ValueError(f"invalid CIDR: {value!r}") from exc


def _domain(value: str) -> str:
    v = value.strip().lower().rstrip(".")
    if not v or not _DOMAIN_RE.match(v):
        raise ValueError(f"invalid domain name: {value[:80]!r}")
    return v


def _domain_suffix(value: str) -> str:
    return _domain(value.lstrip("*."))


def _safe_text(value: str) -> str:
    return _CONTROL_CHARS.sub("", value)


IPAddress = Annotated[str, AfterValidator(_ip)]
CIDR = Annotated[str, AfterValidator(_cidr)]
DomainName = Annotated[str, AfterValidator(_domain)]
DomainSuffix = Annotated[str, AfterValidator(_domain_suffix)]
Port = Annotated[int, Field(ge=0, le=65535)]
Probability = Annotated[float, Field(ge=0.0, le=1.0)]
SafeText = Annotated[str, AfterValidator(_safe_text)]


def is_valid_rule_id(value: str) -> bool:
    return bool(_RULE_ID_RE.match(value))


def check_probability(value: float, *, what: str) -> float:
    """Range-check a model output. Out-of-range is a :class:`ModelFault`."""
    if value != value or not 0.0 <= value <= 1.0:  # NaN check first
        raise ModelFault(f"{what} out of range: {value!r}")
    return float(value)


def ip_in_any(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        if addr.version == net.version and addr in net:
            return True
    return False


def domain_matches_suffix(name: str | None, suffixes: list[str]) -> bool:
    if not name:
        return False
    n = name.lower().rstrip(".")
    return any(n == s or n.endswith("." + s) for s in suffixes)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationFailure(message)
