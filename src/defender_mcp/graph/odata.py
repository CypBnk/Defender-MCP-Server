"""Input validation and OData helpers. Every ID that goes into a URL path and every value
that goes into a $filter passes through one of these functions."""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from ..errors import InputError

_GUID_RE = re.compile(r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$")
_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-.=+]{0,199}$")
# Entra UPN: local part A-Z a-z 0-9 ' . - _ ! # ^ ~ (guest UPNs contain #EXT#)
_UPN_RE = re.compile(
    r"^[A-Za-z0-9'._\-!#^~]{1,113}@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$"
)
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def is_guid(value: object) -> bool:
    return isinstance(value, str) and bool(_GUID_RE.match(value.strip()))


def guid(value: object, name: str = "id") -> str:
    """Normalized GUID or InputError."""
    try:
        return str(uuid.UUID(str(value).strip().strip("{}")))
    except (ValueError, AttributeError, TypeError):
        raise InputError(f"{name} must be a GUID, got {str(value)[:80]!r}.") from None


def key(value: object, name: str = "id") -> str:
    """Path segment for IDs that are not always GUIDs (app protection policies 'T_...',
    detected apps, alert IDs). Returns a percent-encoded, validated segment."""
    v = str(value or "").strip()
    if is_guid(v):
        return guid(v, name)
    if not _KEY_RE.match(v) or ".." in v:
        raise InputError(f"{name} contains unsupported characters: {v[:80]!r}.")
    return quote(v, safe="-_.")


def is_upn(value: object) -> bool:
    return isinstance(value, str) and bool(_UPN_RE.match(value.strip()))


def odata_str(value: object, name: str = "value", max_len: int = 256) -> str:
    """Quoted OData string literal with single quotes escaped."""
    v = str(value if value is not None else "").strip()
    if not v:
        raise InputError(f"{name} must not be empty.")
    if _CTRL_RE.search(v) or len(v) > max_len:
        raise InputError(f"{name} is too long or contains control characters.")
    return "'" + v.replace("'", "''") + "'"


def clamp_int(value: object, lo: int, hi: int, name: str) -> int:
    try:
        v = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise InputError(f"{name} must be an integer.") from None
    if not lo <= v <= hi:
        raise InputError(f"{name} must be between {lo} and {hi}.")
    return v


def iso_hours_ago(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_days_ago(days: int) -> str:
    return iso_hours_ago(days * 24)
