"""KQL building blocks for Microsoft Defender XDR advanced hunting (Graph POST /security/runHuntingQuery).

Every value that goes into a prebuilt query passes through a validator here and is inserted as an escaped
KQL string literal; numbers are clamped integers. Tool arguments therefore cannot change the structure of a
prebuilt query (no KQL injection). Free-form KQL (run_hunting_query) stays read-only by nature of the API."""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Iterable, Optional

from . import runtime
from .errors import GraphError, InputError
from .graph.odata import clamp_int, is_guid, is_upn
from .graph.paging import clamp, json_size
from .shaping import UNTRUSTED_NOTE, truncate

HUNTING_PATH = "/security/runHuntingQuery"
MAX_QUERY_CHARS = 20_000
MAX_DAYS = 30            # advanced hunting keeps 30 days of data (longer only with Microsoft Sentinel)
MAX_TIMESPAN_DAYS = 180  # service maximum for the Timespan parameter
KQL_HINT = ("KQL error. Check table and column names with get_hunting_schema(table=...); column names are "
            "case-sensitive and advanced hunting keeps 30 days of data.")
MORE_ROWS_HINT = ("More rows match. Narrow the filters or the time window, raise max_items (up to the server limit) "
                  "or aggregate with run_hunting_query (summarize).")

_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_QUERY_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")  # tab, CR and LF are allowed in queries
_MDE_ID = re.compile(r"^[0-9a-fA-F]{40}$")
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}(?:\.[A-Za-z0-9_-]{1,63}){0,10}$")
_DOMAIN = re.compile(r"^(?=.{3,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,62}$")
_HASH_LEN = {"sha256": 64, "sha1": 40, "md5": 32}
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_TABLE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{1,79}$")
_SAM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._$\-]{0,63}$")
_RENDER = re.compile(r"\|\s*render\b", re.IGNORECASE)


# --------------------------------------------------------------------------- literals and validators
def kql_str(value: Any, name: str = "value", max_len: int = 256) -> str:
    """Single-quoted KQL string literal with backslash and quote escaped. Control characters are rejected."""
    v = str(value if value is not None else "").strip()
    if not v:
        raise InputError(f"{name} must not be empty.")
    if _CTRL.search(v) or len(v) > max_len:
        raise InputError(f"{name} is too long or contains control characters.")
    return "'" + v.replace("\\", "\\\\").replace("'", "\\'") + "'"


def ip_list(ip: str) -> str:
    """KQL list for an address as Defender for Endpoint records it in LocalIP / RemoteIP: an IPv4 address can also
    appear IPv4-mapped (::ffff:a.b.c.d, IP type 'FourToSixMapping'). Expects a validated address."""
    if ":" in ip:
        return f"({kql_str(ip)})"
    return f"({kql_str(ip)}, {kql_str('::ffff:' + ip)})"


def software_condition(value: Any, name: str = "software") -> str:
    """Product filter for the Defender Vulnerability Management tables. They name software with lower-case tokens
    (vendor 'google', name 'chrome'; 'microsoft' / 'edge_chromium-based'), so every word of the input must occur in
    vendor_name: 'Google Chrome', 'chrome' and 'Microsoft Edge' all match."""
    words = [w for w in re.split(r"[\s_\-]+", str(value or "").lower()) if w]
    if not words:
        raise InputError(f"{name} must not be empty.")
    if len(words) > 5:
        raise InputError(f"{name}: use at most five words, e.g. 'Google Chrome'.")
    return " and ".join(f"strcat(SoftwareVendor, '_', SoftwareName) contains {kql_str(w, name, 100)}" for w in words)


def days(value: Any, name: str = "days", hi: int = MAX_DAYS) -> int:
    return clamp_int(value, 1, hi, name)


def is_mde_device_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_MDE_ID.match(value.strip()))


def device_name(value: Any) -> str:
    v = str(value or "").strip()
    if not _HOST.match(v) or len(v) > 255:
        raise InputError(f"device must be a device name (short name or FQDN), a Defender device ID or an Entra device "
                         f"ID, got {v[:80]!r}.")
    return v


def ip_address(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        raise InputError(f"Not a valid IPv4/IPv6 address: {str(value)[:80]!r}.") from None


def domain(value: Any) -> str:
    v = str(value or "").strip().lower().rstrip(".")
    if "://" in v or "/" in v:
        raise InputError("Pass a bare domain such as contoso.com (use indicator_type='url' for full URLs).")
    if not _DOMAIN.match(v):
        raise InputError(f"Not a valid domain name: {v[:80]!r}.")
    return v


def url(value: Any) -> str:
    v = str(value or "").strip()
    if not re.match(r"^https?://[^\s]{3,2000}$", v, re.IGNORECASE) or _CTRL.search(v):
        raise InputError("url must start with http:// or https:// and must not contain spaces.")
    return v


def file_hash(value: Any, kind: Optional[str] = None) -> tuple[str, str]:
    """(kind, lower-case hex) for SHA256, SHA1 or MD5; kind is derived from the length when omitted."""
    v = str(value or "").strip().lower()
    if not _HEX.match(v):
        raise InputError("A file hash must be hexadecimal (SHA256, SHA1 or MD5).")
    for name, length in _HASH_LEN.items():
        if len(v) == length and kind in (None, name):
            return name, v
    raise InputError(f"Hash length {len(v)} does not match {kind or 'SHA256 (64), SHA1 (40) or MD5 (32)'}.")


def cve_id(value: Any) -> str:
    v = str(value or "").strip().upper()
    if not _CVE.match(v):
        raise InputError("cve_id must look like CVE-2024-12345.")
    return v


def table_name(value: Any) -> str:
    v = str(value or "").strip()
    if not _TABLE.match(v):
        raise InputError("table must be a table name such as DeviceProcessEvents.")
    return v


def account(value: Any) -> tuple[str, str]:
    """('upn' | 'objectId' | 'sam', value) for a UPN, an Entra object ID or an on-premises SAM account name
    (DOMAIN\\name is reduced to name)."""
    v = str(value or "").strip()
    if is_guid(v):
        return "objectId", v.strip("{}").lower()
    if "@" in v:
        if not is_upn(v):
            raise InputError(f"Not a valid UPN: {v[:80]!r}.")
        return "upn", v
    if "\\" in v:
        v = v.split("\\", 1)[1]
    if _SAM.match(v):
        return "sam", v
    raise InputError("account must be a UPN, an Entra object ID or a SAM account name.")


def account_condition(value: Any, *, upn: str = "AccountUpn", object_id: str = "AccountObjectId",
                      sam: Optional[str] = "AccountName") -> str:
    kind, v = account(value)
    if kind == "upn":
        return f"{upn} =~ {kql_str(v)}"
    if kind == "objectId":
        return f"{object_id} =~ {kql_str(v)}"
    if not sam:
        raise InputError("This data source has no SAM account names; pass the UPN or the Entra object ID.")
    return f"{sam} =~ {kql_str(v)}"


def device_condition(value: Any, *, id_col: str = "DeviceId", name_col: str = "DeviceName") -> str:
    """Predicate for one device by Defender device ID or by name (short name matches the FQDN).
    Entra device IDs must be resolved first (resolve.resolve_device)."""
    v = str(value or "").strip()
    if is_mde_device_id(v):
        return f"{id_col} =~ {kql_str(v.lower())}"
    if is_guid(v):
        raise InputError("Entra device IDs must be resolved to a Defender device ID first.")
    name = device_name(v)
    return f"({name_col} =~ {kql_str(name)} or {name_col} startswith {kql_str(name + '.')})"


SEVERITY_LEVELS = ("Low", "Medium", "High", "Critical")


def min_severity_condition(severity: Any, column: str = "VulnerabilitySeverityLevel") -> str:
    """'High' -> column in ("High", "Critical"): the severity argument of the vulnerability tools is a minimum."""
    if severity not in SEVERITY_LEVELS:
        raise InputError(f"severity must be one of: {', '.join(SEVERITY_LEVELS)}.")
    levels = SEVERITY_LEVELS[SEVERITY_LEVELS.index(severity):]
    return f"{column} in ({', '.join(kql_str(x) for x in levels)})"


# --------------------------------------------------------------------------- execution
def validate_query(query: Any) -> str:
    q = str(query or "").strip()
    if not q:
        raise InputError("query must not be empty.")
    if len(q) > MAX_QUERY_CHARS:
        raise InputError(f"query is longer than {MAX_QUERY_CHARS} characters.")
    if _QUERY_CTRL.search(q):
        raise InputError("query contains control characters.")
    return q


def with_row_limit(query: str, rows: int) -> str:
    """Append '| take N' so a broad query cannot return a huge result; skipped for 'render' queries."""
    q = query.rstrip().rstrip(";").rstrip()
    if _RENDER.search(q):
        return q
    return f"{q}\n| take {int(rows)}"


async def execute(query: str, *, timespan_days: Optional[int] = None,
                  workspace_id: Optional[str] = None) -> tuple[list[str], list[dict]]:
    """Run KQL; returns (column names, rows) with row keys normalized to the schema's column names.
    workspace_id: Microsoft Sentinel / ISOC workspace (GUID) for workspace tables; None = the user's primary one."""
    q = validate_query(query)
    body: dict[str, Any] = {"Query": q}
    if timespan_days:
        body["Timespan"] = f"P{clamp_int(timespan_days, 1, MAX_TIMESPAN_DAYS, 'timespan_days')}D"
    if workspace_id:
        body["workspaceId"] = workspace_id
    s = runtime.settings()
    try:
        resp = await runtime.graph().post(HUNTING_PATH, json_body=body, version="v1.0", idempotent=True,
                                          timeout=s.hunting_timeout_seconds)
    except GraphError as exc:
        if exc.status == 400:
            raise GraphError(400, exc.code, exc.graph_message, request_id=exc.request_id, hint=KQL_HINT) from None
        raise
    resp = resp if isinstance(resp, dict) else {}
    schema = resp.get("schema") or resp.get("Schema") or []
    columns = [str(c.get("name") or c.get("Name")) for c in schema if isinstance(c, dict)]
    canonical = {c.lower(): c for c in columns}
    rows = []
    for row in resp.get("results") or resp.get("Results") or []:
        if isinstance(row, dict):
            rows.append({canonical.get(str(k).lower(), str(k)): v for k, v in row.items()})
    return columns, rows


def _cell(value: Any, max_str: int) -> Any:
    if isinstance(value, str):
        return truncate(value, max_str)
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
        if len(text) > max_str:
            return truncate(text, max_str)
    return value


def shape_rows(rows: list[dict], *, limit: int, max_str: int = 1000, drop: Iterable[str] = ()) -> tuple[list, bool]:
    """Drop empty cells, cap long strings, stop at `limit` rows or the response-size budget."""
    budget = runtime.settings().max_response_bytes
    drop = set(drop)
    out: list[dict] = []
    size = 2
    for row in rows:
        item = {k: _cell(v, max_str) for k, v in row.items()
                if k not in drop and v is not None and v != "" and v != [] and v != {}}
        item_size = json_size(item) + 1
        if len(out) >= limit or (out and size + item_size > budget):
            break
        out.append(item)
        size += item_size
    return out, len(rows) > len(out)


async def hunt(query: str, *, max_items: Optional[int] = None, timespan_days: Optional[int] = None,
               max_str: int = 1000, include_query: bool = True, append_limit: bool = True,
               workspace_id: Optional[str] = None, **meta: Any) -> dict:
    """Run a (prebuilt or user) query and return a bounded, LLM-friendly result."""
    limit = clamp(max_items)
    q = with_row_limit(query, limit + 1) if append_limit else query
    columns, rows = await execute(q, timespan_days=timespan_days, workspace_id=workspace_id)
    shaped, truncated = shape_rows(rows, limit=limit, max_str=max_str)
    result: dict[str, Any] = dict(meta)
    result.update({"count": len(shaped), "truncated": truncated, "rows": shaped})
    if not shaped and columns:
        result["columns"] = columns
    if truncated:
        result["hint"] = MORE_ROWS_HINT
    if include_query:
        result["kql"] = q
    if shaped:
        result["note"] = UNTRUSTED_NOTE
    return result


async def rows(query: str, *, timespan_days: Optional[int] = None, workspace_id: Optional[str] = None) -> list[dict]:
    """Raw normalized rows (internal use, e.g. resolution and summaries)."""
    _, result = await execute(query, timespan_days=timespan_days, workspace_id=workspace_id)
    return result
