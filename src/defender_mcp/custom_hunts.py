"""Custom hunts: the organization's own KQL queries as one deterministic tool (run_custom_hunt).

The catalog is a JSON file (default: custom_hunts.json in this package, override with CUSTOM_HUNTS_FILE):

    [{"name": "rdp_from_internet",
      "description": "What the hunt finds (shown to the agent).",
      "query": "DeviceLogonEvents | where Timestamp > ago({{days}}d) | where DeviceName startswith {{device}}",
      "parameters": {"days": {"type": "days", "default": 7, "description": "Look-back window"},
                     "device": {"type": "device", "required": true, "description": "Device name"}}}]

Placeholders {{name}} are replaced by validated values: text types become quoted, escaped KQL string
literals (never write quotes around a placeholder), numbers are inserted as numbers, datetime as datetime(...).
The file is checked when the server starts; an invalid catalog stops the start with a clear message."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Callable

from . import kql
from .errors import InputError
from .graph.odata import clamp_int, is_upn

_NAME = re.compile(r"^[a-z][a-z0-9_]{2,40}$")
_PLACEHOLDER = re.compile(r"\{\{\s*([a-z][a-z0-9_]{0,40})\s*\}\}")
MAX_HUNTS = 50


def _iso(value: Any) -> str:
    try:
        ts = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00").replace(" ", "T", 1))
    except ValueError:
        raise InputError("datetime parameters must be ISO 8601, e.g. 2026-11-02T08:15:00Z.") from None
    ts = (ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    return f"datetime({ts.strftime('%Y-%m-%dT%H:%M:%SZ')})"


def _device(value: Any) -> str:
    v = str(value or "").strip()
    return kql.kql_str(v.lower() if kql.is_mde_device_id(v) else kql.device_name(v))


def _upn(value: Any) -> str:
    v = str(value or "").strip()
    if not is_upn(v):
        raise InputError(f"Not a valid UPN: {v[:80]!r}.")
    return kql.kql_str(v)


# type -> renderer(value) returning a KQL literal
RENDERERS: dict[str, Callable[[Any], str]] = {
    "string": lambda v: kql.kql_str(str(v), "value", 500),
    "upn": _upn,
    "account": lambda v: kql.kql_str(kql.account(v)[1]),
    "ip": lambda v: kql.kql_str(kql.ip_address(v)),
    "domain": lambda v: kql.kql_str(kql.domain(v)),
    "url": lambda v: kql.kql_str(kql.url(v)),
    "sha1": lambda v: kql.kql_str(kql.file_hash(v, "sha1")[1]),
    "sha256": lambda v: kql.kql_str(kql.file_hash(v, "sha256")[1]),
    "md5": lambda v: kql.kql_str(kql.file_hash(v, "md5")[1]),
    "device": _device,
    "int": lambda v: str(clamp_int(v, -1_000_000_000, 1_000_000_000, "value")),
    "days": lambda v: str(kql.days(v)),
    "datetime": _iso,
}


class CatalogError(RuntimeError):
    """Invalid custom hunt catalog (raised at startup)."""


def _validate(raw: Any, source: str) -> dict[str, dict]:
    if not isinstance(raw, list):
        raise CatalogError(f"{source}: the catalog must be a JSON array of hunts.")
    if len(raw) > MAX_HUNTS:
        raise CatalogError(f"{source}: at most {MAX_HUNTS} custom hunts are supported.")
    hunts: dict[str, dict] = {}
    for i, h in enumerate(raw):
        where = f"{source}: hunt #{i + 1}"
        if not isinstance(h, dict):
            raise CatalogError(f"{where} must be an object.")
        name = h.get("name")
        if not isinstance(name, str) or not _NAME.match(name):
            raise CatalogError(f"{where}: name must match {_NAME.pattern} (got {name!r}).")
        if name in hunts:
            raise CatalogError(f"{where}: duplicate name {name!r}.")
        desc, query = h.get("description"), h.get("query")
        if not isinstance(desc, str) or not 10 <= len(desc) <= 600:
            raise CatalogError(f"{where} ({name}): description needs 10-600 characters.")
        if not isinstance(query, str) or not query.strip() or len(query) > kql.MAX_QUERY_CHARS:
            raise CatalogError(f"{where} ({name}): query is missing or too long.")
        params = h.get("parameters") or {}
        if not isinstance(params, dict):
            raise CatalogError(f"{where} ({name}): parameters must be an object.")
        for pname, spec in params.items():
            if not isinstance(spec, dict) or spec.get("type") not in RENDERERS:
                raise CatalogError(f"{where} ({name}): parameter {pname!r} needs a type out of {sorted(RENDERERS)}.")
            if "default" in spec:
                try:
                    RENDERERS[spec["type"]](spec["default"])
                except InputError as exc:
                    raise CatalogError(f"{where} ({name}): invalid default for {pname!r}: {exc}") from None
        used = set(_PLACEHOLDER.findall(query))
        missing, unused = used - set(params), set(params) - used
        if missing:
            raise CatalogError(f"{where} ({name}): placeholders without parameter definition: {sorted(missing)}.")
        if unused:
            raise CatalogError(f"{where} ({name}): parameters not used in the query: {sorted(unused)}.")
        if "{{" in _PLACEHOLDER.sub("", query):
            raise CatalogError(f"{where} ({name}): malformed placeholder (use {{{{name}}}} with lower-case names).")
        hunts[name] = {"name": name, "description": desc.strip(), "query": query.strip(), "parameters": params}
    return hunts


@lru_cache(maxsize=4)
def load_catalog(path: str = "") -> dict[str, dict]:
    """Validated catalog; path '' = the file shipped with the package."""
    if path:
        file = Path(path)
        if not file.is_file():
            raise CatalogError(f"CUSTOM_HUNTS_FILE {path!r} does not exist.")
        text, source = file.read_text(encoding="utf-8"), path
    else:
        res = resources.files(__package__).joinpath("custom_hunts.json")
        if not res.is_file():
            return {}
        text, source = res.read_text(encoding="utf-8"), "custom_hunts.json"
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CatalogError(f"{source}: invalid JSON ({exc.msg}, line {exc.lineno}).") from None
    return _validate(raw, source)


def describe(hunt: dict) -> dict:
    return {"name": hunt["name"], "description": hunt["description"],
            "parameters": {k: {key: v[key] for key in ("type", "description", "required", "default") if key in v}
                           for k, v in hunt["parameters"].items()}}


def render(hunt: dict, values: dict) -> str:
    """Query with every placeholder replaced by a validated literal."""
    params = hunt["parameters"]
    unknown = set(values) - set(params)
    if unknown:
        raise InputError(f"Unknown parameter(s) for {hunt['name']}: {', '.join(sorted(unknown))}. "
                         f"Expected: {', '.join(sorted(params)) or 'none'}.")
    literals: dict[str, str] = {}
    for pname, spec in params.items():
        if pname in values and values[pname] not in (None, ""):
            value = values[pname]
        elif "default" in spec:
            value = spec["default"]
        elif spec.get("required", True):
            raise InputError(f"Parameter '{pname}' ({spec['type']}) is required for {hunt['name']}.")
        else:
            raise InputError(f"Parameter '{pname}' of {hunt['name']} has no value and no default.")
        try:
            literals[pname] = RENDERERS[spec["type"]](value)
        except InputError as exc:
            raise InputError(f"Parameter '{pname}': {exc}") from None
    return _PLACEHOLDER.sub(lambda m: literals[m.group(1)], hunt["query"])
