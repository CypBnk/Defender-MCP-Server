"""Bounded, resumable paging with HMAC-signed cursors and a response-size budget.

Two cursor kinds:
  g  Graph cursor: path, params, version, offset into the current page (server-side paging).
  l  List cursor: tool arguments + offset into a list the tool rebuilds (client-side filters).
Cursors are signed, so a cursor can never point at a path the tool did not produce itself.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Callable, Optional
from urllib.parse import parse_qsl, urlsplit

from .. import runtime
from ..errors import InputError
from .client import validate_path

TOP_CAP = 999
MAX_PAGES_PER_CALL = 50
MORE_HINT = "More results available: call the same tool again with cursor=<cursor>."


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def encode_cursor(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(runtime.get().cursor_key, raw, hashlib.sha256).digest()[:16]
    return f"{_b64e(raw)}.{_b64e(sig)}"


def decode_cursor(cursor: str, tool: str) -> dict:
    try:
        raw_part, sig_part = cursor.strip().split(".", 1)
        raw, sig = _b64d(raw_part), _b64d(sig_part)
        expected = hmac.new(runtime.get().cursor_key, raw, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(sig, expected):
            raise ValueError("signature")
        payload = json.loads(raw)
    except Exception:  # noqa: BLE001
        raise InputError("Invalid or expired cursor. Repeat the call without cursor.") from None
    if payload.get("t") != tool:
        raise InputError("This cursor belongs to a different tool. Repeat the call without cursor.")
    return payload


def clamp(max_items: Optional[int]) -> int:
    s = runtime.settings()
    if not max_items or int(max_items) < 1:
        return s.default_max_items
    return min(int(max_items), s.hard_max_items)


def json_size(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False, default=str, separators=(",", ":")).encode())


def split_next_link(link: str) -> tuple[str, dict, str]:
    parts = urlsplit(link)
    host = runtime.settings().graph_host
    if parts.scheme != "https" or parts.netloc.lower() != host.lower():
        raise InputError("Unexpected @odata.nextLink host.")
    path = parts.path
    if path.startswith("/beta/"):
        version, path = "beta", path[len("/beta"):]
    elif path.startswith("/v1.0/"):
        version, path = "v1.0", path[len("/v1.0"):]
    else:
        raise InputError("Unexpected @odata.nextLink path.")
    return validate_path(path), dict(parse_qsl(parts.query, keep_blank_values=True)), version


def cursor_extra(cursor: str, tool: str) -> dict:
    """Read the tool-specific 'x' payload of a cursor (e.g. which aspect/transform)."""
    return decode_cursor(cursor, tool).get("x") or {}


async def get_paged(path: str, *, tool: str, params: Optional[dict] = None, version: str = "beta",
                    max_items: Optional[int] = None, use_top: bool = False, cursor: Optional[str] = None,
                    transform: Optional[Callable[[dict], Any]] = None, advanced: bool = False,
                    extra: Optional[dict] = None, top_cap: int = TOP_CAP) -> dict:
    """Fetch up to max_items (and at most MCP_MAX_RESPONSE_BYTES) from a Graph collection.

    transform(item) shapes each item; returning None drops it (client-side filter).
    Singleton responses (no 'value') are returned as one item. top_cap limits $top for APIs with a
    smaller page size (security incidents and alerts: 50)."""
    limit = clamp(max_items)
    budget = runtime.settings().max_response_bytes
    if cursor:
        c = decode_cursor(cursor, tool)
        if c.get("k") != "g":
            raise InputError("Invalid cursor for this call. Repeat the call without cursor.")
        path, params, version, offset = c["p"], dict(c.get("q") or {}), c["v"], int(c.get("o", 0))
        advanced, extra = bool(c.get("a")), c.get("x")
        validate_path(path)
    else:
        params = {k: str(v) for k, v in (params or {}).items()}
        offset = 0
        if use_top:
            params.setdefault("$top", str(min(limit, top_cap, TOP_CAP)))

    graph = runtime.graph()
    items: list = []
    size = 2
    total = None
    next_cursor: Optional[str] = None
    pages = 0

    def make_cursor(p: str, q: dict, v: str, o: int) -> str:
        payload = {"k": "g", "t": tool, "p": p, "q": q, "v": v, "o": o, "a": advanced}
        if extra:
            payload["x"] = extra
        return encode_cursor(payload)

    while True:
        resp = await graph.get(path, version=version, params=params or None, advanced=advanced)
        pages += 1
        if not isinstance(resp, dict) or "value" not in resp:
            single = transform(resp) if (transform and resp) else resp
            out_items = [single] if single else []
            return {"items": out_items, "count": len(out_items), "truncated": False, "cursor": None}
        if total is None and "@odata.count" in resp:
            total = resp["@odata.count"]
        page = resp.get("value") or []
        stopped = False
        for idx in range(offset, len(page)):
            out = transform(page[idx]) if transform else page[idx]
            if out is None:
                continue
            item_size = json_size(out) + 1
            if len(items) >= limit or (items and size + item_size > budget):
                next_cursor = make_cursor(path, params, version, idx)
                stopped = True
                break
            items.append(out)
            size += item_size
        if stopped:
            break
        offset = 0
        link = resp.get("@odata.nextLink")
        if not link:
            break
        path, params, version = split_next_link(link)
        if len(items) >= limit or pages >= MAX_PAGES_PER_CALL:
            next_cursor = make_cursor(path, params, version, 0)
            break

    result: dict = {"items": items, "count": len(items), "truncated": next_cursor is not None, "cursor": next_cursor}
    if total is not None:
        result["total"] = total
    if next_cursor:
        result["hint"] = MORE_HINT
    return result


async def collect(path: str, *, params: Optional[dict] = None, version: str = "beta",
                  limit: Optional[int] = None, advanced: bool = False) -> tuple[list, bool]:
    """Read a collection completely up to `limit` items (default MCP_SCAN_LIMIT).
    Returns (items, complete)."""
    limit = limit or runtime.settings().scan_limit
    graph = runtime.graph()
    items: list = []
    query = {k: str(v) for k, v in (params or {}).items()}
    while True:
        resp = await graph.get(path, version=version, params=query or None, advanced=advanced)
        if not isinstance(resp, dict) or "value" not in resp:
            return ([resp] if resp else []), True
        items.extend(resp.get("value") or [])
        link = resp.get("@odata.nextLink")
        if len(items) >= limit:
            return items[:limit], not link and len(items) == limit
        if not link:
            return items, True
        path, query, version = split_next_link(link)


def read_list_cursor(cursor: str, tool: str) -> tuple[dict, int]:
    """Return (tool arguments, offset) stored in a list cursor."""
    c = decode_cursor(cursor, tool)
    if c.get("k") != "l":
        raise InputError("Invalid cursor for this call. Repeat the call without cursor.")
    return dict(c.get("args") or {}), int(c.get("o", 0))


def paginate_list(items: list, *, tool: str, args: dict, offset: int = 0, max_items: Optional[int] = None,
                  complete: bool = True) -> dict:
    """Slice an already filtered list; the cursor stores the arguments so the tool can rebuild it."""
    limit = clamp(max_items)
    budget = runtime.settings().max_response_bytes
    out: list = []
    size = 2
    next_cursor = None
    for idx in range(max(0, offset), len(items)):
        item_size = json_size(items[idx]) + 1
        if len(out) >= limit or (out and size + item_size > budget):
            next_cursor = encode_cursor({"k": "l", "t": tool, "args": args, "o": idx})
            break
        out.append(items[idx])
        size += item_size
    result: dict = {"items": out, "count": len(out), "total": len(items),
                    "truncated": next_cursor is not None, "cursor": next_cursor}
    if next_cursor:
        result["hint"] = MORE_HINT
    if not complete:
        result["incomplete"] = True
        result["note"] = (f"Only the first {runtime.settings().scan_limit} objects were scanned. "
                          "Narrow the filter for a complete result.")
    return result

