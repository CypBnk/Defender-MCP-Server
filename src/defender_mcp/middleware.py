"""FastMCP middleware: audit trail per tool call and per-user rate limiting."""
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Mapping, Optional

from .auth.identity import current_user, user_key

audit_log = logging.getLogger("defender_mcp.audit")
log = logging.getLogger("defender_mcp")

_SECRET_ARGS = {"confirmation_token"}
_MAX_AUDIT_STR = 500  # long arguments (KQL queries, comments) are cut in the audit log


def client_ip() -> Optional[str]:
    """Caller IP as seen by the Container Apps ingress (first X-Forwarded-For entry), best effort."""
    try:
        from fastmcp.server.dependencies import get_http_request

        request = get_http_request()
    except Exception:  # noqa: BLE001 - no HTTP request (tests, stdio)
        return None
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    client = getattr(request, "client", None)
    return getattr(client, "host", None)


def _audit_value(key: str, value: Any) -> Any:
    if key in _SECRET_ARGS:
        return "<redacted>"
    if isinstance(value, str) and len(value) > _MAX_AUDIT_STR:
        return value[:_MAX_AUDIT_STR] + f"... [{len(value)} chars]"
    return value


def build_audit_record(tool: str, arguments: Optional[dict], *, admin: bool, status: str, duration_ms: float,
                       user: dict, error: Optional[str] = None, ip: Optional[str] = None,
                       immediate: bool = False) -> dict:
    """Read tools: argument names only (no KQL, IOCs or UPNs). Admin tools: full arguments (long values cut,
    tokens redacted), so the audit log shows who changed what on which object."""
    args = arguments or {}
    if admin:
        shown = {k: _audit_value(k, v) for k, v in args.items() if v not in (None, "", [])}
        # immediate calls (comments, antivirus scans, status reads) run without confirmation;
        # every other admin call without token is a preview
        phase = "execute" if (args.get("confirmation_token") or immediate) else "preview"
    else:
        shown = sorted(k for k, v in args.items() if v not in (None, "", [], False))
        phase = None
    record = {"event": "tool_call", "tool": tool, "kind": "admin" if admin else "read", "status": status,
              "duration_ms": round(duration_ms, 1), "user_oid": user.get("oid") or user.get("sub"), "user_upn": user.get("upn"),
              "arguments": shown}
    if ip:
        record["client_ip"] = ip
    if phase:
        record["phase"] = phase
    if error:
        record["error"] = error
    return record


def make_audit_middleware(admin_tools: set[str],
                          immediate: Optional[Mapping[str, Callable[[Optional[dict]], bool]]] = None) -> Any:
    """immediate: tool name -> predicate(arguments) for admin calls that run without confirmation."""
    from fastmcp.server.middleware import Middleware

    immediate = dict(immediate or {})

    class AuditMiddleware(Middleware):
        async def on_call_tool(self, context, call_next):  # type: ignore[override]
            message = context.message
            name = getattr(message, "name", "?")
            arguments = getattr(message, "arguments", None) or {}
            started = time.perf_counter()
            status, error = "ok", None
            try:
                result = await call_next(context)
                if getattr(result, "is_error", False) or getattr(result, "isError", False):
                    status = "error"
                return result
            except Exception as exc:
                status, error = "error", type(exc).__name__
                raise
            finally:
                check = immediate.get(name)
                record = build_audit_record(name, arguments, admin=name in admin_tools, status=status,
                                            duration_ms=(time.perf_counter() - started) * 1000,
                                            user=current_user(), error=error, ip=client_ip(),
                                            immediate=bool(check and check(arguments)))
                audit_log.info("tool %s %s", name, status, extra={"fields": record})

    return AuditMiddleware()


def rate_limit_client_id(*_args: Any, **_kwargs: Any) -> str:
    """Rate-limit per signed-in user instead of globally."""
    try:
        return user_key() or "anonymous"
    except Exception:  # noqa: BLE001 - token without user id; the tool call itself is refused
        return "anonymous"


def add_middlewares(mcp: Any, settings: Any, admin_tools: set[str],
                    immediate: Optional[Mapping[str, Callable[[Optional[dict]], bool]]] = None) -> list[str]:
    """Order matters: error handling first (catches everything), then audit, rate limit, cache."""
    added: list[str] = []
    try:
        from fastmcp.server.middleware.error_handling import ErrorHandlingMiddleware

        # transform_errors=False: keep ToolError results as tool errors the model can read.
        mcp.add_middleware(ErrorHandlingMiddleware(include_traceback=False, transform_errors=False))
        added.append("error_handling")
    except Exception as exc:  # noqa: BLE001
        log.warning("ErrorHandlingMiddleware unavailable: %s", exc)
    mcp.add_middleware(make_audit_middleware(admin_tools, immediate))
    added.append("audit")
    if settings.rate_limit_rps > 0:
        try:
            from fastmcp.server.middleware.rate_limiting import RateLimitingMiddleware

            mcp.add_middleware(RateLimitingMiddleware(max_requests_per_second=settings.rate_limit_rps,
                                                      burst_capacity=settings.rate_limit_burst,
                                                      get_client_id=rate_limit_client_id))
            added.append("rate_limiting")
        except Exception as exc:  # noqa: BLE001
            log.warning("RateLimitingMiddleware unavailable: %s", exc)
    if settings.response_cache_ttl_seconds > 0:
        try:
            from fastmcp.server.middleware.caching import (CallToolSettings, ListToolsSettings,
                                                           ResponseCachingMiddleware)

            kwargs: dict = {
                "list_tools_settings": ListToolsSettings(ttl=settings.response_cache_ttl_seconds),
                "call_tool_settings": CallToolSettings(ttl=settings.response_cache_ttl_seconds,
                                                       included_tools=list(CACHEABLE_TOOLS)),
            }
            # In memory per replica; entries are partitioned per access token, so results never cross users.
            mcp.add_middleware(ResponseCachingMiddleware(**kwargs))
            added.append("response_cache")
        except Exception as exc:  # noqa: BLE001
            log.warning("ResponseCachingMiddleware unavailable: %s", exc)
    return added


# Read tools whose results change rarely; only cached when RESPONSE_CACHE_TTL_SECONDS > 0.
CACHEABLE_TOOLS = ("get_hunting_schema", "list_detection_rules", "get_secure_score", "get_identity_health",
                   "list_attack_simulations", "get_cloud_app_discovery", "get_vulnerability_overview",
                   "get_threat_intelligence", "get_antivirus_health")
