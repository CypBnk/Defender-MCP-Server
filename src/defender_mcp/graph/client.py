"""HTTP clients for Microsoft Graph and the Defender for Endpoint API: path guard, OBO token, retries,
throttling, errors. Both share one implementation; only base URL, versions and error hints differ."""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import uuid
from typing import Any, Awaitable, Callable, Optional

from .. import http as http_mod
from ..errors import GraphError, InputError
from ..observability import tracer
from ..settings import Settings

log = logging.getLogger("defender_mcp.graph")

_PATH_RE = re.compile(r"^/[A-Za-z0-9\-._~!$&'()*+,;=:@%/]*$")
_BAD_ENCODED = ("%2f", "%5c", "%2e", "%00")
_GUID_IN_PATH = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_HEX_IN_PATH = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
_RETRY_STATUSES = {429, 503, 504}
VERSIONS = ("v1.0", "beta")

GRAPH_HINTS = {
    400: "Request not supported as sent (for example an unsupported filter combination). Try fewer filters.",
    401: "The user token is missing or expired. Reconnect the MCP connection in Copilot Studio.",
    403: "Missing permission: the Graph scope is not admin-consented for this app, or the signed-in user lacks the "
         "Defender XDR / Entra role (e.g. Security Reader, Security Operator) or access to the device group.",
    404: "Not found, or not visible to the signed-in user.",
    409: "Conflict with the current state of the object.",
    429: "Microsoft Graph is throttling requests (advanced hunting has a per-tenant quota). Try again in a minute.",
}
MDE_HINTS = {
    400: "Request not accepted by Defender for Endpoint (for example the action is not supported on this OS, or an "
         "action of the same type is already pending on the device).",
    401: "The user token is missing or expired. Reconnect the MCP connection in Copilot Studio.",
    403: "Missing permission: the WindowsDefenderATP permission is not admin-consented for this app "
         "(deploy.ps1 -ConfigureAppRegistration -GrantWritePermissions), or the signed-in user lacks the Defender role "
         "permission (e.g. 'Active remediation actions') or access to the device group.",
    404: "Device or object not found in Defender for Endpoint, or not visible to the signed-in user.",
    409: "Conflict: an action of this type is probably already pending for the device.",
    429: "Defender for Endpoint API is throttling requests (100 calls per minute). Try again in a minute.",
}


MDCA_HINTS = {
    400: "Request not accepted by Defender for Cloud Apps (the undocumented endpoint may have changed). Tag the app in "
         "the portal: Cloud apps > Cloud discovery > Discovered apps.",
    401: "Defender for Cloud Apps rejected the credentials. MDCA_AUTH=obo: reconnect in Copilot Studio and check the "
         "admin consent for 'Microsoft Cloud App Security' (Discovery.manage). MDCA_AUTH=token: renew the API token.",
    403: "Defender for Cloud Apps refused the action: the user (or the API token owner) needs a role that may manage "
         "discovered apps (e.g. Security Administrator or Cloud App Security Administrator), or the API does not accept "
         "Entra tokens for this undocumented endpoint (then use MDCA_AUTH=token or the portal).",
    404: "Endpoint or app not found in Defender for Cloud Apps (check MDCA_API_URL and the app ID; the undocumented "
         "endpoint may have changed).",
    429: "Defender for Cloud Apps throttles API requests (30 per minute per tenant). Try again in a minute.",
}


def validate_path(path: str) -> str:
    """Reject anything that could change the request target: query/fragment characters,
    dot segments, encoded slashes/dots, backslashes, whitespace."""
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 2048:
        raise InputError("Invalid API path.")
    if not _PATH_RE.match(path) or "//" in path:
        raise InputError("Invalid characters in API path.")
    low = path.lower()
    if any(bad in low for bad in _BAD_ENCODED):
        raise InputError("Encoded path separators are not allowed.")
    if any(seg in (".", "..") for seg in path.split("/")):
        raise InputError("Dot segments are not allowed in API paths.")
    return path


def template_path(path: str) -> str:
    """Path for logs/telemetry without IDs or UPNs."""
    out = []
    for seg in path.split("/"):
        if "@" in seg or "%40" in seg.lower():
            out.append("{upn}")
        else:
            out.append(_HEX_IN_PATH.sub("{id}", _GUID_IN_PATH.sub("{id}", seg)))
    return "/".join(out)


class GraphClient:
    """Microsoft Graph (https://graph.microsoft.com/{v1.0|beta}/...)."""

    service = "Graph"
    hints = GRAPH_HINTS
    auth_scheme = "Bearer"
    # Security enums are evolvable: without this header Graph returns newer members (incident status
    # awaitingAction, alert serviceSource microsoftSentinel, ...) as 'unknownFutureValue' and rejects them in $filter.
    default_headers: dict = {"Prefer": "include-unknown-enum-members"}

    def __init__(self, settings: Settings, token_provider: Callable[[], Awaitable[str]], *,
                 http: Any = None, sleep: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None:
        self._s = settings
        self._token = token_provider
        self._http = http
        self._sleep = sleep
        self._sem = asyncio.Semaphore(settings.graph_max_concurrency)
        self.base = self._base_url(settings)

    @staticmethod
    def _base_url(settings: Settings) -> str:
        return f"https://{settings.graph_host}"

    # ----------------------------------------------------------------- helpers
    def url(self, version: str, path: str) -> str:
        if version not in VERSIONS:
            raise InputError(f"Unsupported Graph version {version!r}.")
        return f"{self.base}/{version}{validate_path(path)}"

    def _backoff(self, attempt: int) -> float:
        return min(self._s.graph_retry_max_wait_seconds, (2 ** (attempt - 1)) + random.uniform(0, 0.5))

    # ----------------------------------------------------------------- request
    async def request(self, method: str, path: str, *, version: str = "v1.0",
                      params: Optional[dict] = None, json_body: Any = None,
                      advanced: bool = False, idempotent: Optional[bool] = None,
                      headers: Optional[dict] = None, timeout: Optional[float] = None) -> Any:
        extra_headers = dict(headers or {})
        method = method.upper()
        url = self.url(version, path)
        if idempotent is None:
            idempotent = method in ("GET", "HEAD")
        token = await self._token()
        headers = {
            "Authorization": f"{self.auth_scheme} {token}",
            "Accept": "application/json",
            "client-request-id": str(uuid.uuid4()),
            **self.default_headers,
        }
        if json_body is not None:
            # KQL and comments may contain non-ASCII characters (e.g. lookalike characters in subjects).
            headers["Content-Type"] = "application/json; charset=utf-8"
        if advanced:
            headers["ConsistencyLevel"] = "eventual"
        for name, value in extra_headers.items():
            if name.lower() in {"authorization", "host"}:
                continue
            headers[name] = str(value)
        http = self._http or http_mod.get_http_client(self._s.graph_timeout_seconds)
        span_cm = None
        t = tracer()
        if t is not None:
            span_cm = t.start_as_current_span(
                f"{self.service.lower()} {method}", attributes={"http.request.method": method, "api.version": version,
                                                               "api.path": template_path(path)})
        span = span_cm.__enter__() if span_cm is not None else None
        try:
            resp = await self._send(http, method, url, params, json_body, headers, idempotent, timeout)
            status = resp.status_code
            request_id = _header(resp, "request-id")
            if span is not None:
                span.set_attribute("http.response.status_code", status)
                if request_id:
                    span.set_attribute("api.request_id", request_id)
            log.debug("%s %s %s %s -> %s", self.service, method, version, template_path(path), status,
                      extra={"fields": {"api_status": status, "request_id": request_id, "service": self.service}})
            if status >= 400:
                raise _error_from(resp, request_id, self.hints, self.service)
            return _parse(resp)
        finally:
            if span_cm is not None:
                span_cm.__exit__(None, None, None)

    async def _send(self, http: Any, method: str, url: str, params: Optional[dict], json_body: Any,
                    headers: dict, idempotent: bool, timeout: Optional[float]) -> Any:
        attempt = 0
        kwargs: dict = {"params": params, "json": json_body, "headers": headers}
        max_retries, max_wait = self._s.graph_max_retries, self._s.graph_retry_max_wait_seconds
        if timeout:
            kwargs["timeout"] = timeout
            # Long-running calls (advanced hunting) must finish within the client's tool timeout (Copilot Studio:
            # 120 s): a timed-out query is not repeated, other transient errors are retried once after a short wait.
            max_retries, max_wait = min(1, max_retries), min(5.0, max_wait)
        while True:
            try:
                async with self._sem:
                    resp = await http.request(method, url, **kwargs)
            except Exception as exc:  # noqa: BLE001 - classified below
                if not http_mod.is_transport_error(exc):
                    raise
                timed_out = "Timeout" in type(exc).__name__
                if idempotent and attempt < max_retries and not (timeout and timed_out):
                    attempt += 1
                    await self._sleep(min(self._backoff(attempt), max_wait))
                    continue
                hint = ("The request timed out. For advanced hunting narrow the time window or add filters."
                        if timed_out else f"Network error while calling {self.service}. Try again.")
                raise GraphError(503, "NetworkError", type(exc).__name__, hint=hint, service=self.service) from None
            status = resp.status_code
            # Non-idempotent requests (actions) are only retried on 429: the request was rejected, not executed.
            retryable = status in _RETRY_STATUSES and not (timeout and status == 504)
            if retryable and attempt < max_retries and (idempotent or status == 429):
                attempt += 1
                wait = http_mod.retry_after_seconds(resp.headers) or self._backoff(attempt)
                await self._sleep(min(wait, max_wait))
                continue
            return resp

    async def get(self, path: str, *, version: str = "v1.0", params: Optional[dict] = None,
                  advanced: bool = False, headers: Optional[dict] = None) -> Any:
        return await self.request("GET", path, version=version, params=params, advanced=advanced, headers=headers)

    async def post(self, path: str, *, json_body: Any = None, version: str = "v1.0",
                   idempotent: bool = False, timeout: Optional[float] = None) -> Any:
        return await self.request("POST", path, version=version, json_body=json_body if json_body is not None else {},
                                  idempotent=idempotent, timeout=timeout)

    async def patch(self, path: str, *, json_body: Any, version: str = "v1.0") -> Any:
        return await self.request("PATCH", path, version=version, json_body=json_body)

    async def put(self, path: str, *, json_body: Any, version: str = "v1.0") -> Any:
        return await self.request("PUT", path, version=version, json_body=json_body, idempotent=True)

    async def delete(self, path: str, *, version: str = "v1.0") -> Any:
        return await self.request("DELETE", path, version=version)


class MdeClient(GraphClient):
    """Defender for Endpoint API (https://api.security.microsoft.com/api/...). The token is issued for
    MDE_RESOURCE (WindowsDefenderATP), see auth/obo.py. There are no API versions; the 'version' argument
    of the shared methods is ignored."""

    service = "Defender API"
    hints = MDE_HINTS
    default_headers: dict = {}

    @staticmethod
    def _base_url(settings: Settings) -> str:
        return f"https://{settings.mde_api_host}"

    def url(self, version: str, path: str) -> str:  # noqa: ARG002 - signature shared with GraphClient
        validate_path(path)
        if not path.startswith("/api/"):
            raise InputError("Defender API paths must start with /api/.")
        return f"{self.base}{path}"


class MdcaClient(GraphClient):
    """Defender for Cloud Apps API (https://<tenant>.<region>.portal.cloudappsecurity.com/cas/api/...), used only by
    sanction_cloud_apps for an UNDOCUMENTED endpoint. Authentication: OBO token for 'Microsoft Cloud App Security'
    (Bearer) or, with MDCA_AUTH=token, the legacy API token (scheme 'Token'). No API versions."""

    service = "Defender for Cloud Apps API"
    hints = MDCA_HINTS
    default_headers: dict = {}

    def __init__(self, settings: Settings, token_provider: Callable[[], Awaitable[str]], *,
                 auth_scheme: str = "Bearer", **kwargs: Any) -> None:
        super().__init__(settings, token_provider, **kwargs)
        self.auth_scheme = auth_scheme

    @staticmethod
    def _base_url(settings: Settings) -> str:
        return settings.mdca_api_url

    def url(self, version: str, path: str) -> str:  # noqa: ARG002 - signature shared with GraphClient
        validate_path(path)
        if not path.startswith("/cas/api/"):
            raise InputError("Defender for Cloud Apps API paths must start with /cas/api/.")
        return f"{self.base}{path}"


def _header(resp: Any, name: str) -> Optional[str]:
    try:
        return resp.headers.get(name)
    except AttributeError:
        return None


def _parse(resp: Any) -> Any:
    if resp.status_code == 204 or not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError:
        return {"raw": (resp.text or "")[:2000]}


def _error_from(resp: Any, request_id: Optional[str], hints: dict, service: str) -> GraphError:
    status = resp.status_code
    code, message = "", ""
    try:
        body = resp.json()
        err = body.get("error") or {}
        if isinstance(err, dict):
            code = str(err.get("code") or "")
            message = str(err.get("message") or "")
            inner = err.get("innerError") or err.get("innererror") or {}
            request_id = request_id or inner.get("request-id")
        elif isinstance(err, str):
            code = err
            message = str(body.get("error_description") or body.get("message") or "")
    except (ValueError, AttributeError):
        message = (getattr(resp, "text", "") or "")[:300]
    if message.startswith("{"):
        # Some services wrap their own JSON into the message: {"_version": 3, "Message": "..."}
        try:
            inner_msg = json.loads(message).get("Message")
            if inner_msg:
                message = str(inner_msg)
        except (ValueError, AttributeError):
            pass
    message = message.split(" - Operation ID")[0].strip()[:600]
    hint = hints.get(status) or (f"{service} service error. Try again later." if status >= 500 else None)
    return GraphError(status, code, message, request_id=request_id, hint=hint, service=service)
