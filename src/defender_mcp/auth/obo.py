"""On-Behalf-Of token exchange (user token -> Graph or Defender for Endpoint API token), async and cached.

Implemented directly against the Entra token endpoint with the shared httpx client:
no blocking MSAL call on the event loop, one exchange per user token and resource until it expires.
One provider instance per resource (Microsoft Graph, WindowsDefenderATP)."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections import OrderedDict
from typing import Any, Callable, Optional

from .. import http as http_mod
from ..errors import AuthError
from ..settings import Settings
from .identity import assert_delegated, incoming_user_token

log = logging.getLogger("defender_mcp.auth")

_MAX_CACHE = 2000
_REFRESH_MARGIN = 300  # seconds before expiry a cached Graph token is replaced

_AADSTS_HINTS = {
    65001: "Admin consent for the API permissions is missing. Grant admin consent in the app registration (API permissions) "
           "or run deploy.ps1 -ConfigureAppRegistration.",
    50013: "The user token is invalid or expired. Reconnect the MCP connection in Copilot Studio.",
    500133: "The user token is expired. Reconnect the MCP connection in Copilot Studio.",
    70011: "Invalid scope requested for the target API.",
    500011: "The target API is not available in this tenant (resource principal not found). For Defender for Endpoint "
            "actions the WindowsDefenderATP service principal is missing, for sanction_cloud_apps 'Microsoft Cloud App "
            "Security': run deploy.ps1 -ConfigureAppRegistration -GrantWritePermissions.",
    650052: "The tenant has no service principal for the requested API (WindowsDefenderATP for Defender for Endpoint "
            "actions). Run deploy.ps1 -ConfigureAppRegistration -GrantWritePermissions or "
            "'az ad sp create --id fc780465-2017-40d4-a0c5-307022471b92'.",
    7000215: "The client secret is invalid. Check CLIENT_SECRET.",
    7000222: "The client secret has expired. Create a new secret and update Key Vault.",
    53003: "Blocked by Conditional Access for this app.",
    50076: "MFA is required (claims challenge). Sign in again with MFA.",
    50079: "MFA registration is required for the user.",
    700016: "The application was not found in the tenant. Check CLIENT_ID and TENANT_ID.",
}


def explain_token_error(body: dict, status: int) -> str:
    codes = body.get("error_codes") or []
    for code in codes:
        if code in _AADSTS_HINTS:
            return f"Token exchange failed (AADSTS{code}): {_AADSTS_HINTS[code]}"
    desc = str(body.get("error_description") or body.get("error") or f"HTTP {status}")
    return "Token exchange failed: " + desc.splitlines()[0][:300]


class StaticTokenProvider:
    """Returns a fixed API token (Defender for Cloud Apps legacy API token, MDCA_AUTH=token)."""

    def __init__(self, token: str) -> None:
        if not token:
            raise AuthError("No API token configured.")
        self._token = token

    async def __call__(self) -> str:
        return self._token


class OboTokenProvider:
    def __init__(self, settings: Settings, *, scope: Optional[str] = None,
                 assertion_source: Callable[[], str] = incoming_user_token,
                 http: Any = None, clock: Callable[[], float] = time.time) -> None:
        self._s = settings
        # Default: Microsoft Graph. Defender for Endpoint: f"{settings.mde_resource}/.default"
        self.scope = scope or f"https://{settings.graph_host}/.default"
        self._assertion_source = assertion_source
        self._http = http
        self._clock = clock
        self._cache: "OrderedDict[str, tuple[str, float]]" = OrderedDict()
        self._locks: dict[str, asyncio.Lock] = {}

    async def __call__(self) -> str:
        assertion = self._assertion_source()
        cache_key = hashlib.sha256(assertion.encode()).hexdigest()
        cached = self._cached(cache_key)
        if cached:
            return cached
        lock = self._locks.setdefault(cache_key, asyncio.Lock())
        async with lock:  # one exchange per user token, even with parallel Graph calls
            cached = self._cached(cache_key)
            if cached:
                return cached
            try:
                token, expires_at = await self._exchange(assertion)
                assert_delegated(token)
            except Exception:
                self._locks.pop(cache_key, None)
                raise
            self._cache[cache_key] = (token, expires_at)
            self._cache.move_to_end(cache_key)
            while len(self._cache) > _MAX_CACHE:
                old, _ = self._cache.popitem(last=False)
                self._locks.pop(old, None)
        return token

    def _cached(self, cache_key: str) -> Optional[str]:
        hit = self._cache.get(cache_key)
        if hit and hit[1] - _REFRESH_MARGIN > self._clock():
            self._cache.move_to_end(cache_key)
            return hit[0]
        return None

    async def _exchange(self, assertion: str) -> tuple[str, float]:
        s = self._s
        url = f"https://{s.authority_host}/{s.tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "client_id": s.client_id,
            "client_secret": s.client_secret.get(),
            "assertion": assertion,
            "scope": self.scope,
            "requested_token_use": "on_behalf_of",
        }
        http = self._http or http_mod.get_http_client(s.graph_timeout_seconds)
        try:
            resp = await http.post(url, data=data, headers={"Accept": "application/json"})
        except Exception as exc:  # noqa: BLE001
            if http_mod.is_transport_error(exc):
                raise AuthError("Token exchange failed: network error reaching Entra ID. Try again.") from None
            raise
        try:
            body = resp.json()
        except ValueError:
            body = {}
        if resp.status_code != 200 or "access_token" not in body:
            message = explain_token_error(body, resp.status_code)
            log.warning("OBO exchange failed", extra={"fields": {"status": resp.status_code, "scope": self.scope,
                                                                  "error_codes": body.get("error_codes")}})
            raise AuthError(message)
        expires_in = int(body.get("expires_in") or 3600)
        return body["access_token"], self._clock() + expires_in
