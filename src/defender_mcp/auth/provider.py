"""Authentication for the MCP endpoint.

Copilot Studio signs in at Entra ID itself (OAuth 2.0 "manual") and sends the Entra access token. The server only
validates it (AzureJWTVerifier inside RemoteAuthProvider) and pins tenant, delegated use and - optionally - the
calling client application. There is no /register, /authorize or consent page on this server and no token storage.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from ..settings import Settings, SettingsError
from .identity import tenant_from_issuer, unverified_claims

log = logging.getLogger("defender_mcp.auth")


def token_rejection_reason(claims: dict, settings: Settings) -> Optional[str]:
    """Extra checks on an Entra access token that already passed signature, issuer, audience and scope
    validation. Returns why the token must be rejected, or None."""
    tenant = settings.tenant_guid
    # tid is only emitted with the 'profile' scope; the issuer (already validated) always names the tenant.
    token_tenant = str(claims.get("tid") or tenant_from_issuer(claims.get("iss")) or "").lower()
    if tenant and token_tenant != tenant:
        return "token from another tenant"
    if claims.get("idtyp") == "app" or not claims.get("scp"):
        return "app-only token (no delegated scope)"
    if settings.allowed_client_app_ids:
        app = str(claims.get("azp") or claims.get("appid") or "").lower()
        if app not in settings.allowed_client_app_ids:
            return "client application not allowed"
    return None


def _pinned_verifier_class(base: type) -> type:
    class PinnedAzureJWTVerifier(base):  # type: ignore[misc, valid-type]
        """AzureJWTVerifier plus tenant pinning, delegated-only and client-app allow list."""

        def __init__(self, *, settings: Settings, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            self._mcp_settings = settings

        async def verify_token(self, token: str) -> Any:
            result = await super().verify_token(token)
            if result is None:
                return None
            claims = getattr(result, "claims", None) or unverified_claims(token)
            reason = token_rejection_reason(claims, self._mcp_settings)
            if reason:
                log.warning("Rejected access token: %s", reason, extra={"fields": {
                    "reason": reason, "tid": claims.get("tid"), "azp": claims.get("azp") or claims.get("appid"),
                    "oid": claims.get("oid")}})
                return None
            return result

    return PinnedAzureJWTVerifier


def build_entra_auth(settings: Settings) -> Any:
    from fastmcp.server.auth import RemoteAuthProvider
    from fastmcp.server.auth.providers.azure import AzureJWTVerifier

    if not settings.tenant_guid:
        log.warning("TENANT_ID is not a GUID: the tid claim cannot be pinned (issuer validation still applies).")
    if not settings.allowed_client_app_ids:
        log.warning("ALLOWED_CLIENT_APP_IDS is empty: tokens for this API from any client application of the "
                    "tenant are accepted. Set it to the Copilot Studio client app ID.")
    try:
        verifier = _pinned_verifier_class(AzureJWTVerifier)(
            settings=settings,
            client_id=settings.client_id,
            tenant_id=settings.tenant_id,
            # Scope name as in "Expose an API"; Entra puts the short name into the scp claim.
            required_scopes=[settings.required_scope],
        )
    except TypeError as exc:
        raise SettingsError(f"AzureJWTVerifier rejected a parameter ({exc}). Check the installed fastmcp version "
                            "against requirements.txt.") from exc
    issuer = f"https://{settings.authority_host}/{settings.tenant_id}/v2.0"
    try:
        from pydantic import AnyHttpUrl

        servers: list[Any] = [AnyHttpUrl(issuer)]
    except ImportError:  # pragma: no cover - pydantic ships with fastmcp
        servers = [issuer]
    return RemoteAuthProvider(token_verifier=verifier, authorization_servers=servers, base_url=settings.base_url)


def build_auth(settings: Settings) -> Any:
    return build_entra_auth(settings)
