"""Access to the signed-in user's token and claims for the current MCP request."""
from __future__ import annotations

import base64
import json
from typing import Any

from ..errors import AuthError


def unverified_claims(token: str) -> dict:
    """Decode JWT claims WITHOUT signature verification (FastMCP already validated the
    incoming token; this is only used to read claims and to inspect Graph tokens)."""
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception:  # noqa: BLE001
        return {}


def _access_token() -> Any:
    try:
        from fastmcp.server.dependencies import get_access_token
    except ImportError:  # pragma: no cover
        return None
    try:
        return get_access_token()
    except Exception:  # noqa: BLE001 - no request context
        return None


def incoming_user_token() -> str:
    """The user's Entra token for this request (validated by AzureJWTVerifier)."""
    access = _access_token()
    token = getattr(access, "token", None) if access is not None else None
    if not token:
        raise AuthError("No authenticated user token in the request. Reconnect the MCP connection in Copilot Studio "
                        "(authentication type OAuth 2.0) and publish the agent again.")
    return token


def tenant_from_issuer(issuer: Any) -> str:
    """Tenant GUID from an Entra issuer (https://login.microsoftonline.com/<tid>/v2.0 or
    https://sts.windows.net/<tid>/), or "" if it cannot be parsed."""
    parts = [p for p in str(issuer or "").split("/") if p]
    for part in parts[2:] if len(parts) > 2 else parts[1:]:
        if len(part) == 36 and part.count("-") == 4:
            return part.lower()
    return ""


def _claims(access: Any) -> dict:
    claims = getattr(access, "claims", None) or {}
    if not claims and getattr(access, "token", None):
        claims = unverified_claims(access.token)
    return claims


def current_user() -> dict:
    """Identity of the signed-in user, or {} outside a request.

    tid, oid and preferred_username are only emitted when the client requested the 'profile' scope.
    Fallbacks: tenant from the (validated) issuer, sub as stable per-app user identifier."""
    access = _access_token()
    if access is None:
        return {}
    claims = _claims(access)
    return {
        "oid": claims.get("oid"),
        "sub": claims.get("sub"),
        "tid": (claims.get("tid") or tenant_from_issuer(claims.get("iss")) or None),
        "upn": claims.get("preferred_username") or claims.get("upn") or claims.get("unique_name"),
        "name": claims.get("name"),
    }


def user_key() -> str:
    """Stable key for the signed-in user (rate limit, confirmation binding).

    "" outside an authenticated request (tests, local stdio). Inside a request without any user
    identifier the call is refused instead of silently sharing one key between users."""
    access = _access_token()
    if access is None:
        return ""
    user = current_user()
    ident = user.get("oid") or user.get("sub")
    if not ident:
        raise AuthError("The access token contains no user identifier (oid/sub). Add the scopes 'openid profile' "
                        "to the MCP connection in Copilot Studio and reconnect.")
    return f"{user.get('tid') or '-'}:{ident}"


def assert_delegated(graph_token: str) -> None:
    """Refuse app-only tokens: they would bypass the user's Defender roles and device groups."""
    claims = unverified_claims(graph_token)
    if claims.get("idtyp") == "app" or ("roles" in claims and not claims.get("scp")):
        raise AuthError("The exchanged token is app-only (roles, no scp). Remove application permissions from the "
                        "app registration; this server only works with delegated permissions.")
