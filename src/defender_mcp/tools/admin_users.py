"""Containment of a compromised user account: revoke sessions, disable / enable the Entra
account, confirm compromised / dismiss risk in Entra ID Protection. Also the on-premises Active Directory
account through Defender for Identity (Graph identityAccounts/invokeAction: disable, enable, force password reset).
Always two-step."""
from __future__ import annotations

import re
from typing import Annotated, Literal, Optional

from .. import runtime
from ..confirm import two_step
from ..errors import GraphError, InputError, NotFoundError
from ..resolve import resolve_user
from ..graph.odata import key, odata_str
from ..scopes import (IDENTITY_ACCOUNTS_READ, IDENTITY_ACTIONS_READWRITE, IDENTITY_RISKY_USER_READ,
                      IDENTITY_RISKY_USER_READWRITE, USER_ENABLE_DISABLE, USER_READ_ALL, USER_REVOKE_SESSIONS)
from ..shaping import compact, pick
from .common import ConfirmationToken
from .registry import admin_tool

UserAction = Literal["revoke_sessions", "disable_account", "enable_account", "confirm_compromised", "dismiss_risk",
                     "disable_ad_account", "enable_ad_account", "force_password_reset"]
_AD_ACTIONS = {"disable_ad_account": "disable", "enable_ad_account": "enable", "force_password_reset": "forcePasswordReset"}
_SID = re.compile(r"^S-1-5-21-\d+-\d+-\d+-\d+$", re.IGNORECASE)
_EFFECTS = {
    "revoke_sessions": "All refresh tokens and browser sessions of the user become invalid (sign-out everywhere, "
                       "takes a few minutes). Access tokens stay valid until they expire (usually up to 1 hour).",
    "disable_account": "The account can no longer sign in (accountEnabled = false). Existing sessions continue "
                       "until they are revoked: combine with revoke_sessions.",
    "enable_account": "The account can sign in again (accountEnabled = true).",
    "confirm_compromised": "Entra ID Protection sets the user risk to high (confirmed compromised); risk-based "
                           "Conditional Access policies then apply (e.g. block or secure password change).",
    "dismiss_risk": "Entra ID Protection dismisses the user risk (risk state 'dismissed'). Only after the account "
                    "has been secured or the risk was a false positive.",
    "disable_ad_account": "Defender for Identity disables the on-premises Active Directory account on a domain "
                          "controller: it can no longer authenticate in AD (and, once synchronized, in Entra ID).",
    "enable_ad_account": "Defender for Identity re-enables the on-premises Active Directory account.",
    "force_password_reset": "Defender for Identity sets 'User must change password at next logon' on the on-premises "
                            "Active Directory account.",
}
_USER_FIELDS = ("id", "displayName", "userPrincipalName", "accountEnabled", "userType", "onPremisesSyncEnabled",
                "signInSessionsValidFromDateTime", "lastPasswordChangeDateTime")
_HINT_403 = ("Missing permission or role. revoke_sessions / disable_account need an Entra role that may manage the "
             "user (e.g. User Administrator; Privileged Authentication Administrator for admin accounts); "
             "confirm_compromised / dismiss_risk need at least Security Administrator (Entra ID P2); the AD actions "
             "need Security Administrator and Defender for Identity with a sensor that may perform remediation.")


async def _current_risk(object_id: str) -> dict:
    try:
        res = await runtime.graph().get(f"/identityProtection/riskyUsers/{object_id}")
    except GraphError as exc:
        if exc.status == 404:
            return {"riskState": "none"}
        return {"error": str(exc)[:300]}
    return compact(pick(res, ("riskLevel", "riskState", "riskDetail", "riskLastUpdatedDateTime")))


async def _ad_identity(sid: str) -> tuple[dict, dict]:
    """Defender for Identity identity and its Active Directory account for an on-premises SID."""
    res = await runtime.graph().get("/security/identities/identityAccounts",
                                    params={"$filter": f"onPremisesSecurityIdentifier eq {odata_str(sid)}"})
    for identity in res.get("value") or []:
        for account in identity.get("accounts") or []:
            if str(account.get("provider") or "").lower() == "activedirectory" and account.get("identifier"):
                return identity, account
    raise NotFoundError(f"Defender for Identity knows no Active Directory account with SID {sid} (no sensor coverage "
                        "of the domain, or not an AD account).")


async def _ad_action(user: str, action: str, token: Optional[str]) -> dict:
    value = str(user or "").strip()
    entra: dict = {}
    if _SID.match(value):
        sid = value.upper()
    else:
        entra = await resolve_user(value)
        sid = str(entra.get("onPremisesSecurityIdentifier") or "")
        if not sid:
            raise InputError("This is a cloud-only account without an on-premises AD account: use disable_account, "
                             "enable_account or revoke_sessions instead.")
    identity, account = await _ad_identity(sid)
    enabled = identity.get("isEnabled")
    if action == "disable_ad_account" and enabled is False:
        raise InputError("The Active Directory account is already disabled.")
    if action == "enable_ad_account" and enabled is True:
        raise InputError("The Active Directory account is already enabled.")
    if action in ("disable_ad_account", "force_password_reset"):
        me = await runtime.graph().get("/me", params={"$select": "id,onPremisesSecurityIdentifier"})
        if str(me.get("onPremisesSecurityIdentifier") or "").upper() == sid.upper():
            raise InputError("You cannot run this action on your own account with this tool.")
    identity_id = key(str(identity.get("id") or ""), "identity id")
    view = compact({"displayName": identity.get("displayName"), "domain": identity.get("domain"),
                    "onPremisesSecurityIdentifier": identity.get("onPremisesSecurityIdentifier"), "isEnabled": enabled,
                    "entraUser": entra.get("userPrincipalName"), "adAccountId": account.get("identifier")})

    async def preview() -> dict:
        warnings = ["The action runs on a domain controller through the Defender for Identity sensor; sessions and "
                    "Kerberos tickets that already exist stay valid until they expire."]
        if action == "disable_ad_account" and entra:
            warnings.append("Also run contain_user(action='revoke_sessions') to end the Entra ID sessions.")
        return {"identity": view, "effect": _EFFECTS[action], "warnings": warnings}

    async def execute() -> dict:
        try:
            res = await runtime.graph().post(f"/security/identities/identityAccounts/{identity_id}/invokeAction",
                                             json_body={"accountId": account["identifier"], "action": _AD_ACTIONS[action],
                                                        "identityProvider": "activeDirectory"})
        except GraphError as exc:
            if exc.status == 403:
                raise GraphError(403, exc.code, exc.graph_message, request_id=exc.request_id, hint=_HINT_403) from None
            raise
        result = (res or {}).get("value") if isinstance(res, dict) else None
        return {"identity": view, "message": _EFFECTS[action],
                "correlationId": (result or {}).get("correlationId") if isinstance(result, dict) else None,
                "next_steps": "The Action center in the Defender portal shows the result; investigate_user for the "
                              "account's activity."}

    return await two_step(action=f"user.{action}", target=sid, params={"action": action}, token=token,
                          preview=preview, execute=execute)


@admin_tool(scopes=(USER_READ_ALL, USER_REVOKE_SESSIONS, USER_ENABLE_DISABLE, IDENTITY_RISKY_USER_READWRITE,
                    IDENTITY_RISKY_USER_READ, IDENTITY_ACCOUNTS_READ, IDENTITY_ACTIONS_READWRITE),
            title="Contain user (sessions, sign-in, risk, AD account)", destructive=True)
async def contain_user(
    user: Annotated[str, "UPN or Entra object ID of the user; for the AD actions also the on-premises SID "
                         "(S-1-5-21-...)."],
    action: Annotated[UserAction, "revoke_sessions: sign out everywhere; disable_account / enable_account: block or "
                                  "allow Entra sign-in (cloud accounts); confirm_compromised: set user risk to high in "
                                  "Entra ID Protection; dismiss_risk: dismiss the user risk; disable_ad_account / "
                                  "enable_ad_account / force_password_reset: on-premises Active Directory account "
                                  "through Defender for Identity."],
    confirmation_token: ConfirmationToken = None,
) -> dict:
    """Respond to a compromised Entra ID account: revoke all sessions and refresh tokens (sign-out everywhere),
    disable or re-enable the account, confirm the user as compromised in Entra ID Protection (user risk high,
    so risk-based Conditional Access applies) or dismiss the user risk; for on-premises Active Directory
    accounts (also synchronized ones) disable, re-enable or force a password reset through Defender for
    Identity. Two-step: the first call shows the account, its current state and the effect; the second call with
    confirmation_token executes."""
    if action not in _EFFECTS:
        raise InputError(f"action must be one of: {', '.join(_EFFECTS)}.")
    if action in _AD_ACTIONS:
        return await _ad_action(user, action, confirmation_token)
    u = await resolve_user(user)
    uid = u["id"]
    graph = runtime.graph()
    if action in ("disable_account", "enable_account"):
        wanted = action == "enable_account"
        if u.get("onPremisesSyncEnabled"):
            raise InputError("The account is synchronized from on-premises Active Directory: use "
                             f"action='{'enable' if wanted else 'disable'}_ad_account' (Defender for Identity). "
                             "revoke_sessions and confirm_compromised work for synchronized accounts.")
        if u.get("accountEnabled") is wanted:
            raise InputError(f"The account is already {'enabled' if wanted else 'disabled'}.")
        if not wanted:
            me = await graph.get("/me", params={"$select": "id"})
            if me.get("id") == uid:
                raise InputError("You cannot disable your own account with this tool.")

    async def preview() -> dict:
        out: dict = {"user": compact(pick(u, _USER_FIELDS)), "effect": _EFFECTS[action]}
        if action in ("confirm_compromised", "dismiss_risk"):
            out["currentRisk"] = await _current_risk(uid)
        warnings = []
        if u.get("userType") == "Guest" and action == "revoke_sessions":
            warnings.append("Guest account: sessions in the home tenant are not revoked.")
        if action == "dismiss_risk":
            warnings.append("Dismiss the risk only after the account is secured (password reset, sessions revoked) "
                            "or the detection was a false positive.")
        if warnings:
            out["warnings"] = warnings
        return out

    async def execute() -> dict:
        try:
            if action == "revoke_sessions":
                await graph.post(f"/users/{uid}/revokeSignInSessions")
            elif action in ("disable_account", "enable_account"):
                await graph.patch(f"/users/{uid}", json_body={"accountEnabled": action == "enable_account"})
            elif action == "confirm_compromised":
                await graph.post("/identityProtection/riskyUsers/confirmCompromised", json_body={"userIds": [uid]})
            else:
                await graph.post("/identityProtection/riskyUsers/dismiss", json_body={"userIds": [uid]})
        except GraphError as exc:
            if exc.status == 403:
                raise GraphError(403, exc.code, exc.graph_message, request_id=exc.request_id, hint=_HINT_403) from None
            raise
        follow = {
            "revoke_sessions": "Also reset the password / MFA if credentials are compromised; check sign-ins with "
                               "investigate_user.",
            "disable_account": "Run contain_user(action='revoke_sessions') to end active sessions.",
            "enable_account": "Check investigate_user for new suspicious sign-ins.",
            "confirm_compromised": "Revoke sessions and reset the password; dismiss_risk afterwards if needed.",
            "dismiss_risk": "Keep monitoring the account with investigate_user.",
        }[action]
        return {"user": compact(pick(u, ("id", "displayName", "userPrincipalName"))), "message": _EFFECTS[action],
                "next_steps": follow}

    return await two_step(action=f"user.{action}", target=uid, params={"action": action}, token=confirmation_token,
                          preview=preview, execute=execute)
