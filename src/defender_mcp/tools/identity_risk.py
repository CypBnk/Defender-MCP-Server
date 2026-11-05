"""Identity risks across the tenant: Entra ID Protection risky users, risk detections and risky
workload identities (service principals) - the 'which users are at risk?' view that investigate_user answers per
user. Delegated Graph permissions IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All and
IdentityRiskyServicePrincipal.Read.All; roles: Security Reader or higher. Licenses: Entra ID P2 (users,
detections in full), Workload ID Premium (service principals)."""
from __future__ import annotations

from typing import Annotated, Literal, Optional

from .. import runtime
from ..errors import DefenderToolError, InputError
from ..graph.odata import clamp_int, iso_days_ago, is_upn, odata_str
from ..scopes import IDENTITY_RISK_EVENT_READ, IDENTITY_RISKY_SP_READ, IDENTITY_RISKY_USER_READ
from ..shaping import compact, pick
from ..util import gather_sections
from .common import MaxItems
from .registry import read_tool

RiskView = Literal["users", "detections", "service_principals"]
_LEVEL = {"low": 1, "medium": 2, "high": 3}
_USER_FIELDS = ("id", "userDisplayName", "userPrincipalName", "riskLevel", "riskState", "riskDetail",
                "riskLastUpdatedDateTime", "isProcessing")
_SP_FIELDS = ("id", "appId", "displayName", "servicePrincipalType", "riskLevel", "riskState", "riskDetail",
              "riskLastUpdatedDateTime", "isProcessing")
_DETECTION_FIELDS = ("detectedDateTime", "userPrincipalName", "userDisplayName", "riskEventType", "riskLevel",
                     "riskState", "riskDetail", "ipAddress", "source", "detectionTimingType", "activity", "userId")
_OPEN_STATES = ("atRisk", "confirmedCompromised")


def _rank(item: dict) -> int:
    return _LEVEL.get(str(item.get("riskLevel") or "").lower(), 0)


def _count(items: list, field: str) -> dict:
    out: dict = {}
    for i in items:
        k = str(i.get(field) or "unknown")
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


async def _risky(path: str, include_closed: bool) -> list:
    graph = runtime.graph()
    if include_closed:
        res = await graph.get(path)
        return list(res.get("value") or [])
    ok, errors = await gather_sections({s: graph.get(path, params={"$filter": f"riskState eq {odata_str(s)}"})
                                        for s in _OPEN_STATES})
    if not ok:   # both requests failed (permission, license): report the service's message
        raise DefenderToolError(next(iter(errors.values())))
    return [i for s in _OPEN_STATES for i in (ok.get(s) or {}).get("value") or []]


@read_tool(scopes=(IDENTITY_RISKY_USER_READ, IDENTITY_RISK_EVENT_READ, IDENTITY_RISKY_SP_READ),
           title="Identity risks (Entra ID Protection)")
async def get_identity_risks(
    view: Annotated[RiskView, "users: risky users (at risk or confirmed compromised); detections: risk detections "
                              "(e.g. password spray, anonymous IP, leaked credentials) in the last days; "
                              "service_principals: risky workload identities."] = "users",
    min_risk_level: Annotated[Optional[Literal["low", "medium", "high"]], "Only this risk level or higher."] = None,
    include_closed: Annotated[bool, "users / service_principals: also remediated or dismissed risks."] = False,
    days: Annotated[int, "detections: look-back window in days (1-90)."] = 7,
    user: Annotated[Optional[str], "detections: only this user (UPN)."] = None,
    max_items: MaxItems = 50,
) -> dict:
    """Entra ID Protection across the tenant, highest risk first: risky users with risk level, state and detail;
    risk detections with type, level, IP address and location, summarized by type, level and user; or risky
    service principals. Use investigate_user for one user and contain_user to respond (confirm_compromised,
    dismiss_risk, revoke_sessions, disable)."""
    limit = clamp_int(max_items, 1, 300, "max_items")
    floor = _LEVEL.get(min_risk_level or "", 0)
    if view == "detections":
        d = clamp_int(days, 1, 90, "days")
        filters = [f"detectedDateTime ge {iso_days_ago(d)}"]
        if user:
            if not is_upn(user.strip()):
                raise InputError("user must be a UPN, e.g. max@contoso.com.")
            filters.append(f"userPrincipalName eq {odata_str(user.strip())}")
        res = await runtime.graph().get("/identityProtection/riskDetections",
                                        params={"$filter": " and ".join(filters), "$top": "500"})
        rows = []
        for r in res.get("value") or []:
            item = compact(pick(r, _DETECTION_FIELDS))
            loc = r.get("location") or {}
            if isinstance(loc, dict) and (loc.get("countryOrRegion") or loc.get("city")):
                item["location"] = ", ".join(x for x in (loc.get("city"), loc.get("countryOrRegion")) if x)
            if _rank(item) >= floor:
                rows.append(item)
        rows.sort(key=lambda r: str(r.get("detectedDateTime") or ""), reverse=True)
        rows.sort(key=lambda r: -_rank(r))
        users = _count(rows, "userPrincipalName")
        return {"view": view, "days": d, "count": min(len(rows), limit), "total": len(rows),
                "truncated": len(rows) > limit or bool(res.get("@odata.nextLink")),
                "byType": _count(rows, "riskEventType"), "byLevel": _count(rows, "riskLevel"),
                "byState": _count(rows, "riskState"), "topUsers": dict(list(users.items())[:10]),
                "items": rows[:limit],
                "next_steps": "investigate_user(user) for the full picture; contain_user to respond."}
    if user:
        raise InputError("user is only valid for view='detections'.")
    if view == "service_principals":
        items = [compact(pick(i, _SP_FIELDS)) for i in await _risky("/identityProtection/riskyServicePrincipals",
                                                                     include_closed)]
    else:
        items = [compact(pick(i, _USER_FIELDS)) for i in await _risky("/identityProtection/riskyUsers", include_closed)]
    items = [i for i in items if _rank(i) >= floor]
    items.sort(key=lambda r: str(r.get("riskLastUpdatedDateTime") or ""), reverse=True)
    items.sort(key=lambda r: -_rank(r))
    out = {"view": view, "count": min(len(items), limit), "total": len(items), "truncated": len(items) > limit,
           "byLevel": _count(items, "riskLevel"), "byState": _count(items, "riskState"), "items": items[:limit]}
    out["next_steps"] = ("investigate_user(user) to assess an account; contain_user(action='confirm_compromised' / "
                         "'dismiss_risk' / 'revoke_sessions') to respond." if view == "users" else
                         "Review the app's credentials and permissions in Entra ID; hunt_cloud_app_activity("
                         "hunt='oauth_apps') shows its privilege level.")
    return out
