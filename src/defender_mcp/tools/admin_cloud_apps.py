"""sanction_cloud_apps: tags discovered cloud apps as Sanctioned or Unsanctioned in Defender for Cloud Apps.

There is no documented API for this: the Graph Cloud Discovery API is read-only and the documented Defender for Cloud
Apps API has no call for app tags. The tool uses the endpoint the Defender portal calls,
POST /cas/api/v1/discovery/discovery_app/{appId}/set_sanctioned/ with {"sanction": true|false}, known from a public
community script (browser traffic), not from Microsoft documentation. Microsoft can change or block it at any time.

Authentication (MDCA_AUTH): 'obo' = token for the signed-in user (resource 'Microsoft Cloud App Security', delegated
Discovery.manage; the user's Defender for Cloud Apps permissions apply) or 'token' = legacy Defender for Cloud Apps API
token from Key Vault (acts with the token owner's permissions). Apps are looked up and the tag is read back through
Microsoft Graph (Cloud Discovery, last 90 days)."""
from __future__ import annotations

import asyncio
import re
from typing import Annotated, Any, Literal, Optional

from .. import runtime
from ..confirm import two_step
from ..errors import DefenderToolError, GraphError, InputError, NotFoundError
from ..scopes import CLOUDAPP_DISCOVERY_READ, MDCA_DISCOVERY_MANAGE
from .cloud_apps import apps_path, brief, has_tag, resolve_stream, tags_of
from .common import ConfirmationToken, one_of
from .registry import admin_tool

_APP_ID = re.compile(r"^\d{1,9}$")
ENDPOINT = "/cas/api/v1/discovery/discovery_app/{app_id}/set_sanctioned/"
_LOOKUP_PERIOD = "P90D"
_MAX_APPS = 10
Status = Literal["Sanctioned", "Unsanctioned"]
_EFFECT = {
    "Unsanctioned": "Defender for Cloud Apps marks the app as prohibited. If the Defender for Endpoint integration is set "
                    "to block unsanctioned apps, it creates block indicators for the app's domains: users on onboarded "
                    "devices (network protection on) can no longer open the app. Without that integration the tag "
                    "marks the app for filters, policies and block scripts. A Cloud Discovery policy can later "
                    "overwrite the tag (the last action wins).",
    "Sanctioned": "Defender for Cloud Apps marks the app as approved. An Unsanctioned tag is replaced and the blocking "
                  "Defender for Cloud Apps applied because of it ends.",
}
UNDOCUMENTED = ("Undocumented Defender for Cloud Apps API (the call the Defender portal makes): not supported by "
                "Microsoft, may change without notice. If it fails, tag the app in the portal: Cloud apps > Cloud "
                "discovery > Discovered apps.")
_MICROSOFT = ("microsoft", "office 365", "azure", "outlook", "onedrive", "sharepoint", "teams")


def app_ids_arg(app_ids: Any) -> list[str]:
    values = [app_ids] if isinstance(app_ids, (str, int)) else list(app_ids or [])
    out: list[str] = []
    for raw in values:
        value = str(raw).strip()
        if not _APP_ID.match(value):
            raise InputError(f"Invalid app ID {value[:40]!r}: use the numeric app ID from get_cloud_app_discovery.")
        if value not in out:
            out.append(value)
    if not out:
        raise InputError("app_ids is required (numeric app IDs from get_cloud_app_discovery).")
    if len(out) > _MAX_APPS:
        raise InputError(f"At most {_MAX_APPS} apps per call.")
    return out


async def _get_app(stream_id: str, app_id: str) -> Optional[dict]:
    try:
        res = await runtime.graph().get(f"{apps_path(stream_id, _LOOKUP_PERIOD)}/{app_id}", version="beta")
    except GraphError as exc:
        if exc.status in (400, 404):
            return None
        raise
    return res if isinstance(res, dict) and res.get("id") is not None else None


async def lookup_apps(stream_id: str, app_ids: list[str]) -> dict[str, Optional[dict]]:
    found = await asyncio.gather(*(_get_app(stream_id, i) for i in app_ids))
    return dict(zip(app_ids, found, strict=True))


def _auth_note() -> str:
    if runtime.settings().mdca_auth == "token":
        return ("Runs with the configured Defender for Cloud Apps API token (permissions of its owner), not with your "
                "account; the MCP audit log records you as the requester.")
    return "Runs with your account (delegated; your Defender for Cloud Apps permissions apply)."


@admin_tool(scopes=(CLOUDAPP_DISCOVERY_READ, MDCA_DISCOVERY_MANAGE), title="Sanction / unsanction cloud apps",
            destructive=True, idempotent=True)
async def sanction_cloud_apps(
    app_ids: Annotated[list[str], "Numeric app IDs from get_cloud_app_discovery (1-10)."],
    status: Annotated[Status, "Sanctioned = approved for use; Unsanctioned = prohibited (blocked on devices if the "
                              "Defender for Endpoint integration blocks unsanctioned apps)."],
    stream_id: Annotated[Optional[str], "Cloud Discovery stream used to look up the apps (default as in "
                                        "get_cloud_app_discovery)."] = None,
    confirmation_token: ConfirmationToken = None,
) -> dict:
    """Tags discovered cloud apps as Sanctioned or Unsanctioned in Defender for Cloud Apps (Cloud discovery >
    Discovered apps). Uses an UNDOCUMENTED Defender for Cloud Apps endpoint (the call of the Defender portal); Microsoft
    can change it without notice. Two-step: the preview shows each app with its current tag, risk score, users and the
    effect; the second call sets the tag and reads it back. Unsanctioned apps are blocked on onboarded devices when the
    Defender for Endpoint integration blocks unsanctioned apps. Only apps found in Cloud Discovery (90 days) can be
    tagged; Monitored, custom tags and removing a tag stay in the portal."""
    ids = app_ids_arg(app_ids)
    wanted = one_of(status, ("Sanctioned", "Unsanctioned"), "status")
    client = runtime.mdca()                        # configuration error before any lookup
    sid, stream, _others = await resolve_stream(stream_id)
    apps = await lookup_apps(sid, ids)
    missing = [i for i, app in apps.items() if app is None]
    if missing:
        raise NotFoundError(f"App ID(s) {', '.join(missing)} not found in Cloud Discovery (stream "
                            f"{stream.get('displayName') or sid}, last 90 days). Check the IDs with "
                            "get_cloud_app_discovery; apps that were not discovered can be tagged in the portal "
                            "(Cloud app catalog).")
    pending = [i for i in ids if not has_tag(apps[i], wanted)]
    if not pending:
        return {"status": "no_change", "message": f"All apps are already tagged {wanted}.",
                "apps": [brief(apps[i]) for i in ids]}

    async def preview() -> dict:
        rows, warnings = [], [UNDOCUMENTED, _auth_note()]
        for i in ids:
            app = apps[i]
            current = ", ".join(tags_of(app)) or "untagged"
            rows.append({**brief(app), "change": f"{current} -> {wanted}" if i in pending else f"none (already {wanted})"})
            name = str(app.get("displayName") or "")
            if wanted == "Unsanctioned" and name.lower().startswith(_MICROSOFT):
                warnings.append(f"{name} is a Microsoft service: unsanctioning it can disrupt Microsoft 365 or Azure.")
        return {"status": wanted, "apps": rows, "effect": _EFFECT[wanted], "stream": stream, "warnings": warnings}

    async def execute() -> dict:
        results = []
        for i in pending:                          # sequential: the API allows 30 requests per minute per tenant
            row: dict = {"id": i, "name": apps[i].get("displayName"), "before": tags_of(apps[i]) or ["untagged"]}
            try:
                await client.post(ENDPOINT.format(app_id=i), json_body={"sanction": wanted == "Sanctioned"})
                row["accepted"] = True
            except DefenderToolError as exc:
                row.update(accepted=False, error=str(exc))
            results.append(row)
        # Read every app back (also rejected ones: a timeout or 5xx may still have been applied).
        verify_error = None
        after: dict = {}
        try:
            after = await lookup_apps(sid, pending)
        except DefenderToolError as exc:
            verify_error = str(exc)
        for r in results:
            now = after.get(r["id"])
            r["tagsNow"] = (tags_of(now) or ["untagged"]) if now else None
            r["verified"] = bool(now) and has_tag(now, wanted)
            if r["verified"]:
                r["state"] = "done"
            elif r["accepted"]:
                r["state"] = "pending"          # accepted, Graph does not show the tag yet
            elif now is not None:
                r["state"] = "unchanged"        # rejected, read-back shows the old tag
            else:
                r["state"] = "unknown"          # rejected and not readable: check in the portal
        states = {r["state"] for r in results}
        if states == {"done"}:
            outcome = "verified"
        elif states <= {"done", "pending"}:
            outcome = "accepted"
        elif states <= {"unchanged", "unknown"}:
            outcome = "failed"
        else:
            outcome = "partial"
        out: dict = {"outcome": outcome, "requested": wanted, "results": results, "api": UNDOCUMENTED}
        notes = []
        pending_ids = [r["id"] for r in results if r["state"] == "pending"]
        if pending_ids:
            notes.append(f"Accepted, but Microsoft Graph does not show the new tag yet for {', '.join(pending_ids)} "
                         "(Cloud Discovery data can lag a few minutes). Check later with "
                         "get_cloud_app_discovery(view='app', app_id=...) or in the portal.")
        applied_anyway = [r["id"] for r in results if r["state"] == "done" and not r["accepted"]]
        if applied_anyway:
            notes.append(f"The API reported an error for {', '.join(applied_anyway)}, but the new tag is set.")
        unknown_ids = [r["id"] for r in results if r["state"] == "unknown"]
        if unknown_ids:
            notes.append(f"State of {', '.join(unknown_ids)} could not be read back: check the portal before trying "
                         "again.")
        if notes:
            out["notes"] = notes
        if verify_error:
            out["verifyError"] = verify_error
        if outcome in ("failed", "partial"):
            prefix = "No app was changed. " if states == {"unchanged"} else ""
            out["hint"] = (prefix + "Check MDCA_API_URL, the role of the user (or token owner) and, with MDCA_AUTH=obo, "
                           "whether the API accepts Entra tokens for this endpoint; otherwise tag the apps in the "
                           "portal.")
        return out

    return await two_step(action="cloudapp.sanction", target=",".join(ids), params={"status": wanted, "stream": sid},
                          token=confirmation_token, preview=preview, execute=execute)
