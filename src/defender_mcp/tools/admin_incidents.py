"""Triage of incidents and alerts plus comments.
Updates need the two-step confirmation; comments are added immediately (append-only)."""
from __future__ import annotations

import re
from typing import Annotated, Literal, Optional

from .. import runtime
from ..auth.identity import current_user
from ..confirm import two_step
from ..errors import InputError
from ..graph.odata import is_upn, key
from ..scopes import SECURITY_ALERT_READWRITE, SECURITY_INCIDENT_READWRITE
from ..shaping import compact, pick, truncate
from .common import AlertId, ConfirmationToken, IncidentId, Severity
from .incidents import ALERT_FIELDS, INCIDENT_FIELDS, Classification, IncidentDetermination, valid_incident_id
from .registry import admin_tool

AlertDetermination = Literal["multiStagedAttack", "maliciousUserActivity", "compromisedUser", "malware", "phishing",
                             "unwantedSoftware", "apt", "securityTesting", "lineOfBusinessApplication",
                             "confirmedUserActivity", "securityPersonnel", "clean", "insufficientData", "other", "unknown"]
# Determinations that fit a classification (as offered in the Defender portal).
_INCIDENT_DETERMINATIONS = {
    "truePositive": {"multiStagedAttack", "maliciousUserActivity", "compromisedAccount", "malware", "phishing",
                     "unwantedSoftware", "apt", "other"},
    "informationalExpectedActivity": {"securityTesting", "lineOfBusinessApplication", "confirmedActivity",
                                      "securityPersonnel", "other"},
    "falsePositive": {"notMalicious", "notEnoughDataToValidate", "other"},
}
_ALERT_DETERMINATIONS = {
    "truePositive": {"multiStagedAttack", "maliciousUserActivity", "compromisedUser", "malware", "phishing",
                     "unwantedSoftware", "apt", "other"},
    "informationalExpectedActivity": {"securityTesting", "lineOfBusinessApplication", "confirmedUserActivity",
                                      "securityPersonnel", "other"},
    "falsePositive": {"clean", "insufficientData", "other"},
}
_TAG = re.compile(r"^[^\x00-\x1f]{1,100}$")
AssignTo = Annotated[Optional[str], "New owner: UPN, or 'me' for the signed-in user."]


def _owner(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = value.strip()
    if v.lower() == "me":
        upn = current_user().get("upn")
        if not upn:
            raise InputError("The sign-in token has no UPN; pass the owner's UPN instead of 'me'.")
        return upn
    if not is_upn(v):
        raise InputError("assign_to must be a UPN or 'me'.")
    return v


def _check_determination(classification: Optional[str], determination: Optional[str], allowed: dict,
                         current_classification: Optional[str]) -> None:
    if not determination or determination == "unknown":
        return
    cls = classification or current_classification
    if cls in allowed and determination not in allowed[cls]:
        raise InputError(f"determination '{determination}' does not fit classification '{cls}'. "
                         f"Allowed: {', '.join(sorted(allowed[cls]))}.")


def _changes(current: dict, body: dict) -> dict:
    return {k: {"from": current.get(k), "to": v} for k, v in body.items() if current.get(k) != v}


@admin_tool(scopes=(SECURITY_INCIDENT_READWRITE,), title="Update incident", destructive=False, idempotent=True)
async def update_incident(
    incident_id: IncidentId,
    status: Annotated[Optional[Literal["active", "resolved"]], "New status (resolved also resolves its alerts)."] = None,
    classification: Annotated[Optional[Classification], "Classification."] = None,
    determination: Annotated[Optional[IncidentDetermination], "Determination; must fit the classification."] = None,
    assign_to: AssignTo = None,
    severity: Annotated[Optional[Severity], "New severity."] = None,
    add_tags: Annotated[Optional[list[str]], "Custom tags to add (existing tags are kept)."] = None,
    resolving_comment: Annotated[Optional[str], "Comment explaining the resolution and classification."] = None,
    confirmation_token: ConfirmationToken = None,
) -> dict:
    """Triage one Defender XDR incident: status, classification, determination, owner, severity, tags and
    resolving comment. Two-step: the first call shows the current and new values, the second call with
    confirmation_token applies them."""
    iid = valid_incident_id(incident_id)
    graph = runtime.graph()
    current = await graph.get(f"/security/incidents/{iid}")
    body: dict = {}
    if status:
        body["status"] = status
    if classification:
        body["classification"] = classification
    if determination:
        _check_determination(classification, determination, _INCIDENT_DETERMINATIONS, current.get("classification"))
        body["determination"] = determination
    owner = _owner(assign_to)
    if owner:
        body["assignedTo"] = owner
    if severity:
        body["severity"] = severity
    if add_tags:
        bad = [t for t in add_tags if not isinstance(t, str) or not _TAG.match(t)]
        if bad:
            raise InputError("Tags must be 1-100 characters without control characters.")
        tags = list(dict.fromkeys(list(current.get("customTags") or []) + [t.strip() for t in add_tags]))
        body["customTags"] = tags
    if resolving_comment:
        body["resolvingComment"] = truncate(resolving_comment.strip(), 2000)
    if not body:
        raise InputError("Nothing to change: pass at least one of status, classification, determination, assign_to, "
                         "severity, add_tags, resolving_comment.")
    changes = _changes(current, body)

    async def preview() -> dict:
        warnings = []
        if body.get("status") == "resolved":
            warnings.append("Resolving the incident also resolves all of its active alerts.")
            if not (body.get("classification") or current.get("classification") not in (None, "unknown")):
                warnings.append("No classification set; consider classifying (truePositive, falsePositive, "
                                "informationalExpectedActivity) before resolving.")
        out = {"incident": compact(pick(current, INCIDENT_FIELDS)), "changes": changes or "no effective change"}
        if warnings:
            out["warnings"] = warnings
        return out

    async def execute() -> dict:
        updated = await graph.patch(f"/security/incidents/{iid}", json_body=body)
        return {"incident": compact(pick(updated or {}, INCIDENT_FIELDS)) or {"id": iid}, "changed": list(body)}

    return await two_step(action="incident.update", target=iid, params=body, token=confirmation_token,
                          preview=preview, execute=execute)


@admin_tool(scopes=(SECURITY_ALERT_READWRITE,), title="Update alert", destructive=False, idempotent=True)
async def update_alert(
    alert_id: AlertId,
    status: Annotated[Optional[Literal["new", "inProgress", "resolved"]], "New status."] = None,
    classification: Annotated[Optional[Classification], "Classification."] = None,
    determination: Annotated[Optional[AlertDetermination], "Determination; must fit the classification."] = None,
    assign_to: AssignTo = None,
    confirmation_token: ConfirmationToken = None,
) -> dict:
    """Triage one Defender XDR alert: status, classification, determination and owner. Two-step: the first call
    shows the current and new values, the second call with confirmation_token applies them."""
    aid = key(alert_id, "alert_id")
    graph = runtime.graph()
    current = await graph.get(f"/security/alerts_v2/{aid}")
    body: dict = {}
    if status:
        body["status"] = status
    if classification:
        body["classification"] = classification
    if determination:
        _check_determination(classification, determination, _ALERT_DETERMINATIONS, current.get("classification"))
        body["determination"] = determination
    owner = _owner(assign_to)
    if owner:
        body["assignedTo"] = owner
    if not body:
        raise InputError("Nothing to change: pass at least one of status, classification, determination, assign_to.")
    changes = _changes(current, body)

    async def preview() -> dict:
        return {"alert": compact(pick(current, ALERT_FIELDS)), "changes": changes or "no effective change"}

    async def execute() -> dict:
        updated = await graph.patch(f"/security/alerts_v2/{aid}", json_body=body)
        return {"alert": compact(pick(updated or {}, ALERT_FIELDS)) or {"id": aid}, "changed": list(body)}

    return await two_step(action="alert.update", target=aid, params=body, token=confirmation_token,
                          preview=preview, execute=execute)


@admin_tool(scopes=(SECURITY_INCIDENT_READWRITE, SECURITY_ALERT_READWRITE), title="Add comment to incident or alert",
            destructive=False, idempotent=False, immediate=lambda _args: True)
async def add_comment(
    target: Annotated[Literal["incident", "alert"], "Comment on an incident or on an alert."],
    target_id: Annotated[str, "Incident ID (number) or alert ID."],
    comment: Annotated[str, "Comment text (max. 2000 characters). It is stored with the signed-in user's name."],
) -> dict:
    """Add a comment to a Defender XDR incident or alert (investigation notes, hand-over). Runs immediately
    without confirmation because comments are append-only; it cannot be deleted through this server."""
    text = (comment or "").strip()
    if not text:
        raise InputError("comment must not be empty.")
    if len(text) > 2000:
        raise InputError("comment is longer than 2000 characters.")
    body = {"@odata.type": "microsoft.graph.security.alertComment", "comment": text}
    if target == "incident":
        path = f"/security/incidents/{valid_incident_id(target_id)}/comments"
    else:
        path = f"/security/alerts_v2/{key(target_id, 'target_id')}/comments"
    res = await runtime.graph().post(path, json_body=body)
    comments = (res or {}).get("value") or []
    return {"status": "done", "action": f"{target}.comment", "target": target_id, "commentCount": len(comments) or None}
