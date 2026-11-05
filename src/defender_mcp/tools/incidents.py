"""Defender XDR incidents and alerts. Server-side filters; $orderby is not supported by these APIs (newest first anyway)."""
from __future__ import annotations

import re
import statistics
from datetime import datetime
from typing import Annotated, Literal, Optional

from .. import runtime
from ..errors import InputError
from ..graph.odata import clamp_int, iso_hours_ago, key, odata_str
from ..graph.paging import collect, cursor_extra, get_paged
from ..scopes import SECURITY_ALERT_READ, SECURITY_INCIDENT_READ
from ..shaping import UNTRUSTED_NOTE, compact, evidence_item, pick, summarize_entities, truncate
from .common import AlertId, Cursor, IncidentId, MaxItems, Severity
from .registry import read_tool

IncidentStatus = Literal["active", "inProgress", "resolved", "redirected", "awaitingAction"]
AlertStatus = Literal["new", "inProgress", "resolved"]
Classification = Literal["unknown", "falsePositive", "truePositive", "informationalExpectedActivity"]
IncidentDetermination = Literal["multiStagedAttack", "maliciousUserActivity", "compromisedAccount", "malware",
                                "phishing", "unwantedSoftware", "apt", "securityTesting", "lineOfBusinessApplication",
                                "confirmedActivity", "securityPersonnel", "notMalicious", "notEnoughDataToValidate",
                                "other", "unknown"]
ServiceSource = Literal["microsoftDefenderForEndpoint", "microsoftDefenderForIdentity", "microsoftDefenderForOffice365",
                        "microsoftDefenderForCloudApps", "microsoft365Defender", "azureAdIdentityProtection",
                        "microsoftAppGovernance", "dataLossPrevention", "microsoftDefenderForCloud",
                        "microsoftSentinel", "microsoftInsiderRiskManagement"]
SinceHours = Annotated[Optional[int], "Only items created in the last N hours (1-4320)."]
AssignedTo = Annotated[Optional[str], "Only items assigned to this owner (as shown in the portal, usually a UPN); "
                                      "'me' = the signed-in user."]
PAGE = 50  # page size of the security incidents/alerts APIs

_INCIDENT_ID = re.compile(r"^\d{1,20}$")
INCIDENT_FIELDS = ("id", "displayName", "status", "severity", "classification", "determination", "assignedTo",
                   "createdDateTime", "lastUpdateDateTime", "priorityScore", "customTags", "systemTags",
                   "redirectIncidentId", "incidentWebUrl")
ALERT_FIELDS = ("id", "title", "severity", "status", "classification", "determination", "serviceSource",
                "detectionSource", "category", "createdDateTime", "lastUpdateDateTime", "firstActivityDateTime",
                "lastActivityDateTime", "incidentId", "assignedTo", "mitreTechniques", "threatDisplayName",
                "threatFamilyName", "actorDisplayName", "alertWebUrl")


def valid_incident_id(value: object) -> str:
    v = str(value or "").strip()
    if not _INCIDENT_ID.match(v):
        raise InputError(f"incident_id must be the numeric incident ID, got {v[:40]!r}.")
    return v


async def owner(value: Optional[str]) -> Optional[str]:
    """'me' -> UPN of the signed-in user (owners are stored as UPN)."""
    if value and value.strip().lower() == "me":
        me = await runtime.graph().get("/me", params={"$select": "userPrincipalName"})
        upn = me.get("userPrincipalName")
        if not upn:
            raise InputError("The UPN of the signed-in user could not be read; pass the owner's UPN instead of 'me'.")
        return upn
    return value


def _filters(*, status: Optional[str], severity: Optional[str], since_hours: Optional[int],
             assigned_to: Optional[str], classification: Optional[str],
             service_source: Optional[str] = None, determination: Optional[str] = None) -> Optional[str]:
    filters = []
    if status:
        filters.append(f"status eq {odata_str(status)}")
    if severity:
        filters.append(f"severity eq {odata_str(severity)}")
    if since_hours is not None:
        filters.append(f"createdDateTime ge {iso_hours_ago(clamp_int(since_hours, 1, 4320, 'since_hours'))}")
    if assigned_to:
        filters.append(f"assignedTo eq {odata_str(assigned_to, 'assigned_to')}")
    if classification:
        filters.append(f"classification eq {odata_str(classification)}")
    if service_source:
        filters.append(f"serviceSource eq {odata_str(service_source)}")
    if determination:
        filters.append(f"determination eq {odata_str(determination)}")
    return " and ".join(filters) or None


def _newest_first(res: dict) -> dict:
    """Graph cannot sort incidents or alerts ($orderby is not supported), so each page is sorted here."""
    items = res.get("items")
    if isinstance(items, list):
        items.sort(key=lambda r: str(r.get("createdDateTime") or ""), reverse=True)
    return res


def _incident_filter(unassigned_only: bool, tag: Optional[str], name: Optional[str] = None):
    """Client-side filters (Graph cannot filter incidents by tag, name or missing owner); stored in the cursor."""
    wanted = tag.lower() if tag else None
    text = name.lower() if name else None

    def transform(i: dict) -> Optional[dict]:
        if unassigned_only and i.get("assignedTo"):
            return None
        if wanted:
            tags = [str(t).lower() for t in (i.get("customTags") or []) + (i.get("systemTags") or [])]
            if wanted not in tags:
                return None
        if text and text not in str(i.get("displayName") or "").lower():
            return None
        return _incident_row(i)

    return transform


def _incident_row(i: dict) -> dict:
    row = pick(i, INCIDENT_FIELDS)
    if isinstance(i.get("alerts"), list):   # only with include_alerts ($expand=alerts)
        alerts = i["alerts"]
        row["alertCount"] = len(alerts)
        row["alerts"] = [compact(pick(a, ("title", "severity", "status", "serviceSource", "category",
                                          "mitreTechniques"))) for a in alerts[:5]]
        entities = summarize_entities([e for a in alerts for e in (a.get("evidence") or [])])
        if entities:
            row["entities"] = entities
    return row


@read_tool(scopes=(SECURITY_INCIDENT_READ,), title="List incidents")
async def list_incidents(
    status: Annotated[Optional[IncidentStatus], "Incident status. Open incidents are active, inProgress or awaitingAction."] = None,
    severity: Annotated[Optional[Severity], "Only this severity."] = None,
    since_hours: SinceHours = None,
    assigned_to: AssignedTo = None,
    classification: Annotated[Optional[Classification], "Only this classification."] = None,
    determination: Annotated[Optional[IncidentDetermination], "Only this determination (e.g. malware, phishing)."] = None,
    unassigned_only: Annotated[bool, "Only incidents without an owner."] = False,
    tag: Annotated[Optional[str], "Only incidents with this tag (custom or system tag, case-insensitive)."] = None,
    name_contains: Annotated[Optional[str], "Only incidents whose name contains this text (case-insensitive)."] = None,
    include_alerts: Annotated[bool, "Add the alerts (title, severity, product, MITRE) and impacted entities of each "
                                    "incident, e.g. to rank several incidents for triage."] = False,
    max_items: MaxItems = 50,
    cursor: Cursor = None,
) -> dict:
    """Microsoft Defender XDR incidents (the incident queue), filtered by status, severity, time window, owner
    ('me' for the signed-in user), unassigned, tag, name, classification and determination; optionally with
    the alerts and entities of each incident. Each page is sorted newest first (Graph cannot sort, so narrow
    with since_hours). Each row: id, name, status, severity, owner, classification/determination,
    created/updated time, priority score and portal link. For the alerts and impacted entities of one
    incident use get_incident; for counts across the tenant use get_security_overview."""
    tool = "list_incidents"
    if cursor:
        extra = cursor_extra(cursor, tool)
        return _newest_first(await get_paged("", tool=tool, cursor=cursor, max_items=max_items,
                                             transform=_incident_filter(extra.get("u", False), extra.get("tag"),
                                                                        extra.get("n"))))
    if unassigned_only and assigned_to:
        raise InputError("Use either assigned_to or unassigned_only.")
    tag_value = str(tag).strip() if tag else None
    if tag_value is not None and not 0 < len(tag_value) <= 200:
        raise InputError("tag must have 1-200 characters.")
    name_value = str(name_contains).strip() if name_contains else None
    if name_value is not None and not 0 < len(name_value) <= 200:
        raise InputError("name_contains must have 1-200 characters.")
    params = {}
    flt = _filters(status=status, severity=severity, since_hours=since_hours, assigned_to=await owner(assigned_to),
                   classification=classification, determination=determination)
    if flt:
        params["$filter"] = flt
    if include_alerts:
        params["$expand"] = "alerts"
    extra = {"u": True} if unassigned_only else {}
    if tag_value:
        extra["tag"] = tag_value
    if name_value:
        extra["n"] = name_value
    return _newest_first(await get_paged("/security/incidents", tool=tool, params=params, version="v1.0",
                                         use_top=True, top_cap=PAGE, max_items=max_items, extra=extra or None,
                                         transform=_incident_filter(unassigned_only, tag_value, name_value)))


def _alert_brief(a: dict) -> dict:
    row = pick(a, ("id", "title", "severity", "status", "serviceSource", "detectionSource", "category",
                   "createdDateTime", "firstActivityDateTime", "lastActivityDateTime", "mitreTechniques",
                   "classification", "determination"))
    entities = summarize_entities(a.get("evidence") or [])
    if entities:
        row["entities"] = entities
    return row


def _comments(items: Optional[list], limit: int = 10) -> list:
    rows = [compact({"comment": truncate(c.get("comment"), 500), "by": c.get("createdByDisplayName"),
                     "at": c.get("createdDateTime")}) for c in items or []]
    return rows[-limit:]


@read_tool(scopes=(SECURITY_INCIDENT_READ,), title="Incident details")
async def get_incident(incident_id: IncidentId) -> dict:
    """One Defender XDR incident with its alerts (title, severity, status, source, MITRE techniques), the
    impacted entities across all alerts (devices, users, mailboxes, IPs, URLs, files), comments, tags and
    portal link. Use get_alert(alert_id) for the full evidence of an alert."""
    iid = valid_incident_id(incident_id)
    inc = await runtime.graph().get(f"/security/incidents/{iid}", params={"$expand": "alerts"})
    alerts = inc.get("alerts") or []
    evidence = [e for a in alerts for e in (a.get("evidence") or [])]
    out = {
        "incident": compact(pick(inc, INCIDENT_FIELDS + ("resolvingComment",))),
        "description": truncate(inc.get("description"), 1500),
        "summary": truncate(inc.get("summary"), 1500),
        "alerts": [_alert_brief(a) for a in alerts[:50]],
        "alertCount": len(alerts),
        "entities": summarize_entities(evidence),
        "comments": _comments(inc.get("comments")),
        "next_steps": "get_alert(alert_id) for evidence; hunt_ioc(indicator) or get_device_activity(device) to "
                      "investigate; update_incident / add_comment to triage.",
        "note": UNTRUSTED_NOTE,
    }
    return compact(out)


def _alert_row(a: dict) -> dict:
    row = pick(a, ALERT_FIELDS)
    entities = summarize_entities(a.get("evidence") or [])
    if entities:
        row["entities"] = entities
    return row


@read_tool(scopes=(SECURITY_ALERT_READ,), title="List alerts")
async def list_alerts(
    severity: Annotated[Optional[Severity], "Only this severity."] = None,
    status: Annotated[Optional[AlertStatus], "Only this status."] = None,
    service_source: Annotated[Optional[ServiceSource], "Only alerts from this product."] = None,
    since_hours: SinceHours = 168,
    assigned_to: AssignedTo = None,
    classification: Annotated[Optional[Classification], "Only this classification."] = None,
    max_items: MaxItems = 50,
    cursor: Cursor = None,
) -> dict:
    """Microsoft Defender XDR alerts (alerts_v2) from all products, filtered on the server by severity, status,
    product, time window (default 7 days), owner and classification; each page is sorted newest first. Each row includes the
    incident ID and the impacted entities. Use get_alert for the complete evidence of one alert."""
    if cursor:
        return _newest_first(await get_paged("", tool="list_alerts", cursor=cursor, max_items=max_items,
                                             transform=_alert_row))
    params = {}
    flt = _filters(status=status, severity=severity, since_hours=since_hours, assigned_to=await owner(assigned_to),
                   classification=classification, service_source=service_source)
    if flt:
        params["$filter"] = flt
    return _newest_first(await get_paged("/security/alerts_v2", tool="list_alerts", params=params, version="v1.0",
                                         use_top=True, top_cap=PAGE, max_items=max_items, transform=_alert_row))


@read_tool(scopes=(SECURITY_ALERT_READ,), title="Alert details with evidence")
async def get_alert(alert_id: AlertId) -> dict:
    """One Defender XDR alert with description, recommended actions, MITRE techniques, comments and the
    complete evidence list (devices, users, processes with command lines, files with hashes, IPs, URLs,
    emails, registry keys, cloud apps) including verdict and remediation status."""
    alert = await runtime.graph().get(f"/security/alerts_v2/{key(alert_id, 'alert_id')}")
    evidence = alert.get("evidence") or []
    out = {
        "alert": compact(pick(alert, ALERT_FIELDS + ("incidentWebUrl", "providerAlertId", "resolvedDateTime"))),
        "description": truncate(alert.get("description"), 2000),
        "recommendedActions": truncate(alert.get("recommendedActions"), 1500),
        "evidence": [evidence_item(e) for e in evidence[:60]],
        "evidenceCount": len(evidence),
        "customDetails": compact(alert.get("customDetails") or {}, max_str=300),
        "comments": _comments(alert.get("comments")),
        "note": UNTRUSTED_NOTE,
    }
    return compact(out)


def _hours_between(start: Optional[str], end: Optional[str]) -> Optional[float]:
    try:
        a = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        b = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0.0, (b - a).total_seconds() / 3600)


def _top(values: list, n: int) -> list:
    counts: dict = {}
    for v in values:
        if v:
            counts[v] = counts.get(v, 0) + 1
    return [{"value": k, "count": c} for k, c in sorted(counts.items(), key=lambda kv: (-kv[1], str(kv[0])))[:n]]


def _count(items: list, field: str) -> dict:
    out: dict = {}
    for i in items:
        k = str(i.get(field) or "unknown")
        out[k] = out.get(k, 0) + 1
    return out


@read_tool(scopes=(SECURITY_INCIDENT_READ,), title="Incident statistics (SOC report)")
async def get_incident_statistics(
    days: Annotated[int, "Reporting period in days (1-90), e.g. 1 for a shift handover, 7 for a weekly report."] = 7,
) -> dict:
    """SOC report for a period: incidents created per day, by severity and current status; incidents resolved
    in the period by classification and determination; median, 90th percentile and mean time to resolve; open
    and unassigned incidents with the oldest open ones; top owners and the most frequent incident names. Time
    to resolve is measured up to the last update of a resolved incident (approximation)."""
    d = clamp_int(days, 1, 90, "days")
    since = iso_hours_ago(d * 24)
    limit = max(runtime.settings().scan_limit, 1000)
    created, created_complete = await collect("/security/incidents", version="v1.0",
                                              params={"$filter": f"createdDateTime ge {since}", "$top": str(PAGE)},
                                              limit=limit)
    resolved, resolved_complete = await collect(
        "/security/incidents", version="v1.0",
        params={"$filter": f"status eq 'resolved' and lastUpdateDateTime ge {since}", "$top": str(PAGE)}, limit=limit)
    per_day: dict = {}
    for i in created:
        day = str(i.get("createdDateTime") or "")[:10]
        per_day[day] = per_day.get(day, 0) + 1
    open_created = [i for i in created if str(i.get("status") or "") not in ("resolved", "redirected")]
    open_created.sort(key=lambda i: str(i.get("createdDateTime") or ""))
    hours = sorted(h for h in (_hours_between(i.get("createdDateTime"), i.get("lastUpdateDateTime")) for i in resolved)
                   if h is not None)
    ttr = None
    if hours:
        ttr = {"medianHours": round(statistics.median(hours), 1),
               "p90Hours": round(hours[min(len(hours) - 1, int(len(hours) * 0.9))], 1),
               "meanHours": round(statistics.fmean(hours), 1), "resolvedIncidents": len(hours)}
    return compact({
        "days": d, "since": since,
        "created": {"total": len(created), "complete": created_complete,
                    "perDay": dict(sorted(per_day.items())),
                    "bySeverity": _count(created, "severity"), "byCurrentStatus": _count(created, "status"),
                    "topNames": _top([i.get("displayName") for i in created], 10)},
        "resolved": {"total": len(resolved), "complete": resolved_complete,
                     "byClassification": _count(resolved, "classification"),
                     "byDetermination": _count(resolved, "determination"),
                     "topOwners": _top([i.get("assignedTo") for i in resolved], 5),
                     "timeToResolve": ttr},
        "stillOpenFromPeriod": {"total": len(open_created),
                                "unassigned": sum(1 for i in open_created if not i.get("assignedTo")),
                                "oldest": [pick(i, ("id", "displayName", "severity", "status", "createdDateTime",
                                                    "assignedTo")) for i in open_created[:5]]},
    })
