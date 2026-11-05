"""Security overview and connection test."""
from __future__ import annotations

import asyncio

from .. import __version__, kql, runtime
from ..errors import DefenderToolError
from ..graph.paging import collect
from ..scopes import (IDENTITY_HEALTH_READ, SECURITY_EVENTS_READ, SECURITY_INCIDENT_READ, THREAT_HUNTING_READ,
                      USER_READ)
from ..shaping import compact, pick
from ..util import gather_sections
from .common import Days
from .registry import read_tool

_SEVERITIES = ("high", "medium", "low", "informational")
# Open = not resolved/redirected. One request per status, because only plain 'eq' filters are documented.
_OPEN_STATUSES = ("active", "inProgress", "awaitingAction")


async def _open_incidents() -> tuple[list, bool, list]:
    """(items, complete, statuses that could not be read). Only a failure for 'active' fails the section."""
    results = await asyncio.gather(
        *(collect("/security/incidents", version="v1.0", params={"$filter": f"status eq '{status}'", "$top": "50"},
                  limit=1000) for status in _OPEN_STATUSES),
        return_exceptions=True)
    items: list = []
    complete, skipped = True, []
    for status, res in zip(_OPEN_STATUSES, results, strict=True):
        if isinstance(res, BaseException):
            if status == _OPEN_STATUSES[0] or not isinstance(res, DefenderToolError):
                raise res
            skipped.append(status)
            continue
        items.extend(res[0])
        complete = complete and res[1]
    return items, complete, skipped


def _count(rows: list, field: str) -> dict:
    out: dict = {}
    for r in rows:
        k = str(r.get(field) or "unknown")
        out[k] = out.get(k, 0) + 1
    return out


@read_tool(scopes=(USER_READ, SECURITY_INCIDENT_READ, THREAT_HUNTING_READ, SECURITY_EVENTS_READ, IDENTITY_HEALTH_READ),
           title="Security overview")
async def get_security_overview(days: Days = 7) -> dict:
    """Overview of the Defender XDR tenant and a connection test: signed-in user, open incidents by severity
    (newest high-severity ones listed), alerts of the last days by product and severity with the most frequent
    alert titles and MITRE techniques, device onboarding / sensor health, Secure Score and open Defender for
    Identity health issues. Sections the user may not read (missing role or license) are listed under 'errors'."""
    d = kql.days(days)
    graph = runtime.graph()
    tasks = {
        "signedInUser": graph.get("/me", params={"$select": "id,displayName,userPrincipalName"}),
        "incidents": _open_incidents(),
        "alertsBySource": kql.rows(
            f"AlertInfo\n| where Timestamp > ago({d}d)\n| summarize arg_max(Timestamp, Severity, ServiceSource) by AlertId\n"
            '| summarize Alerts = count(), High = countif(Severity == "High"), Medium = countif(Severity == "Medium"), '
            'Low = countif(Severity == "Low"), Informational = countif(Severity == "Informational") by ServiceSource\n'
            "| order by Alerts desc"),
        "topAlerts": kql.rows(
            f"AlertInfo\n| where Timestamp > ago({d}d)\n| summarize arg_max(Timestamp, Title, Severity, AttackTechniques) by AlertId\n"
            "| summarize Count = count(), Severity = take_any(Severity) by Title\n| top 10 by Count"),
        "techniques": kql.rows(
            f"AlertInfo\n| where Timestamp > ago({d}d)\n| where isnotempty(AttackTechniques)\n"
            "| summarize arg_max(Timestamp, AttackTechniques) by AlertId\n"
            "| mv-expand Technique = todynamic(AttackTechniques) to typeof(string)\n"
            "| summarize Alerts = count() by Technique\n| top 10 by Alerts"),
        "devices": kql.rows(
            "DeviceInfo\n| where Timestamp > ago(7d)\n| summarize arg_max(Timestamp, OnboardingStatus, SensorHealthState) by DeviceId\n"
            "| summarize Devices = count() by OnboardingStatus, SensorHealthState\n| order by Devices desc"),
        "secureScore": graph.get("/security/secureScores", params={"$top": "1"}),
        "identityHealth": collect("/security/identities/healthIssues", version="v1.0", limit=1000),
    }
    ok, errors = await gather_sections(tasks)
    out: dict = {"server": {"version": __version__, "profile": runtime.settings().profile}, "days": d}
    if "signedInUser" in ok:
        out["signedInUser"] = pick(ok["signedInUser"], ("displayName", "userPrincipalName", "id"))
    if "incidents" in ok:
        incidents, complete, skipped = ok["incidents"]
        by_sev = _count(incidents, "severity")
        high = sorted((i for i in incidents if str(i.get("severity")) == "high"),
                      key=lambda i: str(i.get("createdDateTime") or ""), reverse=True)
        newest_high = [pick(i, ("id", "displayName", "createdDateTime", "assignedTo")) for i in high[:5]]
        out["openIncidents"] = compact({"total": len(incidents), "complete": complete,
                                        "byStatus": _count(incidents, "status"), "statusesNotRead": skipped,
                                        "bySeverity": {s: by_sev.get(s, 0) for s in _SEVERITIES},
                                        "unassigned": sum(1 for i in incidents if not i.get("assignedTo")),
                                        "newestHigh": newest_high})
    alerts: dict = {}
    if "alertsBySource" in ok:
        alerts["byProduct"] = ok["alertsBySource"]
        alerts["total"] = sum(int(r.get("Alerts") or 0) for r in ok["alertsBySource"])
    if "topAlerts" in ok:
        alerts["topTitles"] = kql.shape_rows(ok["topAlerts"], limit=10, max_str=200)[0]
    if "techniques" in ok:
        alerts["topMitreTechniques"] = ok["techniques"]
    if alerts:
        out["alerts"] = alerts
    if "devices" in ok:
        out["devices"] = {"total": sum(int(r.get("Devices") or 0) for r in ok["devices"]), "groups": ok["devices"]}
    if "secureScore" in ok:
        latest = (ok["secureScore"].get("value") or [{}])[0]
        if latest:
            cur, mx = latest.get("currentScore"), latest.get("maxScore")
            out["secureScore"] = compact({"score": cur, "maxScore": mx, "date": latest.get("createdDateTime"),
                                          "percentage": round(100 * cur / mx, 1) if cur is not None and mx else None})
    if "identityHealth" in ok:
        issues, _ = ok["identityHealth"]
        open_issues = [i for i in issues if str(i.get("status")) == "open"]
        out["identityHealth"] = {"open": len(open_issues), "bySeverity": _count(open_issues, "severity")}
    if errors:
        out["errors"] = errors
    return out
