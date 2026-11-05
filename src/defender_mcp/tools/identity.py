"""Defender for Identity health issues and sensors.
The identity hunts (failed logons, LDAP reconnaissance, lateral movement) are in hunt_identity_threats."""
from __future__ import annotations

from typing import Annotated, Literal, Optional

from .. import runtime
from ..graph.odata import key
from ..graph.paging import collect, paginate_list, read_list_cursor
from ..scopes import IDENTITY_HEALTH_READ, IDENTITY_SENSORS_READ
from ..shaping import compact, pick, truncate
from .common import Cursor, MaxItems
from .registry import read_tool

HealthStatus = Literal["open", "closed", "suppressed"]
_FIELDS = ("id", "displayName", "severity", "status", "healthIssueType", "issueTypeId", "createdDateTime",
           "lastModifiedDateTime", "domainNames", "sensorDNSNames")


_SENSOR_FIELDS = ("id", "displayName", "domainName", "sensorType", "version", "deploymentStatus", "healthStatus",
                  "serviceStatus", "openHealthIssuesCount", "createdDateTime")


def _sensor_row(i: dict) -> dict:
    row = pick(i, _SENSOR_FIELDS)
    dcs = (i.get("settings") or {}).get("domainControllerDnsNames")
    if dcs:
        row["domainControllers"] = dcs[:5]
    return compact(row)


def _sensor_rank(r: dict) -> tuple:
    healthy = str(r.get("healthStatus") or "").lower() == "healthy"
    return (healthy, str(r.get("serviceStatus") or "").lower() == "running", str(r.get("displayName") or "").lower())


def _count(rows: list, field: str) -> dict:
    out: dict = {}
    for r in rows:
        k = str(r.get(field) or "unknown")
        out[k] = out.get(k, 0) + 1
    return out


def _row(i: dict) -> dict:
    row = pick(i, _FIELDS)
    for k in ("domainNames", "sensorDNSNames"):
        if isinstance(row.get(k), list) and len(row[k]) > 10:
            row[k] = row[k][:10] + [f"... {len(i[k]) - 10} more"]
    return row


@read_tool(scopes=(IDENTITY_HEALTH_READ, IDENTITY_SENSORS_READ), title="Defender for Identity health and sensors")
async def get_identity_health(
    status: Annotated[Optional[HealthStatus], "Only issues with this status (default: open)."] = "open",
    severity: Annotated[Optional[Literal["low", "medium", "high"]], "Only this severity."] = None,
    issue_id: Annotated[Optional[str], "Health issue ID: returns this issue with recommendations and commands."] = None,
    view: Annotated[Literal["issues", "sensors"], "issues: health issues; sensors: all Defender for Identity sensors "
                                                  "with health, service status, version and deployment status."] = "issues",
    max_items: MaxItems = 50,
    cursor: Cursor = None,
) -> dict:
    """Microsoft Defender for Identity health: health issues (sensors, domain controllers, configuration such
    as missing auditing), newest first, filtered by status and severity; one issue with description,
    recommendations, recommended PowerShell commands and affected sensors/domains; or view='sensors': the
    sensor inventory (domain controllers, AD FS / AD CS / Entra Connect servers) with health, service status,
    version and update status, unhealthy sensors first."""
    tool = "get_identity_health"
    graph = runtime.graph()
    if view == "sensors" and not issue_id:
        if cursor:
            args, offset = read_list_cursor(cursor, tool)
        else:
            args, offset = {"view": "sensors"}, 0
        if args.get("view") == "sensors":
            rows, complete = await collect("/security/identities/sensors", version="v1.0", limit=2000)
            items = sorted((_sensor_row(i) for i in rows), key=_sensor_rank)
            result = paginate_list(items, tool=tool, args=args, offset=offset, max_items=max_items, complete=complete)
            result.update({"byHealthStatus": _count(items, "healthStatus"), "byServiceStatus": _count(items, "serviceStatus"),
                           "byDeploymentStatus": _count(items, "deploymentStatus")})
            return result
    if issue_id:
        issue = await graph.get(f"/security/identities/healthIssues/{key(issue_id, 'issue_id')}")
        return compact({
            "issue": _row(issue),
            "description": truncate(issue.get("description"), 1500),
            "recommendations": [truncate(r, 500) for r in issue.get("recommendations") or []][:10],
            "recommendedActionCommands": [truncate(r, 500) for r in issue.get("recommendedActionCommands") or []][:10],
            "additionalInformation": [truncate(r, 300) for r in issue.get("additionalInformation") or []][:10],
        })
    if cursor:
        args, offset = read_list_cursor(cursor, tool)
        if args.get("view") == "sensors":
            return await get_identity_health(view="sensors", max_items=max_items, cursor=cursor)
    else:
        args, offset = {"status": status, "severity": severity}, 0
    rows, complete = await collect("/security/identities/healthIssues", version="v1.0", limit=2000)
    items = [_row(i) for i in rows
             if (not args.get("status") or str(i.get("status") or "").lower() == args["status"])
             and (not args.get("severity") or str(i.get("severity") or "").lower() == args["severity"])]
    items.sort(key=lambda r: str(r.get("createdDateTime") or ""), reverse=True)
    result = paginate_list(items, tool=tool, args=args, offset=offset, max_items=max_items, complete=complete)
    by_severity: dict = {}
    for i in items:
        by_severity[i.get("severity") or "unknown"] = by_severity.get(i.get("severity") or "unknown", 0) + 1
    result["bySeverity"] = by_severity
    return result
