"""Microsoft Sentinel / Integrated SOC (ISOC) workspaces: list_sentinel_workspaces of the Sentinel MCP
server. Workspaces are probed through advanced hunting (Usage table) with the user's own rights; no Azure Resource
Manager access is needed."""
from __future__ import annotations

from typing import Optional

from .. import kql, workspaces
from ..scopes import THREAT_HUNTING_READ
from ..util import gather_sections
from .registry import read_tool

_PROBE = "\n".join([
    "Usage",
    "| where TimeGenerated > ago(1d)",
    "| summarize TablesWithData = dcount(DataType), IngestedMB = round(sum(Quantity), 1), LastIngestion = max(EndTime) "
    "by WorkspaceId = TenantId",
])
_NO_WORKSPACE = ("No Microsoft Sentinel / ISOC workspace answered: none is connected to the Defender portal, or you "
                 "lack read access (Microsoft Sentinel Reader on the workspace).")


def _entry(name: str, requested: Optional[str], rows: list) -> dict:
    row = rows[0] if rows else {}
    answered = str(row.get("WorkspaceId") or "").lower() or None
    entry = {"name": name, "workspaceId": requested or answered, "reachable": True,
             "tablesWithData24h": row.get("TablesWithData", 0), "ingestedMB24h": row.get("IngestedMB", 0),
             "lastIngestion": row.get("LastIngestion")}
    if requested and answered and answered != requested:
        entry.update({"reachable": False, "answeredBy": answered,
                      "note": "Not accessible to you: the service answered from your primary workspace instead."})
    if not rows:
        entry["note"] = "Reachable, but no data was ingested in the last 24 hours."
    return entry


@read_tool(scopes=(THREAT_HUNTING_READ,), title="Sentinel / ISOC workspaces")
async def list_sentinel_workspaces() -> dict:
    """Microsoft Sentinel / Integrated SOC (ISOC) workspaces you can hunt in: your primary workspace (used when
    no workspace is given) and the workspaces configured for this server, each checked with a short query
    (reachable, workspace ID, tables with data in the last 24 hours, ingested MB, last ingestion). Pass the name
    or ID as workspace to run_hunting_query, get_hunting_schema or run_custom_hunt."""
    targets: dict[str, Optional[str]] = {"primary": None}
    for w in workspaces.configured():
        targets.setdefault(w["name"], w["workspaceId"])
    ok, errors = await gather_sections({name: kql.rows(_PROBE, workspace_id=wid) for name, wid in targets.items()})
    primary: dict = {"name": "primary", "reachable": False, "note": _NO_WORKSPACE}
    if "primary" in ok:
        primary = _entry("primary", None, ok["primary"])
        primary["name"] = workspaces.name_of(primary.get("workspaceId")) or "primary"
    elif "primary" in errors:
        primary["error"] = errors["primary"][:300]
    items = []
    for name, wid in targets.items():
        if name == "primary":
            continue
        if name in ok:
            items.append(_entry(name, wid, ok[name]))
        else:
            items.append({"name": name, "workspaceId": wid, "reachable": False, "error": errors.get(name, "")[:300]})
    out = {"primary": primary, "configured": items, "count": len(items) + (1 if primary.get("reachable") else 0)}
    out["hint"] = ("Omit workspace to use the primary workspace. Workspace tables (SigninLogs, BehaviorAnalytics, "
                   "ThreatIntelIndicators, custom _CL tables ...) are listed by get_hunting_schema(search=...); "
                   "data-lake-tier data is not available in advanced hunting.")
    return out
