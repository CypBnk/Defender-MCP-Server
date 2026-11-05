"""Custom detection rules (read). Graph beta API in its 2026 shape:
status (enabled/disabled/autoDisabled) and schedule.frequency replace isEnabled and schedule.period."""
from __future__ import annotations

from typing import Annotated, Literal, Optional

from .. import runtime
from ..graph.odata import key, odata_str
from ..graph.paging import get_paged
from ..scopes import CUSTOM_DETECTION_READ
from ..shaping import compact, pick, truncate
from .common import Cursor, MaxItems
from .registry import read_tool

RuleStatus = Literal["enabled", "disabled", "autoDisabled"]


def rule_row(r: dict) -> dict:
    template = ((r.get("detectionAction") or {}).get("alertTemplate") or {})
    tactics = [t.get("tactic") for t in template.get("tactics") or [] if t.get("tactic")]
    return compact({
        **pick(r, ("id", "displayName", "status", "createdBy", "createdDateTime", "lastModifiedBy",
                   "lastModifiedDateTime")),
        "frequency": (r.get("schedule") or {}).get("frequency") or (r.get("schedule") or {}).get("period"),
        "alertTitle": template.get("title"), "alertSeverity": template.get("severity"), "tactics": tactics,
    })


@read_tool(scopes=(CUSTOM_DETECTION_READ,), title="List custom detection rules")
async def list_detection_rules(
    name_contains: Annotated[Optional[str], "Part of the rule name."] = None,
    status: Annotated[Optional[RuleStatus], "Only rules with this status."] = None,
    max_items: MaxItems = 50,
    cursor: Cursor = None,
) -> dict:
    """Custom detection rules of Defender XDR: name, status (enabled, disabled, autoDisabled), run frequency,
    alert title and severity, MITRE tactics, creator and last change. Use get_detection_rule for the query."""
    tool = "list_detection_rules"
    if cursor:
        return await get_paged("", tool=tool, cursor=cursor, max_items=max_items, transform=rule_row)
    filters = []
    if name_contains:
        filters.append(f"contains(displayName,{odata_str(name_contains, 'name_contains')})")
    if status:
        filters.append(f"status eq {odata_str(status)}")
    params = {"$filter": " and ".join(filters)} if filters else None
    return await get_paged("/security/rules/detectionRules", tool=tool, params=params, version="beta",
                           max_items=max_items, transform=rule_row)


@read_tool(scopes=(CUSTOM_DETECTION_READ,), title="Custom detection rule details")
async def get_detection_rule(rule_id: Annotated[str, "Detection rule ID."]) -> dict:
    """One custom detection rule with its KQL query, schedule, alert template (title, description, severity,
    recommended actions, MITRE tactics/techniques, entity mappings), automated response actions and incident
    correlation setting."""
    rule = await runtime.graph().get(f"/security/rules/detectionRules/{key(rule_id, 'rule_id')}", version="beta")
    action = rule.get("detectionAction") or {}
    template = action.get("alertTemplate") or {}
    return compact({
        "rule": rule_row(rule),
        "description": truncate(rule.get("description"), 1000),
        "query": truncate((rule.get("queryCondition") or {}).get("queryText"), 8000),
        "alertTemplate": compact({**pick(template, ("title", "severity", "category")),
                                  "description": truncate(template.get("description"), 1000),
                                  "recommendedActions": truncate(template.get("recommendedActions"), 1000),
                                  "tactics": template.get("tactics"), "entityMappings": template.get("entityMappings"),
                                  "mitreTechniques": template.get("mitreTechniques")}),
        "automatedActions": action.get("automatedActions") or action.get("responseActions"),
        "incidentConfiguration": action.get("incidentConfiguration"),
        "lastRunDetails": rule.get("lastRunDetails"),
    })
