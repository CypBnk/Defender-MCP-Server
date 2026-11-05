"""Custom detection rules: create, enable/disable, update, delete. Built for the 2026 shape of the Graph beta API: client-provided
id, status instead of isEnabled, schedule.frequency instead of schedule.period, alertTemplate.tactics and
entityMappings instead of category, mitreTechniques and impactedAssets (removed on 2026-10-01).
The preview runs the query once in advanced hunting to prove that it is valid."""
from __future__ import annotations

import re
from typing import Annotated, Literal, Optional

from .. import kql, runtime
from ..confirm import two_step
from ..errors import DefenderToolError, InputError
from ..graph.odata import key
from ..scopes import CUSTOM_DETECTION_READWRITE, THREAT_HUNTING_READ
from ..shaping import truncate
from .common import ConfirmationToken, Severity
from .detections import rule_row
from .registry import admin_tool

Frequency = Literal["PT1H", "PT3H", "PT12H", "P1D"]
Tactic = Literal["Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
                 "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
                 "Collection", "CommandAndControl", "Exfiltration", "Impact"]
EntityKind = Literal["device", "account", "file"]
_ENTITY_MAPPINGS = {
    "device": ("hosts", {"deviceIdColumn": "DeviceId", "nameColumn": "DeviceName"}),
    "account": ("accounts", {"nameColumn": "AccountName", "ntDomainColumn": "AccountDomain", "sidColumn": "AccountSid"}),
    "file": ("files", {"nameColumn": "FileName", "sha1Column": "SHA1", "sha256Column": "SHA256"}),
}
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
_RULE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
_PATH = "/security/rules/detectionRules"


def _slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60].strip("-")
    return slug if len(slug) >= 3 else f"rule-{slug or 'custom'}"


async def validate_rule_query(query: str, mapped: list[str]) -> dict:
    """Run the query (max. 5 rows) and report the columns, so a broken rule is caught before it is saved."""
    q = kql.validate_query(query)
    try:
        columns, rows = await kql.execute(kql.with_row_limit(q, 5))
    except DefenderToolError as exc:
        return {"valid": False, "error": str(exc)[:600]}
    warnings = []
    required = {"Timestamp", "ReportId"}
    for kind in mapped:
        required |= {v for v in _ENTITY_MAPPINGS[kind][1].values()}
    missing = sorted(c for c in required if columns and c not in columns)
    if missing:
        warnings.append("The query result lacks columns that the rule needs (Timestamp, ReportId and the mapped entity "
                        f"columns): {', '.join(missing)}. Add them with project/extend.")
    if not rows:
        warnings.append("The query returned no rows for the default time range; the rule may never fire.")
    return {"valid": True, "columns": columns[:40], "sampleRows": len(rows), "warnings": warnings}


@admin_tool(scopes=(CUSTOM_DETECTION_READWRITE, THREAT_HUNTING_READ), title="Create custom detection rule",
            destructive=False)
async def create_detection_rule(
    display_name: Annotated[str, "Rule name."],
    query: Annotated[str, "Advanced hunting KQL. Must return Timestamp, ReportId and the columns of the mapped "
                          "entities (DeviceId/DeviceName, AccountName/AccountDomain/AccountSid, FileName/SHA1/SHA256)."],
    alert_title: Annotated[str, "Title of the alerts the rule creates."],
    severity: Annotated[Severity, "Alert severity."] = "medium",
    frequency: Annotated[Frequency, "How often the rule runs (ISO 8601: PT1H hourly ... P1D daily)."] = "PT1H",
    alert_description: Annotated[Optional[str], "Alert description."] = None,
    recommended_actions: Annotated[Optional[str], "Recommended actions shown in the alert."] = None,
    tactic: Annotated[Optional[Tactic], "MITRE ATT&CK tactic."] = None,
    techniques: Annotated[Optional[list[str]], "MITRE technique IDs, e.g. ['T1059.001'] (needs tactic)."] = None,
    entities: Annotated[Optional[list[EntityKind]], "Entities to attach to the alert (default: device)."] = None,
    enabled: Annotated[bool, "Create the rule enabled (true) or disabled (false)."] = True,
    description: Annotated[Optional[str], "Rule description."] = None,
    rule_id: Annotated[Optional[str], "Rule ID (lowercase letters, digits, hyphens). Default: derived from the name."] = None,
    confirmation_token: ConfirmationToken = None,
) -> dict:
    """Create a Defender XDR custom detection rule from a KQL query (e.g. the 'kql' of a hunt). Two-step: the
    preview runs the query once to validate it and lists missing columns; the second call with
    confirmation_token creates the rule. No automated response actions are configured."""
    name = (display_name or "").strip()
    if not 3 <= len(name) <= 200:
        raise InputError("display_name must have 3-200 characters.")
    title = (alert_title or "").strip()
    if not 3 <= len(title) <= 200:
        raise InputError("alert_title must have 3-200 characters.")
    q = kql.validate_query(query)
    rid = (rule_id or _slug(name)).strip().lower()
    if not _RULE_ID.match(rid):
        raise InputError("rule_id must be 3-64 lowercase letters, digits or hyphens.")
    mapped = list(dict.fromkeys(entities or ["device"]))
    techniques = list(dict.fromkeys(t.strip().upper() for t in techniques or []))
    if techniques and not tactic:
        raise InputError("techniques need a tactic.")
    bad = [t for t in techniques if not _TECHNIQUE.match(t)]
    if bad:
        raise InputError(f"Invalid MITRE technique IDs: {bad[:5]} (format T1059 or T1059.001).")
    template: dict = {"title": title, "severity": severity,
                      "entityMappings": {_ENTITY_MAPPINGS[k][0]: [_ENTITY_MAPPINGS[k][1]] for k in mapped}}
    if alert_description:
        template["description"] = truncate(alert_description.strip(), 4000)
    if recommended_actions:
        template["recommendedActions"] = truncate(recommended_actions.strip(), 4000)
    if tactic:
        template["tactics"] = [{"tactic": tactic, "techniques": [{"technique": t} for t in techniques]}]
    body: dict = {
        "@odata.type": "#microsoft.graph.security.detectionRule",
        "id": rid,
        "displayName": name,
        "status": "enabled" if enabled else "disabled",
        "queryCondition": {"queryText": q},
        "schedule": {"frequency": frequency},
        "detectionAction": {"alertTemplate": template},
    }
    if description:
        body["description"] = truncate(description.strip(), 4000)

    async def preview() -> dict:
        check = await validate_rule_query(q, mapped)
        out = {"rule": {"id": rid, "displayName": name, "status": body["status"], "frequency": frequency,
                        "alertTitle": title, "severity": severity, "entities": mapped, "tactic": tactic,
                        "techniques": techniques},
               "queryValidation": check}
        if not check.get("valid"):
            out["warning"] = "The query failed in advanced hunting. Fix it before confirming."
        return out

    async def execute() -> dict:
        created = await runtime.graph().post(_PATH, json_body=body, version="beta")
        return {"rule": rule_row(created or body)}

    return await two_step(action="detection_rule.create", target=rid, params=body, token=confirmation_token,
                          preview=preview, execute=execute)


@admin_tool(scopes=(CUSTOM_DETECTION_READWRITE, THREAT_HUNTING_READ), title="Enable, disable, update or delete a "
            "custom detection rule", destructive=True)
async def manage_detection_rule(
    rule_id: Annotated[str, "Detection rule ID."],
    action: Annotated[Literal["enable", "disable", "update", "delete"], "What to do with the rule."],
    display_name: Annotated[Optional[str], "update: new rule name."] = None,
    query: Annotated[Optional[str], "update: new KQL query (validated in the preview)."] = None,
    frequency: Annotated[Optional[Frequency], "update: new run frequency."] = None,
    alert_title: Annotated[Optional[str], "update: new alert title."] = None,
    severity: Annotated[Optional[Severity], "update: new alert severity."] = None,
    confirmation_token: ConfirmationToken = None,
) -> dict:
    """Enable, disable, update (name, query, frequency, alert title/severity) or delete one custom detection
    rule. Two-step: the preview shows the rule and the change (a new query is validated in advanced hunting);
    the second call with confirmation_token applies it. Deleting is irreversible."""
    rid = key(rule_id, "rule_id")
    graph = runtime.graph()
    rule = await graph.get(f"{_PATH}/{rid}", version="beta")
    updates = {k: v for k, v in {"display_name": display_name, "query": query, "frequency": frequency,
                                 "alert_title": alert_title, "severity": severity}.items() if v}
    if action != "update" and updates:
        raise InputError("display_name, query, frequency, alert_title and severity are only valid for action='update'.")
    body: dict = {}
    if action in ("enable", "disable"):
        body = {"status": "enabled" if action == "enable" else "disabled"}
    elif action == "update":
        if not updates:
            raise InputError("action='update' needs at least one of display_name, query, frequency, alert_title, severity.")
        if display_name:
            body["displayName"] = display_name.strip()
        if query:
            body["queryCondition"] = {"queryText": kql.validate_query(query)}
        if frequency:
            body["schedule"] = {"frequency": frequency}
        if alert_title or severity:
            # Complex properties are replaced as a whole: send the complete alert template with the change.
            action_obj = dict(rule.get("detectionAction") or {})
            template = dict(action_obj.get("alertTemplate") or {})
            for removed in ("category", "mitreTechniques", "impactedAssets"):  # removed from the API on 2026-10-01
                template.pop(removed, None)
            template = {k: v for k, v in template.items() if v is not None}
            if alert_title:
                template["title"] = alert_title.strip()
            if severity:
                template["severity"] = severity
            action_obj["alertTemplate"] = template
            body["detectionAction"] = {k: v for k, v in action_obj.items() if v is not None}

    async def preview() -> dict:
        out: dict = {"rule": rule_row(rule), "action": action}
        if body:
            out["change"] = {k: (truncate((v or {}).get("queryText"), 2000) if k == "queryCondition" else v)
                             for k, v in body.items()}
        if query:
            mapping = ((rule.get("detectionAction") or {}).get("alertTemplate") or {}).get("entityMappings") or {}
            kinds = [k for k, (prop, _) in _ENTITY_MAPPINGS.items() if mapping.get(prop)]
            out["queryValidation"] = await validate_rule_query(query, kinds)
        if action == "delete":
            out["warning"] = "IRREVERSIBLE. The rule is deleted; alerts it created remain."
        if action == "disable":
            out["warning"] = "The rule stops creating alerts until it is enabled again."
        return out

    async def execute() -> dict:
        if action == "delete":
            await graph.delete(f"{_PATH}/{rid}", version="beta")
            return {"rule": {"id": rid, "displayName": rule.get("displayName")}, "message": "Rule deleted."}
        updated = await graph.patch(f"{_PATH}/{rid}", json_body=body, version="beta")
        return {"rule": rule_row(updated or {**rule, **body})}

    return await two_step(action=f"detection_rule.{action}", target=rid, params=body or {"action": action},
                          token=confirmation_token, preview=preview, execute=execute)
