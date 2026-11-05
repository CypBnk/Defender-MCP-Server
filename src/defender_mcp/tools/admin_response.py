"""Defender for Endpoint response actions and custom indicators (Defender for Endpoint API, delegated:
WindowsDefenderATP permissions plus the user's Defender role, e.g. 'Active remediation actions', and access
to the device group)."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal, Optional

from .. import kql, runtime
from ..confirm import two_step
from ..errors import GraphError, InputError
from ..graph.odata import clamp_int, guid, iso_days_ago, key, odata_str
from ..resolve import resolve_device
from ..scopes import (MDE_ALERT_READWRITE, MDE_MACHINE_COLLECT_FORENSICS, MDE_MACHINE_ISOLATE,
                      MDE_MACHINE_READWRITE, MDE_MACHINE_RESTRICT_EXECUTION, MDE_MACHINE_SCAN,
                      MDE_MACHINE_STOP_AND_QUARANTINE, MDE_TI_READWRITE, THREAT_HUNTING_READ)
from ..shaping import compact, pick, truncate
from ..util import gather_sections
from .common import ConfirmationToken, DeviceRef, MaxItems
from .registry import admin_tool

ResponseAction = Literal["isolate", "release_isolation", "antivirus_scan_quick", "antivirus_scan_full",
                         "collect_investigation_package", "restrict_app_execution", "remove_app_restriction",
                         "stop_and_quarantine_file", "start_automated_investigation", "add_tag", "remove_tag"]
# action -> (API path, immediate, effect, Windows only)
_ACTIONS: dict[str, tuple[str, bool, str, bool]] = {
    "isolate": ("isolate", False, "The device is cut off from the network except the Defender service; users lose "
                                  "network access until the isolation is released.", False),
    "release_isolation": ("unisolate", False, "The network isolation is removed.", False),
    "antivirus_scan_quick": ("runAntiVirusScan", True, "Microsoft Defender Antivirus runs a quick scan.", False),
    "antivirus_scan_full": ("runAntiVirusScan", True, "Microsoft Defender Antivirus runs a full scan (can take hours).",
                            False),
    "collect_investigation_package": ("collectInvestigationPackage", False, "Forensic data (processes, autoruns, "
                                      "event logs, network connections ...) is collected and uploaded to Defender.", False),
    "restrict_app_execution": ("restrictCodeExecution", False, "Only Microsoft-signed applications may run until the "
                               "restriction is removed.", True),
    "remove_app_restriction": ("unrestrictCodeExecution", False, "The application execution restriction is removed.",
                               True),
    "stop_and_quarantine_file": ("StopAndQuarantineFile", False, "Processes of the file are stopped and the file is "
                                 "quarantined on the device.", True),
    "start_automated_investigation": ("startInvestigation", False, "An automated investigation (AIR) starts on the "
                                      "device. Depending on the automation level of its device group, remediation "
                                      "actions run automatically or wait for approval in the Action center.", True),
    "add_tag": ("tags", False, "The tag is added to the device. Tags can move the device into another device group "
                               "(RBAC, automation level, policies).", False),
    "remove_tag": ("tags", False, "The tag is removed from the device (device group membership can change).", False),
}
_TAG_ACTIONS = ("add_tag", "remove_tag")
_TAG = re.compile(r"^[^\x00-\x1f]{1,200}$")
_INVESTIGATION_FIELDS = ("id", "state", "startTime", "machineId", "computerDnsName", "triggeringAlertId",
                         "statusDetails")
_ACTION_FIELDS = ("id", "type", "scope", "status", "requestor", "requestorComment", "computerDnsName", "machineId",
                  "creationDateTimeUtc", "lastUpdateDateTimeUtc", "relatedFileInfo")
_COMMENT_SUFFIX = " [via Defender XDR MCP]"


def _comment(text: Optional[str], action: str) -> str:
    base = (text or "").strip() or f"{action.replace('_', ' ').capitalize()} requested in Copilot Studio"
    if re.search(r"[\x00-\x1f]", base):
        raise InputError("comment must not contain control characters.")
    return truncate(base, 900) + _COMMENT_SUFFIX


def _is_immediate_response(args: dict) -> bool:
    return bool(_ACTIONS.get(str(args.get("action")), ("", False))[1])


async def _pending_actions(device_id: str) -> list:
    res = await runtime.mde().get("/api/machineactions",
                                  params={"$filter": f"machineId eq {odata_str(device_id)} and status eq 'Pending'"})
    return [compact(pick(a, ("id", "type", "status", "creationDateTimeUtc", "requestor"))) for a in res.get("value") or []]


@admin_tool(scopes=(THREAT_HUNTING_READ, MDE_MACHINE_ISOLATE, MDE_MACHINE_SCAN, MDE_MACHINE_COLLECT_FORENSICS,
                    MDE_MACHINE_RESTRICT_EXECUTION, MDE_MACHINE_STOP_AND_QUARANTINE, MDE_MACHINE_READWRITE,
                    MDE_ALERT_READWRITE),
            title="Device response action (isolate, scan, investigation, tags ...)", destructive=True,
            immediate=_is_immediate_response)
async def run_device_response(
    device: DeviceRef,
    action: Annotated[ResponseAction, "antivirus_scan_* run immediately; all other actions need confirmation."],
    comment: Annotated[Optional[str], "Reason, stored with the action in Defender (e.g. 'incident 42')."] = None,
    isolation_type: Annotated[Literal["Full", "Selective"], "isolate: Full or Selective (Selective keeps Outlook, "
                                                            "Teams and Skype working; Windows 10 1709+)."] = "Full",
    sha1: Annotated[Optional[str], "stop_and_quarantine_file: SHA1 of the file."] = None,
    tag: Annotated[Optional[str], "add_tag / remove_tag: the device tag (1-200 characters)."] = None,
    confirmation_token: ConfirmationToken = None,
) -> dict:
    """Run a Defender for Endpoint action on one device: isolate / release isolation, antivirus scan (quick,
    full), collect investigation package, restrict / allow app execution, stop and quarantine a file (SHA1),
    start an automated investigation, add or remove a device tag. Antivirus scans run immediately; all other
    actions are two-step (preview, then confirmation_token). Returns the machine action or investigation ID;
    follow up with get_response_actions."""
    if action not in _ACTIONS:
        raise InputError(f"action must be one of: {', '.join(_ACTIONS)}.")
    path, immediate, effect, windows_only = _ACTIONS[action]
    if isolation_type != "Full" and action != "isolate":
        raise InputError("isolation_type is only valid for action='isolate'.")
    if sha1 and action != "stop_and_quarantine_file":
        raise InputError("sha1 is only valid for action='stop_and_quarantine_file'.")
    if tag and action not in _TAG_ACTIONS:
        raise InputError("tag is only valid for action='add_tag' or 'remove_tag'.")
    body: dict
    if action in _TAG_ACTIONS:
        value = str(tag or "").strip()
        if not _TAG.match(value):
            raise InputError("tag is required for add_tag / remove_tag (1-200 characters, no control characters).")
        body = {"Value": value, "Action": "Add" if action == "add_tag" else "Remove"}
    else:
        body = {"Comment": _comment(comment, action)}
    if action == "isolate":
        body["IsolationType"] = isolation_type
    elif action.startswith("antivirus_scan"):
        body["ScanType"] = "Quick" if action.endswith("quick") else "Full"
    elif action == "stop_and_quarantine_file":
        if not sha1:
            raise InputError("sha1 is required for stop_and_quarantine_file (use hunt_ioc or get_alert to find it).")
        body["Sha1"] = kql.file_hash(sha1, "sha1")[1]
    dev = await resolve_device(device)
    device_id = dev["DeviceId"]
    warnings = []
    platform = str(dev.get("OSPlatform") or "")
    if windows_only and not platform.lower().startswith("windows"):
        warnings.append(f"'{action}' is only supported on Windows; the device runs {platform or 'an unknown OS'}.")
    if action == "isolate" and isolation_type == "Selective" and not platform.lower().startswith("windows"):
        warnings.append("Selective isolation is only supported on Windows 10 1709 or later and Windows 11.")
    if str(dev.get("OnboardingStatus") or "").lower() not in ("onboarded", ""):
        warnings.append(f"Onboarding status is '{dev.get('OnboardingStatus')}': response actions need an onboarded device.")
    if str(dev.get("SensorHealthState") or "").lower() not in ("active", ""):
        warnings.append(f"Sensor health is '{dev.get('SensorHealthState')}': the action stays pending until the "
                        "device connects.")

    current_tags = [str(t) for t in (dev.get("DeviceManualTags") or [])] if isinstance(dev.get("DeviceManualTags"), list) else []
    if action == "remove_tag" and current_tags and body["Value"].lower() not in (t.lower() for t in current_tags):
        warnings.append(f"The device has no manual tag '{body['Value']}' (tags: {', '.join(current_tags)}).")
    if action == "add_tag" and body["Value"].lower() in (t.lower() for t in current_tags):
        warnings.append(f"The device already has the tag '{body['Value']}'.")

    async def run() -> dict:
        res = await runtime.mde().post(f"/api/machines/{device_id}/{path}", json_body=body)
        out: dict = {"device": pick(dev, ("DeviceId", "DeviceName"))}
        if action in _TAG_ACTIONS:
            out.update({"machineTags": (res or {}).get("machineTags"), "message": effect})
        elif action == "start_automated_investigation":
            out.update({"investigation": compact(pick(res or {}, _INVESTIGATION_FIELDS)), "message": f"Requested. {effect}",
                        "next_steps": "Follow the investigation and approve pending actions in the Defender portal "
                                      "(Action center); the investigation can take several hours."})
        else:
            out.update({"machineAction": compact(pick(res or {}, _ACTION_FIELDS)), "message": f"Requested. {effect}",
                        "next_steps": "get_response_actions(action_id=...) shows the progress (Pending, InProgress, "
                                      "Succeeded)."})
        return out

    if immediate:
        out = await run()
        out.update({"status": "done", "action": f"device.{action}"})
        if warnings:
            out["warnings"] = warnings
        return out

    async def preview() -> dict:
        out: dict = {"device": pick(dev, ("DeviceId", "DeviceName", "OSPlatform", "OSVersion", "OnboardingStatus",
                                         "SensorHealthState", "MachineGroup", "LastSeen")),
                     "effect": effect, "comment": body.get("Comment")}
        if action == "isolate":
            out["isolationType"] = isolation_type
        if action == "stop_and_quarantine_file":
            out["sha1"] = body["Sha1"]
        if action in _TAG_ACTIONS:
            out.update({"tag": body["Value"], "currentTags": current_tags})
            out.pop("comment", None)
        ok, _errors = await gather_sections({"pending": _pending_actions(device_id)})
        if ok.get("pending"):
            out["pendingActions"] = ok["pending"]
            warnings.append("The device already has pending response actions (see pendingActions).")
        if warnings:
            out["warnings"] = warnings
        return out

    return await two_step(action=f"device.{action}", target=device_id, params=body, token=confirmation_token,
                          preview=preview, execute=run)


@admin_tool(scopes=(THREAT_HUNTING_READ, MDE_MACHINE_READWRITE, MDE_ALERT_READWRITE),
            title="Status of response actions and automated investigations",
            destructive=False, idempotent=True, read_only=True, immediate=lambda _args: True)
async def get_response_actions(
    device: Annotated[Optional[str], "Only actions of this device (name, FQDN, Defender or Entra device ID)."] = None,
    action_id: Annotated[Optional[str], "One machine action ID (returned by run_device_response)."] = None,
    days: Annotated[int, "Look-back window in days (1-180)."] = 7,
    kind: Annotated[Literal["machine_actions", "investigations", "attack_disruption"],
                    "machine_actions: isolation, scans, packages, ...; investigations: automated investigations (AIR); "
                    "attack_disruption: what automatic attack disruption and predictive shielding blocked (contained "
                    "users' logons, sessions, applied policies)."] = "machine_actions",
    investigation_id: Annotated[Optional[str], "One automated investigation by ID."] = None,
    state: Annotated[Optional[Literal["Running", "PendingApproval", "PendingResource", "Queued", "Benign",
                                      "SuccessfullyRemediated", "PartiallyRemediated", "PartiallyInvestigated",
                                      "Failed", "Terminated", "TerminatedByUser", "TerminatedBySystem"]],
                     "investigations: only this state (PendingApproval = waiting in the Action center)."] = None,
    max_items: MaxItems = 20,
) -> dict:
    """Status of Defender for Endpoint response actions (isolation, scans, investigation packages, ...) or of
    automated investigations (kind='investigations': state such as Running, PendingApproval, SuccessfullyRemediated, with
    device and triggering alert): one by ID, those of one device, or all recent ones, newest first;
    kind='attack_disruption': outcomes of automatic attack disruption (advanced hunting, last 30 days). Read-only;
    needs the Defender for Endpoint permissions Machine.ReadWrite / Alert.ReadWrite (granted with the write
    permissions)."""
    if kind == "attack_disruption":
        return await _attack_disruption(device, days, max_items)
    mde = runtime.mde()
    if investigation_id or kind == "investigations":
        return await _investigations(device, investigation_id, days, state, max_items)
    if state:
        raise InputError("state is only valid for kind='investigations'.")
    if action_id:
        res = await mde.get(f"/api/machineactions/{guid(action_id, 'action_id')}")
        return {"machineAction": compact(pick(res, _ACTION_FIELDS))}
    since = iso_days_ago(clamp_int(days, 1, 180, "days"))
    filters = [f"creationDateTimeUtc ge {since}"]
    device_id = None
    if device:
        device_id = device.strip().lower() if kql.is_mde_device_id(device) else (await resolve_device(device))["DeviceId"]
        filters.append(f"machineId eq {odata_str(device_id)}")
    res = await mde.get("/api/machineactions", params={"$filter": " and ".join(filters), "$top": "1000"})
    rows = [compact(pick(a, _ACTION_FIELDS)) for a in res.get("value") or []]
    rows.sort(key=lambda r: str(r.get("creationDateTimeUtc") or ""), reverse=True)
    limit = clamp_int(max_items, 1, 300, "max_items")
    out = {"items": rows[:limit], "count": min(len(rows), limit), "total": len(rows), "truncated": len(rows) > limit}
    if device_id:
        out["deviceId"] = device_id
    return out


async def _attack_disruption(device: Optional[str], days: int, max_items: Optional[int]) -> dict:
    """DisruptionAndResponseEvents: outcomes of automatic attack disruption (only Defender for Endpoint controls;
    the 'contain user' action itself is logged in the Action center)."""
    d = kql.days(days)
    flt = None
    if device:
        v = device.strip()
        if kql.is_mde_device_id(v):
            lit = kql.kql_str(v.lower())
            flt = f"DeviceId =~ {lit} or TargetDeviceId =~ {lit} or SourceDeviceId =~ {lit}"
        else:
            name = kql.device_name(v)
            lit, pre = kql.kql_str(name), kql.kql_str(name + ".")
            flt = " or ".join(f"{c} =~ {lit} or {c} startswith {pre}" for c in ("DeviceName", "TargetDeviceName",
                                                                                 "SourceDeviceName"))
    base = "\n".join(x for x in ["DisruptionAndResponseEvents", f"| where Timestamp > ago({d}d)",
                                  f"| where {flt}" if flt else None] if x)
    ok, errors = await gather_sections({
        "summary": kql.rows(base + "\n| summarize Events = count(), Devices = dcount(DeviceName), "
                            "FirstSeen = min(Timestamp), LastSeen = max(Timestamp), "
                            "ContainedUsers = make_set_if(SourceUserName, isnotempty(SourceUserName), 10), "
                            "Policies = make_set_if(PolicyName, isnotempty(PolicyName), 5) by ActionType, ReportType"
                            "\n| order by LastSeen desc"),
        "events": kql.hunt(base + "\n| project Timestamp, ActionType, ReportType, DeviceName, SourceUserName, "
                           "SourceUserDomainName, SourceDeviceName, SourceIpAddress, TargetDeviceName, IpAddress, Port, "
                           "Service, AuthenticationProtocol, ShareName, FileName, PolicyName, IsPolicyOn"
                           "\n| order by Timestamp desc", max_items=max_items, max_str=300),
    })
    out: dict = {"kind": "attack_disruption", "days": d}
    if "summary" in ok:
        out["summary"] = kql.shape_rows(ok["summary"], limit=30, max_str=300)[0]
    if "events" in ok:
        out["events"] = ok["events"].get("rows", [])
        out["truncated"] = ok["events"].get("truncated", False)
    if errors:
        out["errors"] = errors
    out["note"] = ("Shows the outcomes (blocked logons, ended sessions, applied policies) of Defender for Endpoint "
                   "controls; the containment action itself is listed in the Action center.")
    return out


async def _investigations(device: Optional[str], investigation_id: Optional[str], days: int, state: Optional[str],
                          max_items: Optional[int]) -> dict:
    mde = runtime.mde()
    if investigation_id:
        res = await mde.get(f"/api/investigations/{key(investigation_id, 'investigation_id')}")
        return {"investigation": compact(pick(res, _INVESTIGATION_FIELDS + ("endTime", "cancelledBy")))}
    filters = [f"startTime ge {iso_days_ago(clamp_int(days, 1, 180, 'days'))}"]
    device_id = None
    if device:
        device_id = device.strip().lower() if kql.is_mde_device_id(device) else (await resolve_device(device))["DeviceId"]
        filters.append(f"machineId eq {odata_str(device_id)}")
    if state:
        filters.append(f"state eq {odata_str(state)}")
    res = await mde.get("/api/investigations", params={"$filter": " and ".join(filters), "$top": "1000"})
    rows = [compact(pick(i, _INVESTIGATION_FIELDS + ("endTime",))) for i in res.get("value") or []]
    rows.sort(key=lambda r: str(r.get("startTime") or ""), reverse=True)
    limit = clamp_int(max_items, 1, 300, "max_items")
    by_state: dict = {}
    for r in rows:
        by_state[r.get("state") or "Unknown"] = by_state.get(r.get("state") or "Unknown", 0) + 1
    out = {"kind": "investigations", "items": rows[:limit], "count": min(len(rows), limit), "total": len(rows),
           "byState": by_state, "truncated": len(rows) > limit}
    if device_id:
        out["deviceId"] = device_id
    return out


IndicatorType = Literal["IpAddress", "DomainName", "Url", "FileSha256", "FileSha1", "FileMd5", "CertificateThumbprint"]
IndicatorAction = Literal["Block", "BlockAndRemediate", "AlertAndBlock", "Warn", "Audit", "Alert", "Allowed"]
_FILE_TYPES = {"FileSha256", "FileSha1", "FileMd5"}
_NETWORK_TYPES = {"IpAddress", "DomainName", "Url"}
_INDICATOR_FIELDS = ("id", "indicatorValue", "indicatorType", "action", "title", "severity", "description",
                     "expirationTime", "creationTimeDateTimeUtc", "createdByDisplayName", "createdBy", "generateAlert",
                     "rbacGroupNames", "source")


def _indicator(value: str, indicator_type: Optional[str]) -> tuple[str, str]:
    v = (value or "").strip()
    if indicator_type == "CertificateThumbprint":
        return "CertificateThumbprint", kql.file_hash(v, "sha1")[1]
    if indicator_type in _FILE_TYPES:
        return indicator_type, kql.file_hash(v, indicator_type.removeprefix("File").lower())[1]
    if indicator_type == "IpAddress":
        return "IpAddress", kql.ip_address(v)
    if indicator_type == "Url":
        return "Url", kql.url(v)
    if indicator_type == "DomainName":
        return "DomainName", kql.domain(v)
    try:
        return "IpAddress", kql.ip_address(v)
    except InputError:
        pass
    if v.lower().startswith(("http://", "https://")):
        return "Url", kql.url(v)
    try:
        kind, h = kql.file_hash(v)
        return {"sha256": "FileSha256", "sha1": "FileSha1", "md5": "FileMd5"}[kind], h
    except InputError:
        pass
    return "DomainName", kql.domain(v)


async def _find_indicators(value: str) -> list:
    res = await runtime.mde().get("/api/indicators", params={"$filter": f"indicatorValue eq {odata_str(value, 'indicator', 2000)}"})
    return [compact(pick(i, _INDICATOR_FIELDS)) for i in res.get("value") or []]


@admin_tool(scopes=(MDE_TI_READWRITE,), title="Custom indicators (list, add, delete)", destructive=True,
            immediate=lambda args: args.get("operation") == "list")
async def manage_indicator(
    operation: Annotated[Literal["list", "add", "delete"], "list runs immediately; add and delete need confirmation."],
    indicator: Annotated[Optional[str], "IP address, domain, URL, file hash or certificate thumbprint. list: filter; "
                                        "add: required; delete: deletes all indicators with this value."] = None,
    indicator_type: Annotated[Optional[IndicatorType], "Type; detected automatically when omitted."] = None,
    action: Annotated[Optional[IndicatorAction], "add: Block (default for network), BlockAndRemediate (default for "
                                                 "files), Warn, Audit, Alert, AlertAndBlock or Allowed."] = None,
    title: Annotated[Optional[str], "add: title of the indicator / alert."] = None,
    description: Annotated[Optional[str], "add: description."] = None,
    severity: Annotated[Literal["Informational", "Low", "Medium", "High"], "add: alert severity."] = "Medium",
    expiration_days: Annotated[int, "add: days until the indicator expires (1-365)."] = 90,
    generate_alert: Annotated[bool, "add: create an alert when the indicator matches."] = True,
    device_groups: Annotated[Optional[list[str]], "add: only these device groups (names); default all."] = None,
    indicator_id: Annotated[Optional[str], "delete: indicator ID instead of the value."] = None,
    max_items: MaxItems = 50,
    confirmation_token: ConfirmationToken = None,
) -> dict:
    """Defender for Endpoint custom indicators (IoCs): list them, add one to block, warn, audit or allow an IP,
    domain, URL, file hash or certificate across devices, or delete indicators. Add and delete are two-step.
    Network indicators need network protection on the devices; CIDR ranges are not supported."""
    mde = runtime.mde()
    if operation == "list":
        params = {"$top": str(clamp_int(max_items, 1, 300, "max_items"))}
        if indicator:
            _, value = _indicator(indicator, indicator_type)
            params["$filter"] = f"indicatorValue eq {odata_str(value, 'indicator', 2000)}"
        elif indicator_type:
            params["$filter"] = f"indicatorType eq {odata_str(indicator_type)}"
        res = await mde.get("/api/indicators", params=params)
        rows = [compact(pick(i, _INDICATOR_FIELDS)) for i in res.get("value") or []]
        return {"items": rows, "count": len(rows), "note": "Lists the indicators visible to this app and user."}

    if operation == "delete":
        if indicator_id:
            if not re.match(r"^\d{1,20}$", indicator_id.strip()):
                raise InputError("indicator_id must be numeric.")
            targets = [{"id": indicator_id.strip()}]
            target_key = indicator_id.strip()
        elif indicator:
            _, value = _indicator(indicator, indicator_type)
            targets = await _find_indicators(value)
            if not targets:
                raise InputError(f"No indicator with value {value!r} found.")
            target_key = value
        else:
            raise InputError("delete needs indicator or indicator_id.")
        ids = [str(t.get("id")) for t in targets if t.get("id")]

        async def preview_delete() -> dict:
            return {"indicators": targets, "warning": "The indicators are deleted; blocking/alerting stops."}

        async def execute_delete() -> dict:
            for i in ids:
                await mde.delete(f"/api/indicators/{i}")
            return {"deleted": ids}

        return await two_step(action="indicator.delete", target=target_key, params={"ids": ids},
                              token=confirmation_token, preview=preview_delete, execute=execute_delete)

    # add
    if not indicator:
        raise InputError("add needs indicator.")
    ind_type, value = _indicator(indicator, indicator_type)
    chosen = action or ("BlockAndRemediate" if ind_type in _FILE_TYPES else "Block")
    if chosen == "BlockAndRemediate" and ind_type not in _FILE_TYPES:
        raise InputError("BlockAndRemediate is only valid for file hashes.")
    if chosen == "Warn" and ind_type not in _NETWORK_TYPES:
        raise InputError("Warn is only valid for IP addresses, domains and URLs.")
    if chosen == "Audit" and not generate_alert:
        raise InputError("Audit requires generate_alert=true.")
    days = clamp_int(expiration_days, 1, 365, "expiration_days")
    groups = [g.strip() for g in device_groups or [] if g and g.strip()]
    body = {"indicatorValue": value, "indicatorType": ind_type, "action": chosen,
            "title": truncate((title or f"{chosen} {ind_type} {value}").strip(), 200),
            "description": truncate((description or "Created in Copilot Studio via Defender XDR MCP").strip(), 1000),
            "severity": severity, "generateAlert": bool(generate_alert)}
    if groups:
        body["rbacGroupNames"] = groups
    # The confirmation is bound to the arguments; the expiry timestamp is computed when the indicator is created.
    params = {**body, "expiration_days": days}

    async def preview_add() -> dict:
        out: dict = {"indicator": {**body, "expiresInDays": days}}
        warnings = []
        if chosen == "Allowed":
            warnings.append("Allowed indicators exempt this item from detection and blocking on all targeted devices.")
        if ind_type in _NETWORK_TYPES and chosen in ("Block", "Warn", "AlertAndBlock"):
            warnings.append("Blocking IPs, domains and URLs requires network protection in block mode on the devices.")
        ok, _ = await gather_sections({"existing": _find_indicators(value)})
        if ok.get("existing"):
            out["existing"] = ok["existing"]
            warnings.append("An indicator with this value exists; it is updated with the new settings.")
        if warnings:
            out["warnings"] = warnings
        return out

    async def execute_add() -> dict:
        expires = (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        created = await mde.post("/api/indicators", json_body={**body, "expirationTime": expires})
        return {"indicator": compact(pick(created or {**body, "expirationTime": expires}, _INDICATOR_FIELDS))}

    try:
        return await two_step(action="indicator.add", target=f"{ind_type}:{value}", params=params,
                              token=confirmation_token, preview=preview_add, execute=execute_add)
    except GraphError as exc:
        if exc.status == 400 and "expirationTime" in str(exc):
            raise InputError("Defender rejected the expiration time; try a shorter expiration_days.") from None
        raise
