"""Defender for Endpoint devices via advanced hunting."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal, Optional

from .. import kql, runtime
from ..errors import InputError
from ..graph.odata import clamp_int, odata_str
from ..graph.paging import clamp
from ..resolve import resolve_device
from ..scopes import MDE_MACHINE_READ, THREAT_HUNTING_READ
from ..shaping import UNTRUSTED_NOTE, compact, pick
from ..util import gather_sections
from .common import Days, DeviceRef, MaxItems, one_of
from .registry import read_tool

OsFamily = Literal["windows", "windows_server", "macos", "linux", "ios", "android"]
_OS = {
    "windows": '(OSPlatform startswith "Windows" and not(OSPlatform startswith "WindowsServer"))',
    "windows_server": 'OSPlatform startswith "WindowsServer"',
    "macos": 'OSPlatform =~ "macOS"',
    "linux": '(OSPlatform =~ "Linux" or isnotempty(OSDistribution))',
    "ios": 'OSPlatform =~ "iOS"',
    "android": 'OSPlatform =~ "Android"',
}
_SENSOR = {
    "active": 'SensorHealthState =~ "Active"',
    "inactive": 'SensorHealthState =~ "Inactive"',
    "impaired": '(isnotempty(SensorHealthState) and SensorHealthState !in~ ("Active", "Inactive"))',
}
_LIST_COLUMNS = ("DeviceId", "DeviceName", "OSPlatform", "OSVersion", "OnboardingStatus", "SensorHealthState",
                 "ExposureLevel", "MachineGroup", "DeviceManualTags", "IsInternetFacing", "LastSeen")


RiskScore = Literal["High", "Medium", "Low", "Informational", "None"]
_MDE_MACHINE_FIELDS = ("id", "computerDnsName", "osPlatform", "version", "healthStatus", "riskScore", "exposureLevel",
                       "deviceValue", "rbacGroupName", "machineTags", "lastSeen", "lastIpAddress", "lastExternalIpAddress",
                       "onboardingStatus", "isAadJoined", "managedBy")


def _parse_time(value: str, name: str) -> datetime:
    raw = str(value).strip()
    try:
        ts = datetime.fromisoformat(raw.replace("Z", "+00:00").replace(" ", "T", 1))
    except ValueError:
        raise InputError(f"{name} must be an ISO 8601 time such as 2026-11-02T08:15:00Z.") from None
    ts = (ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    if ts < datetime.now(timezone.utc) - timedelta(days=31):
        raise InputError(f"{name} is older than 30 days; advanced hunting keeps 30 days of data.")
    return ts


def _lit_time(ts: datetime) -> str:
    return f"datetime({ts.strftime('%Y-%m-%dT%H:%M:%SZ')})"


async def _devices_by_ip(ip: str, seen_at: Optional[str], window_minutes: int, max_items: Optional[int]) -> dict:
    """Devices that used an internal IP around a point in time: network events with this local IP in the window,
    and network adapter reports with this IP (last day before the time). Same idea as the Defender for Endpoint
    'find devices by internal IP' API, but read-only through advanced hunting."""
    ts = _parse_time(seen_at, "seen_at") if seen_at else datetime.now(timezone.utc)
    delta = timedelta(minutes=clamp_int(window_minutes, 1, 720, "window_minutes"))
    lit = kql.kql_str(ip)
    quoted = kql.kql_str(f'"{ip}"')
    at, start, end = _lit_time(ts), _lit_time(ts - delta), _lit_time(ts + delta)
    # distance of the closest record to the requested time: the device that held the address at that moment
    # ranks first, an earlier DHCP holder further down
    dist = f"Distance = min(iff(Timestamp > {at}, Timestamp - {at}, {at} - Timestamp))"
    stats = f"Events = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), {dist}"
    query = "\n".join([
        "union isfuzzy=true",
        f"  (DeviceNetworkEvents | where Timestamp between ({start} .. {end}) | where LocalIP in {kql.ip_list(ip)}",
        f"   | summarize {stats} by DeviceId, DeviceName",
        '   | extend Source = "network events (local IP)"),',
        f"  (DeviceNetworkInfo | where Timestamp between ({_lit_time(ts - timedelta(days=1))} .. {end})",
        f'   | where NetworkAdapterStatus == "Up" and IPAddresses has {lit} and IPAddresses contains {quoted}',
        f"   | summarize {stats} by DeviceId, DeviceName",
        '   | extend Source = "adapter configuration")',
        "| summarize Events = sum(Events), FirstSeen = min(FirstSeen), LastSeen = max(LastSeen), "
        "Distance = min(Distance), Sources = make_set(Source) by DeviceId, DeviceName",
        "| extend MinutesFromSeenAt = round(Distance / 1m, 1)",
        "| order by Distance asc, LastSeen desc",
        "| project-away Distance"])
    result = await kql.hunt(query, max_items=max_items, ip=ip, at=ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            windowMinutes=int(delta.total_seconds() // 60))
    result["hint"] = ("Closest to seen_at first (MinutesFromSeenAt). Several devices can appear when the address "
                      "moved (DHCP) or for VPN/NAT ranges; 'network events (local IP)' is stronger evidence than "
                      "'adapter configuration'.")
    return result


async def _devices_by_risk(risk_score: str, exposure_level: Optional[str], name_contains: Optional[str],
                           device_group: Optional[str], tag: Optional[str], max_items: Optional[int]) -> dict:
    """Machine risk is not in advanced hunting: list machines from the Defender for Endpoint API (Machine.Read)."""
    filters = [f"riskScore eq {odata_str(risk_score)}"]
    if exposure_level:
        filters.append(f"exposureLevel eq {odata_str(exposure_level)}")
    res = await runtime.mde().get("/api/machines", params={"$filter": " and ".join(filters), "$top": "10000"})
    rows = res.get("value") or []
    if name_contains:
        rows = [r for r in rows if str(name_contains).lower() in str(r.get("computerDnsName") or "").lower()]
    if device_group:
        rows = [r for r in rows if str(r.get("rbacGroupName") or "").lower() == str(device_group).lower()]
    if tag:
        rows = [r for r in rows if str(tag).lower() in (str(t).lower() for t in r.get("machineTags") or [])]
    rows.sort(key=lambda r: str(r.get("lastSeen") or ""), reverse=True)
    limit = clamp(max_items)
    items = [compact(pick(r, _MDE_MACHINE_FIELDS)) for r in rows[:limit]]
    return {"riskScore": risk_score, "items": items, "count": len(items), "total": len(rows),
            "truncated": len(rows) > limit or bool(res.get("@odata.nextLink"))}


@read_tool(scopes=(THREAT_HUNTING_READ, MDE_MACHINE_READ), title="Find Defender devices")
async def find_defender_devices(
    name_contains: Annotated[Optional[str], "Part of the device name."] = None,
    os_family: Annotated[Optional[OsFamily], "Operating system family."] = None,
    onboarding_status: Annotated[Optional[Literal["Onboarded", "Can be onboarded", "Unsupported", "Insufficient info"]],
                                 "Defender for Endpoint onboarding status (discovered devices are not onboarded)."] = None,
    sensor_health: Annotated[Optional[Literal["active", "inactive", "impaired"]], "EDR sensor health."] = None,
    exposure_level: Annotated[Optional[Literal["High", "Medium", "Low", "None"]], "Exposure level."] = None,
    internet_facing: Annotated[Optional[bool], "Only internet-facing (true) or not internet-facing (false) devices."] = None,
    not_seen_for_days: Annotated[Optional[int], "Only devices not seen for at least this many days (1-29)."] = None,
    device_group: Annotated[Optional[str], "Only devices in this Defender device group (exact name)."] = None,
    tag: Annotated[Optional[str], "Only devices with this device tag (manual or dynamic)."] = None,
    risk_score: Annotated[Optional[RiskScore], "Only devices with this Defender machine risk (e.g. High); can be "
                                               "combined with exposure_level, name_contains, device_group, tag."] = None,
    ip_address: Annotated[Optional[str], "Internal IP address: which device used it at seen_at (+/- window_minutes)? "
                                         "Not combinable with the other filters."] = None,
    seen_at: Annotated[Optional[str], "With ip_address: ISO 8601 time, e.g. from a firewall log (default: now)."] = None,
    window_minutes: Annotated[int, "With ip_address: minutes before and after seen_at (1-720)."] = 15,
    summary_only: Annotated[bool, "Return counts per OS, onboarding status, sensor health and exposure instead of "
                                  "the list."] = False,
    max_items: MaxItems = 50,
) -> dict:
    """Search devices known to Defender for Endpoint in the last 30 days (onboarded and discovered), filtered
    by name, OS, onboarding status, sensor health, exposure level, internet exposure, last seen, device group,
    tag or machine risk. Returns one row per device with DeviceId, name, OS, onboarding, sensor health,
    exposure, device group, tags and last seen, plus the total number of matches. summary_only=true returns
    counts instead (e.g. 'how many devices have an inactive sensor'). ip_address (+ seen_at) finds the device
    that used an internal IP address at a point in time, e.g. for an address from a firewall or proxy log."""
    if ip_address:
        others = [name_contains, os_family, onboarding_status, sensor_health, exposure_level, internet_facing,
                  not_seen_for_days, device_group, tag, risk_score]
        if any(v is not None for v in others) or summary_only:
            raise InputError("ip_address cannot be combined with other filters or summary_only.")
        return await _devices_by_ip(kql.ip_address(ip_address), seen_at, window_minutes, max_items)
    if seen_at:
        raise InputError("seen_at is only valid together with ip_address.")
    if risk_score:
        unsupported = [os_family, onboarding_status, sensor_health, internet_facing, not_seen_for_days]
        if any(v is not None for v in unsupported) or summary_only:
            raise InputError("risk_score can only be combined with exposure_level, name_contains, device_group and tag.")
        return await _devices_by_risk(one_of(risk_score, ("High", "Medium", "Low", "Informational", "None"),
                                             "risk_score"), exposure_level, name_contains, device_group, tag, max_items)
    conditions = []
    if name_contains:
        conditions.append(f"DeviceName contains {kql.kql_str(name_contains, 'name_contains')}")
    if os_family:
        conditions.append(_OS[one_of(os_family, _OS, "os_family")])
    if onboarding_status:
        conditions.append(f"OnboardingStatus =~ {kql.kql_str(onboarding_status)}")
    if sensor_health:
        conditions.append(_SENSOR[one_of(sensor_health, _SENSOR, "sensor_health")])
    if exposure_level:
        conditions.append(f"ExposureLevel =~ {kql.kql_str(exposure_level)}")
    if internet_facing is not None:
        conditions.append(f"IsInternetFacing == {'true' if internet_facing else 'false'}")
    if not_seen_for_days is not None:
        conditions.append(f"Timestamp < ago({kql.days(not_seen_for_days, 'not_seen_for_days', hi=29)}d)")
    if device_group:
        conditions.append(f"MachineGroup =~ {kql.kql_str(device_group, 'device_group')}")
    if tag:
        t = kql.kql_str(tag, "tag")
        conditions.append(f"(tostring(DeviceManualTags) has {t} or tostring(DeviceDynamicTags) has {t})")
    base = "\n".join(["DeviceInfo", "| where Timestamp > ago(30d)", "| summarize arg_max(Timestamp, *) by DeviceId",
                      "| where isempty(MergedToDeviceId)"] + [f"| where {c}" for c in conditions] +
                     ["| extend LastSeen = Timestamp"])
    if summary_only:
        rows = await kql.rows(base + "\n| summarize Devices = count() by OSPlatform, OnboardingStatus, "
                                     "SensorHealthState, ExposureLevel\n| order by Devices desc\n| take 200")
        total = sum(int(r.get("Devices") or 0) for r in rows)
        return {"total": total, "groups": rows, "count": len(rows)}
    limit = clamp(max_items)
    query = (f"let Devices = {base};\nlet Total = toscalar(Devices | count);\nDevices\n"
             f"| project {', '.join(_LIST_COLUMNS)}\n| order by DeviceName asc\n| take {limit + 1}\n"
             "| extend TotalMatches = Total")
    rows = await kql.rows(query)
    total = rows[0].get("TotalMatches") if rows else 0
    items, truncated = kql.shape_rows(rows, limit=limit, drop=("TotalMatches",))
    result: dict = {"items": items, "count": len(items), "total": total, "truncated": truncated}
    if truncated:
        result["hint"] = "More devices match. Narrow the filters (name_contains, os_family, ...) or use summary_only."
    return result


async def _mde_machine(device_id: str) -> dict:
    """Machine entity (risk score, health status ...) from the Defender for Endpoint API (Machine.Read)."""
    return await runtime.mde().get("/api/machines", params={"$filter": f"id eq {odata_str(device_id)}"})


@read_tool(scopes=(THREAT_HUNTING_READ, MDE_MACHINE_READ), title="Defender device details")
async def get_defender_device(device: DeviceRef) -> dict:
    """Details of one Defender for Endpoint device: OS, onboarding and sensor health, exposure level, machine
    risk score and health status, device group, tags, accounts that signed in during the last 30 days (with
    logon types and local admin), network adapters and IP addresses, alerts of the last 30 days by severity
    (with the latest titles) and open vulnerabilities by severity. Accepts device name, FQDN, Defender device
    ID or Entra device ID; if a name matches several devices the error lists the candidates."""
    dev = await resolve_device(device)
    lit = kql.kql_str(dev["DeviceId"])
    tasks = {
        "machine": _mde_machine(dev["DeviceId"]),
        "logonUsers": kql.rows(f"DeviceLogonEvents\n| where Timestamp > ago(30d)\n| where DeviceId =~ {lit}\n"
                               '| where ActionType == "LogonSuccess" and isnotempty(AccountName) and '
                               'not(AccountName endswith "$")\n'
                               '| where not(AccountDomain in~ ("nt authority", "font driver host", "window manager"))\n'
                               "| summarize Logons = count(), AdminLogons = countif(IsLocalAdmin == true), "
                               "LogonTypes = make_set(LogonType, 5), FirstLogon = min(Timestamp), "
                               "LastLogon = max(Timestamp) by AccountDomain, AccountName\n"
                               "| order by LastLogon desc\n| take 15"),
        "info": kql.rows(f"DeviceInfo\n| where Timestamp > ago(30d)\n| where DeviceId =~ {lit}\n"
                         "| summarize arg_max(Timestamp, LoggedOnUsers, DeviceDynamicTags, ClientVersion, OSArchitecture, "
                         "OSDistribution, IsAzureADJoined) by DeviceId\n| project-away Timestamp"),
        "network": kql.rows(f"DeviceNetworkInfo\n| where Timestamp > ago(7d)\n| where DeviceId =~ {lit}\n"
                            "| summarize arg_max(Timestamp, *) by NetworkAdapterName\n"
                            "| project NetworkAdapterName, NetworkAdapterStatus, IPAddresses, MacAddress, ConnectedNetworks, "
                            "DefaultGateways\n| take 10"),
        "alerts": kql.rows(f"AlertEvidence\n| where Timestamp > ago(30d)\n| where DeviceId =~ {lit}\n| distinct AlertId\n"
                           "| join kind=inner (AlertInfo | where Timestamp > ago(30d)) on AlertId\n"
                           "| summarize arg_max(Timestamp, Title, Severity, ServiceSource) by AlertId\n"
                           "| order by Timestamp desc\n| take 50"),
        "vulnerabilities": kql.rows(f"DeviceTvmSoftwareVulnerabilities\n| where DeviceId =~ {lit}\n"
                                    "| summarize CVEs = dcount(CveId) by VulnerabilitySeverityLevel"),
    }
    ok, errors = await gather_sections(tasks)
    out: dict = {"device": dev}
    machines = (ok.get("machine") or {}).get("value") or []
    if machines:
        out["machine"] = compact(pick(machines[0], ("riskScore", "healthStatus", "exposureLevel", "deviceValue",
                                                    "rbacGroupName", "machineTags", "lastIpAddress",
                                                    "lastExternalIpAddress", "managedBy", "onboardingStatus")))
    if "logonUsers" in ok:
        out["logonUsers30d"] = kql.shape_rows(ok["logonUsers"], limit=15, max_str=200)[0]
    if ok.get("info"):
        out["details"] = {k: v for k, v in ok["info"][0].items() if k != "DeviceId" and v not in (None, "", [], {})}
    if "network" in ok:
        out["networkAdapters"] = kql.shape_rows(ok["network"], limit=10, max_str=500)[0]
    if "alerts" in ok:
        alerts = ok["alerts"]
        by_sev: dict = {}
        for a in alerts:
            by_sev[a.get("Severity") or "Unknown"] = by_sev.get(a.get("Severity") or "Unknown", 0) + 1
        out["alerts30d"] = {"count": len(alerts), "bySeverity": by_sev,
                            "latest": [{k: a.get(k) for k in ("Timestamp", "Title", "Severity", "AlertId")}
                                       for a in alerts[:5]]}
    if "vulnerabilities" in ok:
        out["vulnerabilities"] = {r.get("VulnerabilitySeverityLevel"): r.get("CVEs") for r in ok["vulnerabilities"]}
    if errors:
        out["errors"] = errors
    out["next_steps"] = ("get_device_activity(device, activity=...) for the timeline; get_device_exposure(device, "
                         "view=...) for CVEs, software and misconfigurations; run_device_response for isolation or scans.")
    out["note"] = UNTRUSTED_NOTE
    return out


Activity = Literal["processes", "network", "logons", "files", "registry", "events", "alerts"]
_ACTIVITY = {
    "processes": ("DeviceProcessEvents", ("FileName", "ProcessCommandLine", "InitiatingProcessFileName"),
                  "Timestamp, FileName, FolderPath, ProcessCommandLine, AccountName, InitiatingProcessFileName, "
                  "InitiatingProcessCommandLine, SHA256"),
    "network": ("DeviceNetworkEvents", ("RemoteUrl", "RemoteIP", "InitiatingProcessFileName"),
                "Timestamp, ActionType, RemoteIP, RemotePort, RemoteUrl, Protocol, InitiatingProcessFileName, "
                "InitiatingProcessAccountName"),
    "logons": ("DeviceLogonEvents", ("AccountName", "RemoteIP", "RemoteDeviceName"),
               "Timestamp, ActionType, LogonType, AccountDomain, AccountName, RemoteIP, RemoteDeviceName, IsLocalAdmin, "
               "FailureReason"),
    "files": ("DeviceFileEvents", ("FileName", "FolderPath", "InitiatingProcessFileName"),
              "Timestamp, ActionType, FileName, FolderPath, SHA256, FileOriginUrl, InitiatingProcessFileName, "
              "InitiatingProcessAccountName"),
    "registry": ("DeviceRegistryEvents", ("RegistryKey", "RegistryValueName", "InitiatingProcessFileName"),
                 "Timestamp, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName"),
    "events": ("DeviceEvents", ("ActionType", "FileName", "InitiatingProcessFileName"),
               "Timestamp, ActionType, FileName, FolderPath, ProcessCommandLine, RemoteUrl, InitiatingProcessFileName, "
               "AdditionalFields"),
}


def _window(around: str, minutes: int) -> tuple[str, str, str, str]:
    """KQL datetime literals (built from a parsed value, never from the raw text) for around +/- minutes."""
    raw = str(around).strip()
    try:
        ts = datetime.fromisoformat(raw.replace("Z", "+00:00").replace(" ", "T", 1))
    except ValueError:
        raise InputError("around must be an ISO 8601 time such as 2026-11-02T08:15:00Z.") from None
    ts = (ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    if ts < datetime.now(timezone.utc) - timedelta(days=31):
        raise InputError("around is older than 30 days; advanced hunting keeps 30 days of data.")
    delta = timedelta(minutes=clamp_int(minutes, 1, 720, "window_minutes"))
    start, end = (ts - delta).strftime("%Y-%m-%dT%H:%M:%SZ"), (ts + delta).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"datetime({start})", f"datetime({end})", start, end


async def _device_id(device: str) -> tuple[str, Optional[dict]]:
    if kql.is_mde_device_id(device):
        return device.strip().lower(), None
    dev = await resolve_device(device)
    return dev["DeviceId"], dev


@read_tool(scopes=(THREAT_HUNTING_READ,), title="Device activity timeline")
async def get_device_activity(
    device: DeviceRef,
    activity: Annotated[Activity, "processes: process starts with command lines; network: connections; logons: "
                                  "sign-ins on the device; files: file events; registry: registry changes; events: "
                                  "security control events (AV, ASR, exploit protection ...); alerts: alerts of the device."],
    days: Days = 7,
    contains: Annotated[Optional[str], "Only events whose main fields contain this text (e.g. a process name, "
                                       "remote URL/IP, account, registry key or action type)."] = None,
    around: Annotated[Optional[str], "ISO 8601 time, e.g. the alert time 2026-11-02T08:15:00Z: show the events from "
                                     "window_minutes before to window_minutes after it, oldest first (instead of the "
                                     "last days)."] = None,
    window_minutes: Annotated[int, "With around: minutes before and after (1-720)."] = 30,
    max_items: MaxItems = 50,
) -> dict:
    """Timeline of one device for a single activity type, newest first, optionally filtered by text, or the
    events around a point in time (around + window_minutes, oldest first), e.g. what happened on the device
    shortly before and after an alert."""
    one_of(activity, (*_ACTIVITY, "alerts"), "activity")
    window = _window(around, window_minutes) if around else None
    device_id, dev = await _device_id(device)
    d = kql.days(days)
    lit = kql.kql_str(device_id)
    time_filter = f"| where Timestamp between ({window[0]} .. {window[1]})" if window else f"| where Timestamp > ago({d}d)"
    order = "| order by Timestamp asc" if window else "| order by Timestamp desc"
    if activity == "alerts":
        text = (f"| where Title contains {kql.kql_str(contains, 'contains')}" if contains else "")
        query = "\n".join(x for x in [
            "AlertInfo", time_filter,
            f"| where AlertId in ((AlertEvidence {time_filter} | where DeviceId =~ {lit} | distinct AlertId))",
            text, "| summarize arg_max(Timestamp, *) by AlertId",
            "| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, DetectionSource, AttackTechniques",
            order] if x)
    else:
        table, fields, columns = _ACTIVITY[activity]
        text = ""
        if contains:
            c = kql.kql_str(contains, "contains")
            text = "| where " + " or ".join(f"{f} contains {c}" for f in fields)
        query = "\n".join(x for x in [table, time_filter, f"| where DeviceId =~ {lit}", text,
                                      f"| project {columns}", order] if x)
    meta: dict = {"device": (dev or {}).get("DeviceName") or device_id, "deviceId": device_id, "activity": activity}
    if window:
        meta.update({"from": window[2], "to": window[3]})
    else:
        meta["days"] = d
    return await kql.hunt(query, max_items=max_items, **meta)


Exposure = Literal["vulnerabilities", "software", "configuration", "security_baselines", "browser_extensions",
                   "certificates"]
_SEVERITY_RANK = ('extend SeverityRank = case(VulnerabilitySeverityLevel == "Critical", 4, '
                  'VulnerabilitySeverityLevel == "High", 3, VulnerabilitySeverityLevel == "Medium", 2, 1)')


@read_tool(scopes=(THREAT_HUNTING_READ,), title="Device exposure (CVEs, software, configuration)")
async def get_device_exposure(
    device: DeviceRef,
    view: Annotated[Exposure, "vulnerabilities: CVEs with CVSS, exploit availability and recommended update; "
                              "software: installed software with end-of-support status and number of CVEs; "
                              "configuration: failed security configuration checks; security_baselines: failed "
                              "baseline checks (CIS, STIG) with current and expected value; browser_extensions: "
                              "installed browser extensions with risk; certificates: certificates with expiry and "
                              "weak keys."] = "vulnerabilities",
    severity: Annotated[Optional[Literal["Critical", "High", "Medium", "Low"]], "vulnerabilities: minimum severity, "
                                                                                  "e.g. High = high and critical."] = None,
    software: Annotated[Optional[str], "vulnerabilities / software: only this software, e.g. 'chrome' or "
                                       "'Google Chrome' (every word must match vendor or product)."] = None,
    max_items: MaxItems = 50,
) -> dict:
    """Defender Vulnerability Management view of one device, most important first: vulnerabilities (by severity
    and CVSS), installed software, or failed secure configuration assessments with their risk."""
    one_of(view, ("vulnerabilities", "software", "configuration", "security_baselines", "browser_extensions",
                  "certificates"), "view")
    if software and view not in ("vulnerabilities", "software"):
        raise InputError("software is only valid for view='vulnerabilities' or 'software'.")
    device_id, dev = await _device_id(device)
    lit = kql.kql_str(device_id)
    soft = f"| where {kql.software_condition(software)}" if software else ""
    if view == "vulnerabilities":
        sev = f"| where {kql.min_severity_condition(severity)}" if severity else ""
        query = "\n".join(x for x in [
            "DeviceTvmSoftwareVulnerabilities", f"| where DeviceId =~ {lit}", sev, soft,
            "| join kind=leftouter (DeviceTvmSoftwareVulnerabilitiesKB | project CveId, CvssScore, IsExploitAvailable) on CveId",
            f"| {_SEVERITY_RANK}",
            "| project CveId, VulnerabilitySeverityLevel, CvssScore = todouble(CvssScore), IsExploitAvailable, "
            "SoftwareVendor, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate, SeverityRank",
            "| order by SeverityRank desc, CvssScore desc"] if x)
        drop_rank = True
    elif view == "software":
        query = "\n".join(x for x in [
            "DeviceTvmSoftwareInventory", f"| where DeviceId =~ {lit}", soft,
            f"| join kind=leftouter (DeviceTvmSoftwareVulnerabilities | where DeviceId =~ {lit} "
            "| summarize CVEs = dcount(CveId) by SoftwareName, SoftwareVersion) on SoftwareName, SoftwareVersion",
            "| project SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate, "
            "CVEs = coalesce(CVEs, 0)",
            "| order by CVEs desc, SoftwareName asc"] if x)
        drop_rank = False
    elif view == "security_baselines":
        query = "\n".join([
            "DeviceBaselineComplianceAssessment", f"| where DeviceId =~ {lit}",
            "| where IsApplicable == true and IsExempt != true and IsCompliant == false",
            "| join kind=leftouter (DeviceBaselineComplianceAssessmentKB | summarize ConfigurationName = "
            "take_any(ConfigurationName), ConfigurationCategory = take_any(ConfigurationCategory), "
            "RemediationOptions = take_any(RemediationOptions) by ConfigurationId) on ConfigurationId",
            "| join kind=leftouter (DeviceBaselineComplianceProfiles | summarize ProfileName = take_any(ProfileName) "
            "by ProfileId) on ProfileId",
            "| project ConfigurationName, ConfigurationCategory, ProfileName, CurrentValue, RecommendedValue, "
            "RemediationOptions, ConfigurationId",
            "| order by ConfigurationCategory asc"])
        drop_rank = False
    elif view == "browser_extensions":
        query = "\n".join([
            "DeviceTvmBrowserExtensions", f"| where DeviceId =~ {lit}",
            '| extend RiskRank = case(ExtensionRisk =~ "Critical", 4, ExtensionRisk =~ "High", 3, '
            'ExtensionRisk =~ "Medium", 2, ExtensionRisk =~ "Low", 1, 0)',
            "| project BrowserName, ExtensionName, ExtensionVersion, ExtensionRisk, ExtensionVendor, IsActivated, "
            "InstallationTime, ExtensionId, RiskRank",
            "| order by RiskRank desc, ExtensionName asc", "| project-away RiskRank"])
        drop_rank = False
    elif view == "certificates":
        from .vulnerabilities import CERT_STATUS
        query = "\n".join([
            "DeviceTvmCertificateInfo", f"| where DeviceId =~ {lit}", CERT_STATUS,
            "| project FriendlyName, IssuedTo = tostring(IssuedTo), IssuedBy = tostring(IssuedBy), Expires, Status, "
            "Weak, KeySize, SignatureAlgorithm, Path, Thumbprint",
            "| order by Expires asc"])
        drop_rank = False
    else:
        query = "\n".join([
            "DeviceTvmSecureConfigurationAssessment", f"| where DeviceId =~ {lit}",
            "| where IsApplicable == 1 and IsCompliant == 0",
            "| join kind=leftouter (DeviceTvmSecureConfigurationAssessmentKB | project ConfigurationId, ConfigurationName, "
            "RiskDescription) on ConfigurationId",
            "| project ConfigurationId, ConfigurationName, ConfigurationCategory, ConfigurationSubcategory, "
            "ConfigurationImpact, RiskDescription",
            "| order by ConfigurationImpact desc"])
        drop_rank = False
    result = await kql.hunt(query, max_items=max_items, max_str=600,
                            device=(dev or {}).get("DeviceName") or device_id, deviceId=device_id, view=view)
    if drop_rank:
        for row in result.get("rows", []):
            row.pop("SeverityRank", None)
    return result

