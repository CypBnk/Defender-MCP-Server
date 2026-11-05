"""Defender Vulnerability Management across the organization."""
from __future__ import annotations

from typing import Annotated, Literal, Optional

from datetime import datetime, timezone

from .. import kql, runtime
from ..errors import InputError
from ..graph.odata import key, odata_str
from ..graph.paging import clamp
from ..scopes import MDE_REMEDIATION_READ, THREAT_HUNTING_READ
from ..shaping import compact, pick, truncate
from ..util import gather_sections
from .common import MaxItems, one_of
from .registry import read_tool

VulnView = Literal["top_cves", "vulnerable_software", "exposed_devices", "missing_updates", "end_of_support",
                   "misconfigurations", "security_baselines", "browser_extensions", "certificates"]
_VIEWS = ("top_cves", "vulnerable_software", "exposed_devices", "missing_updates", "end_of_support", "misconfigurations",
          "security_baselines", "browser_extensions", "certificates")
_NO_CVE_FILTERS = ("misconfigurations", "end_of_support", "security_baselines", "browser_extensions", "certificates")
_EXTENSION_RANK = ('case(ExtensionRisk =~ "Critical", 4, ExtensionRisk =~ "High", 3, ExtensionRisk =~ "Medium", 2, '
                   'ExtensionRisk =~ "Low", 1, 0)')
# ExpirationDate is a string column; weak: short RSA keys or SHA-1 / MD5 signatures
CERT_STATUS = ('| extend Expires = todatetime(ExpirationDate)\n'
               '| extend Status = case(isnull(Expires), "unknown", Expires < now(), "expired", Expires < now() + 30d, '
               '"expires within 30 days", "valid"), Weak = (toint(KeySize) < 2048 and SignatureAlgorithm !contains "ecdsa") or SignatureAlgorithm contains "sha1" or '
               'SignatureAlgorithm contains "md5"')
_RISK_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
SeverityLevel = Literal["Critical", "High", "Medium", "Low"]
_RANK = ('case(Severity == "Critical", 4, Severity == "High", 3, Severity == "Medium", 2, 1)')


def _overview_query(view: str, severity: Optional[str], exploit_only: bool, software: Optional[str] = None) -> str:
    sev = f"| where {kql.min_severity_condition(severity)}" if severity else ""
    if software:   # all CVE / software views filter on vendor and product name
        sev = "\n".join(x for x in [sev, f"| where {kql.software_condition(software)}"] if x)
    if view == "top_cves":
        return "\n".join(x for x in [
            "DeviceTvmSoftwareVulnerabilities", sev,
            "| summarize AffectedDevices = dcount(DeviceId), Software = make_set(SoftwareName, 5), "
            "Severity = take_any(VulnerabilitySeverityLevel) by CveId",
            "| join kind=leftouter (DeviceTvmSoftwareVulnerabilitiesKB | project CveId, CvssScore, IsExploitAvailable, "
            "PublishedDate) on CveId",
            "| where IsExploitAvailable == true" if exploit_only else "",
            f"| extend Rank = {_RANK}",
            "| project CveId, Severity, CvssScore = todouble(CvssScore), IsExploitAvailable, AffectedDevices, Software, "
            "PublishedDate, Rank",
            "| order by Rank desc, AffectedDevices desc, CvssScore desc",
            "| project-away Rank"] if x)
    if view == "vulnerable_software":
        exploit = ("| join kind=inner (DeviceTvmSoftwareVulnerabilitiesKB | where IsExploitAvailable == true "
                   "| project CveId) on CveId") if exploit_only else ""
        return "\n".join(x for x in [
            "DeviceTvmSoftwareVulnerabilities", sev, exploit,
            '| summarize CVEs = dcount(CveId), Critical = dcountif(CveId, VulnerabilitySeverityLevel == "Critical"), '
            'High = dcountif(CveId, VulnerabilitySeverityLevel == "High"), AffectedDevices = dcount(DeviceId), '
            "Versions = make_set(SoftwareVersion, 5) by SoftwareVendor, SoftwareName",
            "| order by Critical desc, High desc, AffectedDevices desc"] if x)
    if view == "exposed_devices":
        exploit = ("| join kind=inner (DeviceTvmSoftwareVulnerabilitiesKB | where IsExploitAvailable == true "
                   "| project CveId) on CveId") if exploit_only else ""
        return "\n".join(x for x in [
            "DeviceTvmSoftwareVulnerabilities", sev, exploit,
            '| summarize Critical = dcountif(CveId, VulnerabilitySeverityLevel == "Critical"), '
            'High = dcountif(CveId, VulnerabilitySeverityLevel == "High"), CVEs = dcount(CveId) '
            "by DeviceId, DeviceName, OSPlatform",
            "| order by Critical desc, High desc, CVEs desc"] if x)
    if view == "missing_updates":
        exploit = ("| join kind=inner (DeviceTvmSoftwareVulnerabilitiesKB | where IsExploitAvailable == true "
                   "| project CveId) on CveId") if exploit_only else ""
        return "\n".join(x for x in [
            "DeviceTvmSoftwareVulnerabilities", "| where isnotempty(RecommendedSecurityUpdate)", sev, exploit,
            '| summarize Devices = dcount(DeviceId), CVEs = dcount(CveId), Critical = dcountif(CveId, '
            'VulnerabilitySeverityLevel == "Critical"), High = dcountif(CveId, VulnerabilitySeverityLevel == "High"), '
            "Software = make_set(SoftwareName, 5) by RecommendedSecurityUpdate, RecommendedSecurityUpdateId",
            "| order by Critical desc, High desc, Devices desc"] if x)
    if view == "browser_extensions":
        floor = f"| where RiskRank >= {_RISK_RANK[severity]}" if severity else ""
        return "\n".join(x for x in [
            "DeviceTvmBrowserExtensions", f"| extend RiskRank = {_EXTENSION_RANK}", floor,
            f"| where ExtensionName contains {kql.kql_str(software, 'software')}" if software else "",
            "| summarize Devices = dcount(DeviceId), ActivatedStates = make_set(IsActivated, 3), "
            "Versions = make_set(ExtensionVersion, 5), FirstInstalled = min(InstallationTime) "
            "by BrowserName, ExtensionName, ExtensionId, ExtensionVendor, ExtensionRisk, RiskRank",
            "| order by RiskRank desc, Devices desc", "| project-away RiskRank"] if x)
    if view == "certificates":
        return "\n".join([
            "DeviceTvmCertificateInfo", CERT_STATUS,
            '| where Status in ("expired", "expires within 30 days") or Weak',
            "| summarize Devices = dcount(DeviceId), Paths = make_set(Path, 3) by Thumbprint, FriendlyName, "
            "IssuedTo = tostring(IssuedTo), IssuedBy = tostring(IssuedBy), Expires, Status, KeySize, SignatureAlgorithm, Weak",
            "| order by Expires asc"])
    if view == "end_of_support":
        return "\n".join(x for x in [
            "DeviceTvmSoftwareInventory", "| where isnotempty(EndOfSupportStatus)",
            f"| where {kql.software_condition(software)}" if software else "",
            "| summarize Devices = dcount(DeviceId), Versions = make_set(SoftwareVersion, 5), "
            "EndOfSupportDate = min(EndOfSupportDate) by SoftwareVendor, SoftwareName, EndOfSupportStatus",
            "| order by Devices desc"] if x)
    return "\n".join([
        "DeviceTvmSecureConfigurationAssessment",
        "| where IsApplicable == 1 and IsCompliant == 0",
        "| summarize NonCompliantDevices = dcount(DeviceId) by ConfigurationId, ConfigurationCategory, "
        "ConfigurationSubcategory, ConfigurationImpact",
        "| join kind=leftouter (DeviceTvmSecureConfigurationAssessmentKB | project ConfigurationId, ConfigurationName, "
        "RiskDescription) on ConfigurationId",
        "| project ConfigurationId, ConfigurationName, ConfigurationCategory, ConfigurationSubcategory, "
        "ConfigurationImpact, NonCompliantDevices, RiskDescription",
        "| order by ConfigurationImpact desc, NonCompliantDevices desc"])


@read_tool(scopes=(THREAT_HUNTING_READ,), title="Vulnerability overview")
async def get_vulnerability_overview(
    view: Annotated[VulnView, "top_cves: CVEs by severity and number of affected devices; vulnerable_software: "
                              "products with the most critical/high CVEs; exposed_devices: devices with the most "
                              "critical/high CVEs; missing_updates: security updates (KBs / versions) that would fix "
                              "the most CVEs on the most devices; end_of_support: software that is or will soon be "
                              "out of support; misconfigurations: failed security configurations by impact and "
                              "number of devices (security recommendations); security_baselines: compliance per "
                              "baseline profile (CIS, STIG) and the most failed checks; browser_extensions: browser "
                              "extensions by risk and number of devices; certificates: expired, expiring (30 days) "
                              "or weak certificates on devices."] = "top_cves",
    severity: Annotated[Optional[SeverityLevel], "Minimum CVE severity, e.g. High = high and critical; for "
                                                 "browser_extensions the minimum extension risk."] = None,
    exploit_available_only: Annotated[bool, "Only CVEs with a public exploit (not for misconfigurations)."] = False,
    software: Annotated[Optional[str], "Only this software, e.g. 'chrome', 'Google Chrome', 'Microsoft Edge' "
                                       "(every word must match vendor or product); not for misconfigurations."] = None,
    max_items: MaxItems = 50,
) -> dict:
    """Organization-wide Defender Vulnerability Management view, most important first. Use get_cve_exposure for
    one CVE and get_device_exposure for one device."""
    one_of(view, _VIEWS, "view")
    if view in _NO_CVE_FILTERS and (severity or exploit_available_only):
        severity = severity if view == "browser_extensions" else None
        exploit_available_only = False
    if view in ("misconfigurations", "security_baselines", "certificates") and software:
        raise InputError(f"software is not valid for view='{view}'.")
    if view == "security_baselines":
        return await _baselines(max_items)
    query = _overview_query(view, severity, exploit_available_only, software)
    return await kql.hunt(query, max_items=max_items, max_str=600, view=view)


async def _baselines(max_items: Optional[int]) -> dict:
    """Security baselines assessment (Defender Vulnerability Management): compliance per profile and the checks
    that fail on the most devices."""
    ok, errors = await gather_sections({
        "profiles": kql.rows("\n".join([
            "DeviceBaselineComplianceAssessment",
            "| where IsApplicable == true and IsExempt != true",
            "| summarize Devices = dcount(DeviceId), NonCompliantDevices = dcountif(DeviceId, IsCompliant == false), "
            "Checks = countif(isnotnull(IsCompliant)), FailedChecks = countif(IsCompliant == false) by ProfileId",
            "| join kind=leftouter (DeviceBaselineComplianceProfiles | summarize ProfileName = take_any(ProfileName), "
            "BaseBenchmark = take_any(BaseBenchmark), BenchmarkVersion = take_any(BenchmarkVersion), "
            "BenchmarkProfileLevel = take_any(BenchmarkProfileLevel) by ProfileId) on ProfileId",
            "| extend CompliancePercent = iff(Checks > 0, round(100.0 * (Checks - FailedChecks) / Checks, 1), real(null))",
            "| project ProfileName, BaseBenchmark, BenchmarkVersion, BenchmarkProfileLevel, Devices, NonCompliantDevices, "
            "CompliancePercent, FailedChecks, ProfileId",
            "| order by CompliancePercent asc nulls last"])),
        "topFailedChecks": kql.hunt("\n".join([
            "DeviceBaselineComplianceAssessment",
            "| where IsApplicable == true and IsExempt != true and IsCompliant == false",
            "| summarize FailedDevices = dcount(DeviceId) by ConfigurationId, ProfileId",
            "| join kind=leftouter (DeviceBaselineComplianceAssessmentKB | summarize ConfigurationName = "
            "take_any(ConfigurationName), ConfigurationCategory = take_any(ConfigurationCategory), "
            "RemediationOptions = take_any(RemediationOptions) by ConfigurationId) on ConfigurationId",
            "| join kind=leftouter (DeviceBaselineComplianceProfiles | summarize ProfileName = take_any(ProfileName) "
            "by ProfileId) on ProfileId",
            "| project ConfigurationName, ConfigurationCategory, ProfileName, FailedDevices, RemediationOptions, "
            "ConfigurationId",
            "| order by FailedDevices desc"]), max_items=max_items, max_str=600),
    })
    out: dict = {"view": "security_baselines"}
    if "profiles" in ok:
        out["profiles"] = kql.shape_rows(ok["profiles"], limit=50, max_str=300)[0]
        if not ok["profiles"]:
            out["hint"] = ("No baseline data: create baseline profiles in the Defender portal (Vulnerability management "
                           "> Baselines assessment; Defender Vulnerability Management add-on or Premium).")
    if "topFailedChecks" in ok:
        out["topFailedChecks"] = ok["topFailedChecks"].get("rows", [])
    if errors:
        out["errors"] = errors
    return out


@read_tool(scopes=(THREAT_HUNTING_READ,), title="CVE exposure")
async def get_cve_exposure(
    cve_id: Annotated[str, "CVE identifier, e.g. CVE-2024-21412."],
    max_items: MaxItems = 50,
) -> dict:
    """One CVE: description, CVSS score, severity, public exploit, publish date and affected software from the
    Defender knowledge base, plus the affected devices with software version and recommended security update."""
    cve = kql.cve_id(cve_id)
    lit = kql.kql_str(cve)
    limit = clamp(max_items)
    tasks = {
        "kb": kql.rows(f"DeviceTvmSoftwareVulnerabilitiesKB\n| where CveId =~ {lit}\n"
                       "| project CveId, VulnerabilitySeverityLevel, CvssScore, IsExploitAvailable, PublishedDate, "
                       "LastModifiedTime, VulnerabilityDescription, AffectedSoftware\n| take 1"),
        "devices": kql.rows(f"let Affected = DeviceTvmSoftwareVulnerabilities | where CveId =~ {lit};\n"
                            "let Total = toscalar(Affected | summarize dcount(DeviceId));\nAffected\n"
                            "| project DeviceId, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, "
                            f"RecommendedSecurityUpdate\n| order by DeviceName asc\n| take {limit + 1}\n"
                            "| extend TotalDevices = Total"),
    }
    ok, errors = await gather_sections(tasks)
    out: dict = {"cve": cve}
    if "kb" in ok:
        out["details"] = kql.shape_rows(ok["kb"], limit=1, max_str=2000)[0][0] if ok["kb"] else None
        if not ok["kb"]:
            out["hint"] = "CVE not in the Defender Vulnerability Management knowledge base."
    if "devices" in ok:
        rows = ok["devices"]
        out["affectedDevices"] = rows[0].get("TotalDevices") if rows else 0
        items, truncated = kql.shape_rows(rows, limit=limit, drop=("TotalDevices",))
        out.update({"devices": items, "count": len(items), "truncated": truncated})
    if errors:
        out["errors"] = errors
    return out


_TASK_FIELDS = ("id", "title", "category", "type", "priority", "status", "createdOn", "dueOn", "requesterEmail",
                "relatedComponent", "targetDevices", "fixedDevices", "rbacGroupNames", "recommendedVersion",
                "recommendedProgram", "completionMethod", "statusLastModifiedOn")
_PRIORITY = {"High": 0, "Medium": 1, "Low": 2}


def _task_row(t: dict, now: datetime) -> dict:
    row = pick(t, _TASK_FIELDS)
    target, fixed = t.get("targetDevices"), t.get("fixedDevices")
    if isinstance(target, (int, float)) and target and isinstance(fixed, (int, float)):
        row["progressPercent"] = round(100 * fixed / target, 1)
    due = str(t.get("dueOn") or "")
    if due and str(t.get("status")) == "Active":
        try:
            row["overdue"] = datetime.fromisoformat(due.replace("Z", "+00:00")) < now
        except ValueError:
            pass
    return compact(row)


@read_tool(scopes=(MDE_REMEDIATION_READ,), title="Vulnerability remediation tasks")
async def get_remediation_tasks(
    task_id: Annotated[Optional[str], "One remediation activity: its details (and exposed devices)."] = None,
    status: Annotated[Optional[Literal["Active", "Completed"]], "List: only this status (default Active)."] = "Active",
    include_devices: Annotated[bool, "With task_id: list the exposed devices of the activity."] = False,
    max_items: MaxItems = 50,
) -> dict:
    """Defender Vulnerability Management remediation activities (tasks created from security recommendations,
    e.g. 'Update Google Chrome'): title, priority, due date, requester, progress (fixed of target devices) and
    overdue flag, most urgent first; or one activity with description and optionally the exposed devices. Use
    get_vulnerability_overview(view='missing_updates') for what still needs a task."""
    mde = runtime.mde()
    now = datetime.now(timezone.utc)
    if task_id:
        tid = key(task_id, "task_id")
        task = await mde.get(f"/api/remediationTasks/{tid}")
        out: dict = {"task": _task_row(task, now), "description": truncate(task.get("description"), 1500),
                     "notes": truncate(task.get("requesterNotes"), 500)}
        if include_devices:
            res = await mde.get(f"/api/remediationTasks/{tid}/machineReferences")
            devices = [compact(pick(d, ("id", "computerDnsName", "osPlatform", "rbacGroupName")))
                       for d in res.get("value") or []]
            limit = clamp(max_items)
            out["exposedDevices"] = {"items": devices[:limit], "count": min(len(devices), limit), "total": len(devices)}
        return compact(out)
    params = {"$top": "10000"}
    if status:
        params["$filter"] = f"status eq {odata_str(status)}"
    res = await mde.get("/api/remediationTasks", params=params)
    rows = [_task_row(t, now) for t in res.get("value") or []]
    rows.sort(key=lambda r: (not r.get("overdue", False), _PRIORITY.get(str(r.get("priority")), 3),
                             str(r.get("dueOn") or "9999")))
    limit = clamp(max_items)
    return {"items": rows[:limit], "count": min(len(rows), limit), "total": len(rows),
            "overdue": sum(1 for r in rows if r.get("overdue")), "truncated": len(rows) > limit}
