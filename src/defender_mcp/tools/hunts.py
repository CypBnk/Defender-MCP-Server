"""Prebuilt advanced hunting queries for endpoints, identities, email and cloud apps. Every argument is
validated and inserted as an escaped KQL literal."""
from __future__ import annotations

from typing import Annotated, Literal, Optional
from urllib.parse import urlsplit

from .. import kql
from ..errors import InputError
from ..graph.odata import clamp_int, is_upn
from ..graph.paging import clamp
from ..scopes import THREAT_HUNTING_READ
from ..shaping import UNTRUSTED_NOTE
from ..util import gather_sections
from .common import AccountFilter, Days, DeviceFilter, MaxItems
from .registry import read_tool

MinCount = Annotated[Optional[int], "Threshold for aggregated hunts (e.g. failed attempts per account); "
                                    "a sensible default is used when omitted (1 when an account is given)."]


def _q(*parts: str) -> str:
    return "\n".join(p for p in parts if p)


def _where(condition: Optional[str]) -> str:
    return f"| where {condition}" if condition else ""


def _threshold(value: Optional[int], default: int) -> int:
    return clamp_int(value, 1, 100_000, "min_count") if value is not None else default


# =========================================================================== endpoint
EndpointHunt = Literal["suspicious_powershell", "lolbin_downloads", "new_services", "scheduled_tasks",
                       "antivirus_detections", "asr_events", "tampering_attempts", "local_admin_additions"]


def _endpoint_query(hunt: str, d: int, device: Optional[str], account: Optional[str]) -> str:
    dev = kql.device_condition(device) if device else None
    proc_acc = kql.account_condition(account) if account else None
    init_acc = kql.account_condition(account, upn="InitiatingProcessAccountUpn",
                                     object_id="InitiatingProcessAccountObjectId",
                                     sam="InitiatingProcessAccountName") if account else None
    since = f"| where Timestamp > ago({d}d)"
    if hunt == "suspicious_powershell":
        return _q("DeviceProcessEvents", since,
                  '| where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")',
                  '| where ProcessCommandLine has_any ("encodedcommand", "frombase64string", "downloadstring", '
                  '"downloadfile", "invoke-expression", "invoke-webrequest", "net.webclient", "start-bitstransfer", '
                  '"bypass", "hidden") or ProcessCommandLine matches regex @"(?i)\\s-e(c|n|nc|ncodedcommand)?\\s"',
                  _where(dev), _where(proc_acc),
                  "| project Timestamp, DeviceName, DeviceId, AccountName, AccountUpn, ProcessCommandLine, "
                  "InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256",
                  "| order by Timestamp desc")
    if hunt == "lolbin_downloads":
        return _q("DeviceProcessEvents", since,
                  '| where FileName in~ ("certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", '
                  '"msiexec.exe", "wmic.exe", "cscript.exe", "wscript.exe", "curl.exe", "hh.exe", "installutil.exe")',
                  '| where ProcessCommandLine matches regex @"(?i)(https?|ftp)://|urlcache|/transfer|javascript:|'
                  'vbscript:|scrobj\\.dll"',
                  _where(dev), _where(proc_acc),
                  "| project Timestamp, DeviceName, DeviceId, AccountName, FileName, ProcessCommandLine, "
                  "InitiatingProcessFileName, InitiatingProcessCommandLine",
                  "| order by Timestamp desc")
    if hunt == "new_services":
        return _q("DeviceEvents", since, '| where ActionType == "ServiceInstalled"', _where(dev), _where(init_acc),
                  "| extend Fields = todynamic(AdditionalFields)",
                  "| extend ServiceName = tostring(Fields.ServiceName), ServiceAccount = tostring(Fields.ServiceAccount), "
                  "ServiceStartType = tostring(Fields.ServiceStartType)",
                  "| project Timestamp, DeviceName, DeviceId, ServiceName, FileName, FolderPath, ServiceAccount, "
                  "ServiceStartType, InitiatingProcessFileName, InitiatingProcessAccountName",
                  "| order by Timestamp desc")
    if hunt == "scheduled_tasks":
        return _q("DeviceEvents", since, '| where ActionType == "ScheduledTaskCreated"', _where(dev), _where(init_acc),
                  "| extend Fields = todynamic(AdditionalFields)",
                  "| extend TaskName = tostring(Fields.TaskName), TaskContent = tostring(Fields.TaskContent)",
                  "| project Timestamp, DeviceName, DeviceId, TaskName, TaskContent, InitiatingProcessFileName, "
                  "InitiatingProcessCommandLine, InitiatingProcessAccountName",
                  "| order by Timestamp desc")
    if hunt == "antivirus_detections":
        return _q("DeviceEvents", since, '| where ActionType == "AntivirusDetection"', _where(dev), _where(init_acc),
                  "| extend Fields = todynamic(AdditionalFields)",
                  "| extend ThreatName = tostring(Fields.ThreatName), WasRemediated = tostring(Fields.WasRemediated)",
                  "| project Timestamp, DeviceName, DeviceId, ThreatName, WasRemediated, FileName, FolderPath, SHA1, "
                  "SHA256, InitiatingProcessFileName, InitiatingProcessAccountName",
                  "| order by Timestamp desc")
    if hunt == "asr_events":
        return _q("DeviceEvents", since, '| where ActionType startswith "Asr"', _where(dev), _where(init_acc),
                  "| project Timestamp, DeviceName, DeviceId, ActionType, FileName, FolderPath, ProcessCommandLine, "
                  "InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName",
                  "| order by Timestamp desc")
    if hunt == "tampering_attempts":
        return _q("DeviceEvents", since, '| where ActionType == "TamperingAttempt"', _where(dev), _where(init_acc),
                  "| extend Fields = todynamic(AdditionalFields)",
                  "| extend TamperingAction = tostring(Fields.TamperingAction), Target = tostring(Fields.Target), "
                  "Status = tostring(Fields.Status)",
                  "| project Timestamp, DeviceName, DeviceId, TamperingAction, Target, Status, InitiatingProcessFileName, "
                  "InitiatingProcessCommandLine, InitiatingProcessAccountName",
                  "| order by Timestamp desc")
    if hunt == "local_admin_additions":
        return _q("DeviceEvents", since, '| where ActionType == "UserAccountAddedToLocalGroup"', _where(dev),
                  _where(init_acc),
                  "| extend Fields = todynamic(AdditionalFields)",
                  "| extend GroupName = tostring(Fields.GroupName), GroupSid = tostring(Fields.GroupSid)",
                  '| where GroupSid == "S-1-5-32-544" or GroupName =~ "Administrators"',
                  "| project Timestamp, DeviceName, DeviceId, AddedAccountSid = AccountSid, AddedAccountName = AccountName, "
                  "GroupName, InitiatingProcessAccountName, InitiatingProcessFileName",
                  "| order by Timestamp desc")
    raise InputError(f"Unknown hunt {hunt!r}.")


@read_tool(scopes=(THREAT_HUNTING_READ,), title="Hunt: endpoint threats")
async def hunt_endpoint_threats(
    hunt: Annotated[EndpointHunt, "suspicious_powershell: encoded/download/bypass PowerShell; lolbin_downloads: "
                                  "certutil, mshta, regsvr32 & co. with URLs; new_services: service installations "
                                  "(persistence); scheduled_tasks: created tasks; antivirus_detections: Defender AV "
                                  "detections; asr_events: attack surface reduction blocks/audits; tampering_attempts: "
                                  "attempts to disable Defender; local_admin_additions: accounts added to local "
                                  "Administrators."],
    days: Days = 7,
    device: DeviceFilter = None,
    account: AccountFilter = None,
    max_items: MaxItems = 50,
) -> dict:
    """Prebuilt Defender for Endpoint hunts across all devices (or one device / account), newest first. Each
    result contains the KQL used ('kql'), so it can be refined with run_hunting_query or turned into a custom
    detection rule."""
    d = kql.days(days)
    return await kql.hunt(_endpoint_query(hunt, d, device, account), max_items=max_items, hunt=hunt, days=d)


# =========================================================================== identity
IdentityHunt = Literal["failed_logons", "password_spray", "ldap_reconnaissance", "lateral_movement",
                       "group_membership_changes", "identity_alerts"]
_FAILED = '| where ActionType == "LogonFailed" or LogonType in~ ("Failed logon", "Failed logon with certificate")'


def _device_logon_account(account: str) -> str:
    """DeviceLogonEvents has no UPN or object ID; a UPN is matched by its prefix (usually the SAM account name)."""
    kind, v = kql.account(account)
    if kind == "objectId":
        raise InputError("Device logon events contain no Entra object ID; pass the UPN or the SAM account name.")
    return f"AccountName =~ {kql.kql_str(v.split('@', 1)[0] if kind == 'upn' else v)}"


def _identity_query(hunt: str, d: int, account: Optional[str], min_count: Optional[int]) -> str:
    since = f"| where Timestamp > ago({d}d)"
    acc = kql.account_condition(account) if account else None
    # With an account filter the hunt shows that account's activity, so the default threshold drops to 1.
    if hunt == "failed_logons":
        return _q("IdentityLogonEvents", since, _FAILED, _where(acc),
                  "| summarize FailedAttempts = count(), DistinctIPs = dcount(IPAddress), DistinctDevices = dcount(DeviceName), "
                  "Applications = make_set(Application, 5), FailureReasons = make_set(FailureReason, 5), "
                  "FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountUpn, AccountName",
                  f"| where FailedAttempts >= {_threshold(min_count, 1 if account else 10)}",
                  "| order by FailedAttempts desc")
    if hunt == "password_spray":
        # Spraying is detected across all accounts; an account filter keeps the IPs that also targeted it.
        return _q("IdentityLogonEvents", since, _FAILED, "| where isnotempty(IPAddress)",
                  "| extend Account = iff(isnotempty(AccountUpn), AccountUpn, AccountName)",
                  f"| extend IsTarget = {acc}" if acc else "",
                  "| summarize TargetedAccounts = dcount(Account), FailedAttempts = count(), "
                  + ("FailedOnAccount = countif(IsTarget), " if acc else "")
                  + "SampleAccounts = make_set(Account, 10), Applications = make_set(Application, 5), "
                  "FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by IPAddress, Location",
                  f"| where TargetedAccounts >= {_threshold(min_count, 5)}"
                  + (" and FailedOnAccount > 0" if acc else ""),
                  "| order by TargetedAccounts desc")
    if hunt == "ldap_reconnaissance":
        return _q("IdentityQueryEvents", since, '| where ActionType has "LDAP" or Protocol =~ "Ldap"', _where(acc),
                  "| summarize Queries = count(), DistinctTargets = dcount(QueryTarget), QueryTypes = make_set(QueryType, 10), "
                  "SampleTargets = make_set(QueryTarget, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) "
                  "by AccountUpn, AccountName, DeviceName",
                  f"| where Queries >= {_threshold(min_count, 1 if account else 20)}",
                  "| order by Queries desc")
    if hunt == "lateral_movement":
        # Defender for Identity stopped updating lateral movement path maps in May 2025 (SAM-R collection disabled),
        # so this hunt looks at behaviour: one account signing in over the network / RDP on many devices.
        return _q("DeviceLogonEvents", since,
                  '| where ActionType == "LogonSuccess" and LogonType in ("Network", "RemoteInteractive")',
                  '| where isnotempty(AccountName) and not(AccountName endswith "$")',
                  '| where not(AccountDomain in~ ("nt authority", "font driver host", "window manager"))',
                  _where(_device_logon_account(account) if account else None),
                  "| summarize TargetDevices = dcount(DeviceId), Logons = count(), AdminLogons = countif(IsLocalAdmin == true), "
                  "LogonTypes = make_set(LogonType, 5), SampleDevices = make_set(DeviceName, 10), "
                  "SourceDevices = make_set(RemoteDeviceName, 10), SourceIPs = make_set(RemoteIP, 10), "
                  "FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountDomain, AccountName",
                  f"| where TargetDevices >= {_threshold(min_count, 1 if account else 5)}",
                  "| order by TargetDevices desc, AdminLogons desc")
    if hunt == "group_membership_changes":
        target = (kql.account_condition(account, upn="TargetAccountUpn", object_id="AccountObjectId", sam="AccountName")
                  if account else None)
        return _q("IdentityDirectoryEvents", since, '| where ActionType == "Group Membership changed"',
                  "| extend Fields = todynamic(AdditionalFields)",
                  '| extend ToGroup = tostring(Fields["TO.GROUP"]), FromGroup = tostring(Fields["FROM.GROUP"]), '
                  'Actor = tostring(Fields["ACTOR.ACCOUNT"])',
                  _where(f"({target} or {acc})" if account else None),
                  "| project Timestamp, Actor, AccountUpn, AccountName, TargetAccountUpn, TargetAccountDisplayName, "
                  "ToGroup, FromGroup, DeviceName",
                  "| order by Timestamp desc")
    if hunt == "identity_alerts":
        evidence_acc = (kql.account_condition(account) if account else None)
        scope = (f"| where AlertId in ((AlertEvidence | where Timestamp > ago({d}d) | where {evidence_acc} "
                 f"| distinct AlertId))") if evidence_acc else ""
        return _q("AlertInfo", since,
                  '| where ServiceSource in~ ("Microsoft Defender for Identity", "Microsoft Entra ID Protection", '
                  '"AAD Identity Protection", "Azure AD Identity Protection")',
                  scope,
                  f"| join kind=leftouter (AlertEvidence | where Timestamp > ago({d}d) | where EntityType == \"User\" "
                  "| extend Account = iff(isnotempty(AccountUpn), AccountUpn, AccountName) "
                  "| summarize Accounts = make_set(Account, 10) by AlertId) on AlertId",
                  "| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, AttackTechniques, Accounts",
                  "| order by Timestamp desc")
    raise InputError(f"Unknown hunt {hunt!r}.")


@read_tool(scopes=(THREAT_HUNTING_READ,), title="Hunt: identity threats")
async def hunt_identity_threats(
    hunt: Annotated[IdentityHunt, "failed_logons: accounts with many failed sign-ins (AD and Entra via Defender); "
                                  "password_spray: IPs failing on many accounts; ldap_reconnaissance: accounts/devices "
                                  "with many LDAP queries; lateral_movement: accounts with network/RDP sign-ins "
                                  "on many devices; group_membership_changes: AD group membership changes; "
                                  "identity_alerts: Defender for Identity / Entra ID Protection alerts with accounts."],
    days: Days = 7,
    account: AccountFilter = None,
    min_count: MinCount = None,
    max_items: MaxItems = 50,
) -> dict:
    """Prebuilt Defender for Identity hunts (Active Directory and Entra sign-ins captured by Defender), optionally
    for one account. Aggregated hunts return one row per account or IP with counts, first/last seen and
    samples. Each result contains the KQL used ('kql')."""
    d = kql.days(days)
    return await kql.hunt(_identity_query(hunt, d, account, min_count), max_items=max_items, hunt=hunt, days=d)


# =========================================================================== email
EmailHunt = Literal["threat_summary", "phishing", "malware", "malicious_attachments", "url_clicks", "spoofing",
                    "message_trace", "post_delivery", "campaigns", "teams_threats", "collaboration_files"]


def _email_filters(sender: Optional[str], recipient: Optional[str], subject: Optional[str], *,
                   sender_domain_cols: bool = True, recipient_col: str = "RecipientEmailAddress") -> list[str]:
    out = []
    if sender:
        s = sender.strip()
        if "@" in s:
            if not is_upn(s):
                raise InputError("sender must be an email address or a domain.")
            lit = kql.kql_str(s)
            out.append(f"(SenderFromAddress =~ {lit} or SenderMailFromAddress =~ {lit})" if sender_domain_cols
                       else f"SenderFromAddress =~ {lit}")
        else:
            dom = kql.domain(s)
            out.append(f"(SenderFromDomain =~ {kql.kql_str(dom)} or SenderMailFromDomain =~ {kql.kql_str(dom)})"
                       if sender_domain_cols else f"SenderFromAddress endswith {kql.kql_str('@' + dom)}")
    if recipient:
        r = recipient.strip()
        if not is_upn(r):
            raise InputError("recipient must be an email address.")
        out.append(f"{recipient_col} =~ {kql.kql_str(r)}")
    if subject:
        out.append(f"Subject contains {kql.kql_str(subject, 'subject_contains')}")
    return out


_MAIL_COLUMNS = ("Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress, SenderIPv4, "
                 "RecipientEmailAddress, Subject, ThreatTypes, ThreatNames, DetectionMethods, DeliveryAction, "
                 "DeliveryLocation, LatestDeliveryLocation")


def _email_query(hunt: str, d: int, sender: Optional[str], recipient: Optional[str], subject: Optional[str]) -> str:
    since = f"| where Timestamp > ago({d}d)"
    if hunt == "threat_summary":
        flt = _email_filters(sender, recipient, subject)
        return _q("EmailEvents", since, *[_where(f) for f in flt],
                  '| summarize Total = count(), Phish = countif(ThreatTypes has "Phish"), '
                  'Malware = countif(ThreatTypes has "Malware"), Spam = countif(ThreatTypes has "Spam"), '
                  'Blocked = countif(DeliveryAction == "Blocked"), Junked = countif(DeliveryAction == "Junked"), '
                  'DeliveredWithThreat = countif(DeliveryAction == "Delivered" and isnotempty(ThreatTypes)) '
                  "by Day = bin(Timestamp, 1d)",
                  "| order by Day desc")
    if hunt in ("phishing", "malware"):
        word = "Phish" if hunt == "phishing" else "Malware"
        flt = _email_filters(sender, recipient, subject)
        return _q("EmailEvents", since, f'| where ThreatTypes has "{word}"', *[_where(f) for f in flt],
                  f"| project {_MAIL_COLUMNS}", "| order by Timestamp desc")
    if hunt == "malicious_attachments":
        flt = _email_filters(sender, recipient, None, sender_domain_cols=False)
        return _q("EmailAttachmentInfo", since, "| where isnotempty(ThreatTypes)", *[_where(f) for f in flt],
                  f"| join kind=leftouter (EmailEvents | where Timestamp > ago({d}d) | project NetworkMessageId, "
                  "RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation) on NetworkMessageId, RecipientEmailAddress",
                  _where(f"Subject contains {kql.kql_str(subject, 'subject_contains')}" if subject else None),
                  "| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, FileName, "
                  "FileType, SHA256, ThreatTypes, ThreatNames, DeliveryAction, DeliveryLocation",
                  "| order by Timestamp desc")
    if hunt == "url_clicks":
        if sender or subject:
            raise InputError("url_clicks supports only the recipient filter (the account that clicked).")
        flt = _email_filters(None, recipient, None, recipient_col="AccountUpn")
        return _q("UrlClickEvents", since,
                  '| where isnotempty(ThreatTypes) or IsClickedThrough == true or ActionType contains "Blocked"',
                  *[_where(f) for f in flt],
                  "| project Timestamp, AccountUpn, Url, ActionType, ThreatTypes, DetectionMethods, IsClickedThrough, "
                  "Workload, IPAddress, NetworkMessageId",
                  "| order by Timestamp desc")
    if hunt == "spoofing":
        flt = _email_filters(sender, recipient, subject)
        return _q("EmailEvents", since, *[_where(f) for f in flt],
                  "| extend Auth = todynamic(AuthenticationDetails)",
                  "| extend SPF = tostring(Auth.SPF), DKIM = tostring(Auth.DKIM), DMARC = tostring(Auth.DMARC), "
                  "CompAuth = tostring(Auth.CompAuth)",
                  '| where DMARC =~ "fail" or CompAuth =~ "fail" or SPF =~ "fail"',
                  "| project Timestamp, SenderFromAddress, SenderMailFromAddress, SenderIPv4, RecipientEmailAddress, "
                  "Subject, SPF, DKIM, DMARC, CompAuth, DeliveryAction, ThreatTypes",
                  "| order by Timestamp desc")
    if hunt == "post_delivery":
        flt = _email_filters(sender, recipient, None, sender_domain_cols=False)
        return _q("EmailPostDeliveryEvents", since, *[_where(f) for f in flt],
                  f"| join kind=leftouter (EmailEvents | where Timestamp > ago({d}d) | project NetworkMessageId, "
                  "RecipientEmailAddress, Subject) on NetworkMessageId, RecipientEmailAddress",
                  _where(f"Subject contains {kql.kql_str(subject, 'subject_contains')}" if subject else None),
                  "| project Timestamp, ActionType, Action, ActionTrigger, ActionResult, RecipientEmailAddress, "
                  "SenderFromAddress, Subject, DeliveryLocation, ThreatTypes, DetectionMethods, NetworkMessageId",
                  "| order by Timestamp desc")
    if hunt == "campaigns":
        sender_flt = _email_filters(sender, None, subject, sender_domain_cols=False)
        recipient_flt = _email_filters(None, recipient, None)
        return _q("CampaignInfo", since, *[_where(f) for f in recipient_flt],
                  f"| join kind=leftouter (EmailEvents | where Timestamp > ago({d}d) | project NetworkMessageId, "
                  "RecipientEmailAddress, SenderFromAddress, Subject, DeliveryAction, LatestDeliveryLocation) "
                  "on NetworkMessageId, RecipientEmailAddress",
                  *[_where(f) for f in sender_flt],
                  "| summarize Messages = dcount(NetworkMessageId), Recipients = dcount(RecipientEmailAddress), "
                  'Delivered = dcountif(NetworkMessageId, DeliveryAction == "Delivered"), '
                  'StillInInbox = dcountif(NetworkMessageId, LatestDeliveryLocation has "Inbox"), '
                  "Senders = make_set(SenderFromAddress, 5), Subjects = make_set(Subject, 3), FirstSeen = min(Timestamp), "
                  "LastSeen = max(Timestamp) by CampaignId, CampaignName, CampaignType, CampaignSubtype",
                  "| order by Recipients desc")
    if hunt == "teams_threats":
        flt = []
        if sender:
            s = sender.strip()
            flt.append(f"SenderEmailAddress =~ {kql.kql_str(s)}" if "@" in s
                       else f"SenderEmailAddress endswith {kql.kql_str('@' + kql.domain(s))}")
        if recipient:
            if not is_upn(recipient.strip()):
                raise InputError("recipient must be an email address.")
            flt.append(f"tostring(RecipientDetails) contains {kql.kql_str(recipient.strip())}")
        if subject:
            flt.append(f"MessageSubject contains {kql.kql_str(subject, 'subject_contains')}")
        return _q("MessageEvents", since, "| where isnotempty(ThreatTypes)", *[_where(f) for f in flt],
                  "| project Timestamp, SenderEmailAddress, SenderDisplayName, SenderType, IsExternalThread, GroupName, "
                  "ThreadSubtype, MessageSubject, ThreatTypes, DetectionMethods, ConfidenceLevel, DeliveryAction, "
                  "DeliveryLocation, SafetyTip, RecipientDetails, TeamsMessageId",
                  "| order by Timestamp desc")
    if hunt == "collaboration_files":
        if sender or subject:
            raise InputError("collaboration_files supports only the recipient filter (file owner or last modifier).")
        owner = None
        if recipient:
            if not is_upn(recipient.strip()):
                raise InputError("recipient must be an email address (UPN of the file owner or modifier).")
            lit = kql.kql_str(recipient.strip())
            owner = f"FileOwnerUpn =~ {lit} or LastModifyingAccountUpn =~ {lit}"
        return _q("FileMaliciousContentInfo", since, _where(owner),
                  "| project Timestamp, Workload, FileName, FolderPath, FileSize, SHA256, ThreatNames, ThreatTypes, "
                  "DetectionMethods, FileOwnerUpn, LastModifyingAccountUpn, LastModifiedTime",
                  "| order by Timestamp desc")
    if hunt == "message_trace":
        flt = _email_filters(sender, recipient, subject)
        if not flt:
            raise InputError("message_trace needs at least one of sender, recipient or subject_contains.")
        return _q("EmailEvents", since, *[_where(f) for f in flt],
                  "| project Timestamp, NetworkMessageId, InternetMessageId, EmailDirection, SenderFromAddress, "
                  "SenderMailFromAddress, SenderIPv4, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, "
                  "LatestDeliveryLocation, ThreatTypes, AttachmentCount, UrlCount",
                  "| order by Timestamp desc")
    raise InputError(f"Unknown hunt {hunt!r}.")


@read_tool(scopes=(THREAT_HUNTING_READ,), title="Hunt: email threats")
async def hunt_email_threats(
    hunt: Annotated[EmailHunt, "threat_summary: daily counts (phish, malware, spam, blocked, delivered with threat); "
                               "phishing / malware: detected emails; malicious_attachments: attachments with threats; "
                               "url_clicks: Safe Links clicks on malicious or blocked URLs; spoofing: SPF/DMARC/CompAuth "
                               "failures; message_trace: all emails matching the filters (needs a filter); "
                               "post_delivery: zero-hour auto purge (ZAP) and manual remediation after delivery; "
                               "campaigns: email campaigns with recipients, delivered and still in inbox; "
                               "teams_threats: Teams messages with threats; collaboration_files: malicious files in "
                               "SharePoint, OneDrive and Teams."],
    days: Days = 7,
    sender: Annotated[Optional[str], "Sender email address or sender domain."] = None,
    recipient: Annotated[Optional[str], "Recipient email address (for url_clicks: the account that clicked)."] = None,
    subject_contains: Annotated[Optional[str], "Part of the subject (case-insensitive)."] = None,
    max_items: MaxItems = 50,
) -> dict:
    """Prebuilt Defender for Office 365 hunts on email (events, attachments, Safe Links clicks, post-delivery
    actions, campaigns), Microsoft Teams messages and malicious files in SharePoint, OneDrive and Teams, newest
    first, optionally filtered by sender, recipient and subject. Email results include NetworkMessageId and the
    current delivery location (LatestDeliveryLocation). Each result contains the KQL used ('kql')."""
    d = kql.days(days)
    return await kql.hunt(_email_query(hunt, d, sender, recipient, subject_contains), max_items=max_items,
                          hunt=hunt, days=d)


# =========================================================================== cloud apps
CloudHunt = Literal["activity_summary", "account_activity", "oauth_consents", "mass_downloads", "admin_activity",
                    "impossible_travel_alerts", "oauth_apps"]


def _cloud_account(account: str) -> str:
    kind, v = kql.account(account)
    lit = kql.kql_str(v)
    if kind == "upn":
        return f"(AccountId =~ {lit} or tostring(RawEventData.UserId) =~ {lit})"
    if kind == "objectId":
        return f"AccountObjectId =~ {lit}"
    raise InputError("For cloud app activity pass the UPN or the Entra object ID of the account.")


def _cloud_query(hunt: str, d: int, account: Optional[str], application: Optional[str], min_count: Optional[int]) -> str:
    since = f"| where Timestamp > ago({d}d)"
    acc = _cloud_account(account) if account else None
    app = f"Application =~ {kql.kql_str(application, 'application')}" if application else None
    if hunt == "activity_summary":
        return _q("CloudAppEvents", since, _where(app), _where(acc),
                  "| summarize Events = count(), Accounts = dcount(AccountObjectId), LastSeen = max(Timestamp) "
                  "by Application, ActionType",
                  "| order by Events desc")
    if hunt == "account_activity":
        if not account:
            raise InputError("account_activity needs the account parameter.")
        return _q("CloudAppEvents", since, _where(app), _where(acc),
                  "| project Timestamp, Application, ActionType, ObjectName, IPAddress, CountryCode, City, Isp, "
                  "IsAnonymousProxy, UserAgent, UncommonForUser",
                  "| order by Timestamp desc")
    if hunt == "oauth_consents":
        return _q("CloudAppEvents", since,
                  '| where ActionType has_any ("Consent to application", "Add OAuth2PermissionGrant", '
                  '"Add delegated permission grant", "Add app role assignment")',
                  _where(app), _where(acc),
                  "| project Timestamp, ActionType, Application, AccountDisplayName, AccountId, ObjectName, IPAddress, "
                  "CountryCode, City",
                  "| order by Timestamp desc")
    if hunt == "mass_downloads":
        return _q("CloudAppEvents", since,
                  '| where ActionType in~ ("FileDownloaded", "FileSyncDownloadedFull", "FileUploaded")',
                  _where(app), _where(acc),
                  '| summarize Downloads = countif(ActionType != "FileUploaded"), Uploads = countif(ActionType == "FileUploaded"), '
                  "DistinctFiles = dcount(ObjectName), IPs = make_set(IPAddress, 5), FirstSeen = min(Timestamp), "
                  "LastSeen = max(Timestamp) by AccountDisplayName, AccountId, Application",
                  f"| where Downloads >= {_threshold(min_count, 100)} or Uploads >= {_threshold(min_count, 100)}",
                  "| order by Downloads desc")
    if hunt == "admin_activity":
        return _q("CloudAppEvents", since, "| where IsAdminOperation == true", _where(app), _where(acc),
                  "| project Timestamp, Application, ActionType, AccountDisplayName, AccountId, ObjectName, IPAddress, "
                  "CountryCode",
                  "| order by Timestamp desc")
    if hunt == "oauth_apps":
        if account:
            raise InputError("oauth_apps lists applications; use application to filter by app name.")
        name = f"AppName contains {kql.kql_str(application, 'application')}" if application else None
        return _q("OAuthAppInfo", "| summarize arg_max(Timestamp, *) by OAuthAppId",
                  '| where AppStatus == "Enabled"', _where(name),
                  '| extend PrivilegeRank = case(PrivilegeLevel =~ "High", 3, PrivilegeLevel =~ "Medium", 2, '
                  'PrivilegeLevel =~ "Low", 1, 0)',
                  "| project AppName, OAuthAppId, PrivilegeLevel, RiskScore, "
                  "VerifiedPublisher = coalesce(tostring(VerifiedPublisher.DisplayName), tostring(VerifiedPublisher.displayName)), IsAdminConsented, ConsentedUsersCount, "
                  "AppOrigin, AppOwnerTenantId, LastUsedTime, UnusedFor90Days = isnull(LastUsedTime) or "
                  "LastUsedTime < ago(90d), AddedOnTime, AssignedRoles, "
                  "HighPrivilegePermissions = countof(tolower(tostring(Permissions)), '\"privilegelevel\":\"high\"'), PrivilegeRank",
                  "| order by PrivilegeRank desc, RiskScore desc",
                  "| project-away PrivilegeRank")
    if hunt == "impossible_travel_alerts":
        evidence_acc = (kql.account_condition(account, sam=None) if account else None)
        scope = (f"| where AlertId in ((AlertEvidence | where Timestamp > ago({d}d) | where {evidence_acc} "
                 f"| distinct AlertId))") if evidence_acc else ""
        return _q("AlertInfo", since,
                  '| where Title has_any ("Impossible travel", "infrequent country", "Atypical travel", '
                  '"Activity from anonymous IP")',
                  scope,
                  f"| join kind=leftouter (AlertEvidence | where Timestamp > ago({d}d) "
                  "| where EntityType in~ (\"User\", \"Ip\") "
                  "| summarize Accounts = make_set_if(AccountUpn, isnotempty(AccountUpn), 10), "
                  "IPs = make_set_if(RemoteIP, isnotempty(RemoteIP), 10) by AlertId) on AlertId",
                  "| project Timestamp, AlertId, Title, Severity, ServiceSource, Accounts, IPs",
                  "| order by Timestamp desc")
    raise InputError(f"Unknown hunt {hunt!r}.")


@read_tool(scopes=(THREAT_HUNTING_READ,), title="Hunt: cloud app activity")
async def hunt_cloud_app_activity(
    hunt: Annotated[CloudHunt, "activity_summary: events per app and action; account_activity: one account's "
                               "activities with IP, country and user agent (needs account); oauth_consents: app "
                               "consents and permission grants; mass_downloads: accounts with many downloads/uploads; "
                               "admin_activity: administrative operations; impossible_travel_alerts: impossible "
                               "travel / infrequent country alerts with accounts and IPs; oauth_apps: OAuth app "
                               "inventory of app governance (privilege level, risk score, verified publisher, admin "
                               "consent, unused apps), most privileged first."],
    days: Days = 7,
    account: Annotated[Optional[str], "Only this account: UPN or Entra object ID."] = None,
    application: Annotated[Optional[str], "Only this application, e.g. 'Microsoft SharePoint Online'."] = None,
    min_count: MinCount = None,
    max_items: MaxItems = 50,
) -> dict:
    """Prebuilt Defender for Cloud Apps hunts on CloudAppEvents (Microsoft 365 and connected SaaS apps), related
    alerts and the OAuth app inventory of app governance (OAuthAppInfo). Each result contains the KQL used ('kql')."""
    d = kql.days(days)
    return await kql.hunt(_cloud_query(hunt, d, account, application, min_count), max_items=max_items, hunt=hunt,
                          days=d)


# =========================================================================== indicators of compromise
IndicatorType = Literal["auto", "ip", "domain", "url", "sha256", "sha1", "md5"]


def _detect(indicator: str, indicator_type: str) -> tuple[str, str]:
    value = (indicator or "").strip()
    if indicator_type == "ip":
        return "ip", kql.ip_address(value)
    if indicator_type == "domain":
        return "domain", kql.domain(value)
    if indicator_type == "url":
        return "url", kql.url(value)
    if indicator_type in ("sha256", "sha1", "md5"):
        return kql.file_hash(value, indicator_type)
    # auto
    try:
        return "ip", kql.ip_address(value)
    except InputError:
        pass
    if value.lower().startswith(("http://", "https://")):
        return "url", kql.url(value)
    try:
        return kql.file_hash(value)
    except InputError:
        pass
    return "domain", kql.domain(value)


def _remote_condition(kind: str, value: str) -> str:
    """Condition on RemoteUrl / RemoteIP for a domain or the host of a URL."""
    host = value if kind == "domain" else (urlsplit(value).hostname or "")
    try:
        return f"RemoteUrl has {kql.kql_str(kql.domain(host), 'indicator')}"
    except InputError:  # URL with an IP address as host
        return f"RemoteIP in {kql.ip_list(kql.ip_address(host))}"


def _hash_condition(kind: str, value: str, sha1: Optional[str] = None, prefix: str = "") -> str:
    """Hash match; for SHA256 also the SHA1 of the file (Learn: SHA256 is often not populated in the Device*
    tables and AlertEvidence, 'use the SHA1 column when available')."""
    col = {"sha256": "SHA256", "sha1": "SHA1", "md5": "MD5"}[kind]
    cond = f"{prefix}{col} == {kql.kql_str(value, 'indicator')}"
    return f"{cond} or {prefix}SHA1 == {kql.kql_str(sha1)}" if sha1 and kind == "sha256" else cond


def _alert_condition(kind: str, value: str, sha1: Optional[str] = None) -> Optional[str]:
    """AlertEvidence condition for the indicator (AlertEvidence has no MD5 column)."""
    if kind == "ip":
        return f"RemoteIP in {kql.ip_list(value)}"
    if kind in ("domain", "url"):
        return _remote_condition(kind, value)
    if kind in ("sha1", "sha256"):
        return _hash_condition(kind, value, sha1)
    return None


def _legs(kind: str, value: str, d: int, sha1: Optional[str] = None) -> list[str]:
    lit = kql.kql_str(value, "indicator", 2000)
    t = f"where Timestamp > ago({d}d)"
    if kind == "ip":
        ips = kql.ip_list(value)   # Device* tables can hold IPv4 addresses IPv4-mapped (::ffff:a.b.c.d)
        return [
            f'(DeviceNetworkEvents | {t} | where RemoteIP in {ips} or LocalIP in {ips} | extend Source = "DeviceNetworkEvents", '
            'Entity = DeviceName, Detail = strcat(ActionType, " ", RemoteUrl, ":", RemotePort, " by ", InitiatingProcessFileName))',
            f'(DeviceLogonEvents | {t} | where RemoteIP in {ips} | extend Source = "DeviceLogonEvents", Entity = DeviceName, '
            'Detail = strcat(ActionType, " ", LogonType, " ", AccountDomain, "\\\\", AccountName))',
            f'(IdentityLogonEvents | {t} | where IPAddress == {lit} | extend Source = "IdentityLogonEvents", '
            'Entity = iff(isnotempty(AccountUpn), AccountUpn, AccountName), Detail = strcat(ActionType, " ", Application, " ", LogonType))',
            f'(CloudAppEvents | {t} | where IPAddress == {lit} | extend Source = "CloudAppEvents", Entity = AccountDisplayName, '
            'Detail = strcat(Application, " ", ActionType))',
            f'(EmailEvents | {t} | where SenderIPv4 == {lit} or SenderIPv6 == {lit} | extend Source = "EmailEvents", '
            'Entity = RecipientEmailAddress, Detail = strcat(SenderFromAddress, " | ", Subject))',
            f'(UrlClickEvents | {t} | where IPAddress == {lit} | extend Source = "UrlClickEvents", Entity = AccountUpn, Detail = Url)',
            f'(AlertEvidence | {t} | where {_alert_condition(kind, value)} | extend Source = "AlertEvidence", '
            'Entity = iff(isnotempty(DeviceName), DeviceName, AccountUpn), Detail = Title)',
        ]
    if kind in ("domain", "url"):
        remote = _remote_condition(kind, value)
        host_cond = remote[len("RemoteUrl "):] if remote.startswith("RemoteUrl ") else None
        url_cond = f"Url =~ {lit}" if kind == "url" else f"Url {host_cond}"
        email_cond = url_cond if kind == "url" else f"({url_cond} or UrlDomain =~ {lit})"
        legs = [
            f'(DeviceNetworkEvents | {t} | where {remote} | extend Source = "DeviceNetworkEvents", '
            'Entity = DeviceName, Detail = strcat(ActionType, " ", RemoteUrl, " ", RemoteIP, " by ", InitiatingProcessFileName))',
            f'(EmailUrlInfo | {t} | where {email_cond} | extend Source = "EmailUrlInfo", '
            'Entity = NetworkMessageId, Detail = Url)',
            f'(UrlClickEvents | {t} | where {url_cond} | extend Source = "UrlClickEvents", Entity = AccountUpn, '
            'Detail = strcat(ActionType, " ", Url))',
            f'(AlertEvidence | {t} | where {remote} | extend Source = "AlertEvidence", '
            'Entity = iff(isnotempty(DeviceName), DeviceName, AccountUpn), Detail = Title)',
        ]
        if kind == "domain":
            legs.append(f'(EmailEvents | {t} | where SenderFromDomain =~ {lit} or SenderMailFromDomain =~ {lit} '
                        '| extend Source = "EmailEvents (sender)", Entity = RecipientEmailAddress, '
                        'Detail = strcat(SenderFromAddress, " | ", Subject))')
        return legs
    cond = _hash_condition(kind, value, sha1)
    proc = f"{cond} or {_hash_condition(kind, value, sha1, 'InitiatingProcess')}"
    legs = [
        f'(DeviceFileEvents | {t} | where {cond} | extend Source = "DeviceFileEvents", Entity = DeviceName, '
        'Detail = strcat(ActionType, " ", FolderPath))',
        f'(DeviceProcessEvents | {t} | where {proc} | extend Source = '
        '"DeviceProcessEvents", Entity = DeviceName, Detail = strcat(FileName, " ", ProcessCommandLine))',
        f'(DeviceImageLoadEvents | {t} | where {cond} | extend Source = "DeviceImageLoadEvents", Entity = DeviceName, '
        'Detail = strcat(FolderPath, " loaded by ", InitiatingProcessFileName))',
        f'(DeviceEvents | {t} | where {cond} | extend Source = "DeviceEvents", Entity = DeviceName, '
        'Detail = strcat(ActionType, " ", FolderPath))',
    ]
    if kind in ("sha256", "sha1"):
        legs.append(f'(AlertEvidence | {t} | where {_alert_condition(kind, value, sha1)} | extend Source = "AlertEvidence", '
                    'Entity = iff(isnotempty(DeviceName), DeviceName, AccountUpn), Detail = Title)')
    if kind == "sha256":
        legs.append(f'(EmailAttachmentInfo | {t} | where SHA256 == {lit} | extend Source = "EmailAttachmentInfo", '
                    'Entity = RecipientEmailAddress, Detail = strcat(FileName, " from ", SenderFromAddress))')
    return legs


def _file_profile_query(kind: str, value: str) -> str:
    column = kind.upper()
    return (f"print {column} = {kql.kql_str(value)}\n| invoke FileProfile({kql.kql_str(column)}, 1)\n"
            "| project SHA1, SHA256, FileSize, GlobalPrevalence, GlobalFirstSeen, GlobalLastSeen, Signer, Issuer, "
            "IsCertificateValid, IsRootSignerMicrosoft, SignatureState, IsExecutable, ThreatName, Publisher, "
            "SoftwareName, ProfileAvailability")


def _profile_sha1(rows: Optional[list]) -> Optional[str]:
    """SHA1 from a FileProfile row, only if it is a valid SHA1 (unknown files have no profile)."""
    value = str((rows or [{}])[0].get("SHA1") or "").strip().lower()
    return value if len(value) == 40 and all(c in "0123456789abcdef" for c in value) else None


@read_tool(scopes=(THREAT_HUNTING_READ,), title="Hunt: indicator of compromise")
async def hunt_ioc(
    indicator: Annotated[str, "IP address, domain, URL or file hash (SHA256, SHA1, MD5)."],
    indicator_type: Annotated[IndicatorType, "Type of the indicator; auto detects it."] = "auto",
    days: Annotated[int, "Look-back window in days (1-30)."] = 30,
    max_items: MaxItems = 50,
) -> dict:
    """Search one indicator of compromise across devices, identities, cloud apps, email and alert evidence.
    Returns hits per data source (count, first/last
    seen, number of distinct devices/accounts), the devices that saw it (organization prevalence), the alerts
    whose evidence contains it and the most recent matching events; for SHA1/SHA256 also the file profile (global
    prevalence, first seen, signer, certificate, detection name). A SHA256 is also searched by the file's SHA1 from
    the profile (many tables record only the SHA1). Missing data sources (not licensed) are
    skipped. Use get_threat_intelligence for the global reputation of an IP, domain or URL."""
    kind, value = _detect(indicator, indicator_type)
    d = kql.days(days)
    profile_q = _file_profile_query(kind, value) if kind in ("sha1", "sha256") else None
    ok: dict = {}
    errors: dict = {}
    sha1 = None
    if kind == "sha256":
        # SHA256 is often empty in the Device* tables and AlertEvidence: first get the SHA1 from the file profile,
        # then search both hashes
        ok, errors = await gather_sections({"fileProfile": kql.rows(profile_q)})
        sha1 = _profile_sha1(ok.get("fileProfile"))
    union = "union isfuzzy=true\n  " + ",\n  ".join(_legs(kind, value, d, sha1))
    base = _q(union, "| project Timestamp, Source, Entity, Detail")
    summary_q = _q(base, "| summarize Hits = count(), DistinctEntities = dcount(Entity), FirstSeen = min(Timestamp), "
                         "LastSeen = max(Timestamp), Entities = make_set(Entity, 10) by Source", "| order by Hits desc")
    limit = clamp(max_items)
    events_q = _q(base, f"| top {limit + 1} by Timestamp desc")
    tasks = {"summary": kql.rows(summary_q), "events": kql.rows(events_q),
             # organization prevalence: every device that saw the indicator (file, process, network ... events)
             "devices": kql.rows(_q(base, '| where Source startswith "Device"',
                                    "| summarize Hits = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), "
                                    "Sources = make_set(Source, 5) by DeviceName = Entity",
                                    "| order by LastSeen desc", "| take 50"))}
    alert_cond = _alert_condition(kind, value, sha1)
    if alert_cond:
        tasks["alerts"] = kql.rows(_q(
            "AlertInfo", f"| where Timestamp > ago({d}d)",
            f"| where AlertId in ((AlertEvidence | where Timestamp > ago({d}d) | where {alert_cond} | distinct AlertId))",
            "| summarize arg_max(Timestamp, Title, Severity, Category, ServiceSource, DetectionSource) by AlertId",
            "| order by Timestamp desc", "| take 25"))
    if kind == "sha1":
        tasks["fileProfile"] = kql.rows(profile_q)
    ok2, errors2 = await gather_sections(tasks)
    ok.update(ok2)
    errors.update(errors2)
    out: dict = {"indicator": value, "type": kind, "days": d}
    if sha1:
        out["alsoSearchedSha1"] = sha1
    if "summary" in ok:
        out["bySource"] = ok["summary"]
        out["totalHits"] = sum(int(r.get("Hits") or 0) for r in ok["summary"])
    if "events" in ok:
        rows, truncated = kql.shape_rows(ok["events"], limit=limit, max_str=500)
        out.update({"events": rows, "truncated": truncated})
    if ok.get("fileProfile"):
        out["fileProfile"] = kql.shape_rows(ok["fileProfile"], limit=1, max_str=300)[0][0]
    if "devices" in ok:
        devices = kql.shape_rows(ok["devices"], limit=50, max_str=200)[0]
        out["devices"] = {"count": len(devices), "items": devices}
    if "alerts" in ok:
        out["alerts"] = kql.shape_rows(ok["alerts"], limit=25, max_str=300)[0]
    if errors:
        out["errors"] = errors
    out["kql"] = summary_q
    out["note"] = UNTRUSTED_NOTE
    if not out.get("totalHits") and "summary" in ok:
        out["hint"] = "No hits in the searched tables. Check the spelling or widen days (max 30)."
    return out
