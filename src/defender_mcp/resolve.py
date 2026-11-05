"""Resolve what the user typed to exactly one object:
- devices (name, FQDN, Defender device ID, Entra device ID) via DeviceInfo in advanced hunting (honours the
  user's device groups);
- users (UPN or Entra object ID) via Microsoft Graph."""
from __future__ import annotations

import struct
import uuid
from typing import Any

from . import kql, runtime
from .errors import AmbiguousError, InputError, NotFoundError
from .graph.odata import guid, is_guid, is_upn, odata_str

DEVICE_COLUMNS = ("DeviceId", "DeviceName", "OSPlatform", "OSVersion", "OSBuild", "OnboardingStatus",
                  "SensorHealthState", "ExposureLevel", "AssetValue", "MachineGroup", "AadDeviceId", "JoinType",
                  "DeviceType", "PublicIP", "IsInternetFacing", "Model", "Vendor", "DeviceManualTags", "LastSeen")
_LOOKBACK_DAYS = 30


def device_summary(row: dict) -> dict:
    return {k: row[k] for k in DEVICE_COLUMNS if row.get(k) not in (None, "", [], {})}


def _describe(row: dict) -> str:
    return (f"{row.get('DeviceName')} | {row.get('OSPlatform') or '-'} | last seen {row.get('LastSeen')} | "
            f"onboarding {row.get('OnboardingStatus') or '-'} | id {row.get('DeviceId')}")


def device_query(condition: str, take: int = 11) -> str:
    return (f"DeviceInfo\n| where Timestamp > ago({_LOOKBACK_DAYS}d)\n| where {condition}\n"
            f"| summarize arg_max(Timestamp, *) by DeviceId\n"
            f"| where isempty(MergedToDeviceId)\n"
            f"| extend LastSeen = Timestamp\n"
            f"| project {', '.join(DEVICE_COLUMNS)}\n"
            f"| order by LastSeen desc\n| take {int(take)}")


async def resolve_device(device: Any) -> dict:
    """Accepts a device name (short or FQDN), Defender device ID (40 hex) or Entra device ID (GUID)."""
    value = str(device or "").strip()
    if not value:
        raise InputError("device must not be empty.")
    if kql.is_mde_device_id(value):
        condition = f"DeviceId =~ {kql.kql_str(value.lower())}"
    elif is_guid(value):
        condition = f"AadDeviceId =~ {kql.kql_str(value.strip('{}').lower())}"
    else:
        condition = kql.device_condition(value)
    rows = await kql.rows(device_query(condition))
    if not rows:
        raise NotFoundError(f"No Defender for Endpoint device '{value}' seen in the last {_LOOKBACK_DAYS} days (or not "
                            "visible to the signed-in user's device groups). Use find_defender_devices(name_contains=...) to search.")
    if len(rows) > 1:
        exact = [r for r in rows if str(r.get("DeviceName") or "").lower() == value.lower()]
        if len(exact) == 1:
            rows = exact
    if len(rows) > 1:
        listing = "; ".join(_describe(r) for r in rows[:10])
        raise AmbiguousError(f"'{value}' matches {len(rows)} devices. Ask the user which one is meant and call again "
                             f"with its DeviceId. Candidates: {listing}")
    return device_summary(rows[0])


# --------------------------------------------------------------------------- users
USER_SELECT = ("id,displayName,userPrincipalName,mail,accountEnabled,userType,jobTitle,department,createdDateTime,"
               "lastPasswordChangeDateTime,onPremisesSyncEnabled,onPremisesSamAccountName,onPremisesDomainName,"
               "onPremisesSecurityIdentifier,signInSessionsValidFromDateTime")


def user_key(user: Any) -> tuple[str, str]:
    """('objectId' | 'upn', value). Users are addressed by UPN or Entra object ID."""
    v = str(user or "").strip()
    if is_guid(v):
        return "objectId", guid(v, "user")
    if is_upn(v):
        return "upn", v
    raise InputError("user must be a UPN (name@contoso.com) or an Entra object ID.")


async def resolve_user(user: Any) -> dict:
    """Entra user by UPN or object ID. UPNs are looked up with $filter, so guest UPNs (#EXT#) work too."""
    kind, value = user_key(user)
    graph = runtime.graph()
    if kind == "objectId":
        return await graph.get(f"/users/{value}", params={"$select": USER_SELECT})
    res = await graph.get("/users", params={"$filter": f"userPrincipalName eq {odata_str(value, 'user')}",
                                            "$select": USER_SELECT})
    found = res.get("value") or []
    if not found:
        raise NotFoundError(f"No Entra user with UPN '{value}'.")
    return found[0]


def entra_sid(object_id: str) -> str:
    """Security identifier Windows uses for an Entra ID account on Entra-joined devices (S-1-12-1-...)."""
    parts = struct.unpack("<IIII", uuid.UUID(object_id).bytes_le)
    return "S-1-12-1-" + "-".join(str(p) for p in parts)
