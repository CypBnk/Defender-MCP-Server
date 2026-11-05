"""Shared parameter annotations. FastMCP turns the string metadata of Annotated[...] into
parameter descriptions in the tool schema."""
from typing import Annotated, Iterable, Literal, Optional

from ..errors import InputError

MaxItems = Annotated[int, "Maximum number of items to return in this call (default 50, upper limit 300)."]
Cursor = Annotated[Optional[str], "Paging cursor from a previous response with truncated=true. When a cursor is "
                                  "given, the remaining filter arguments are taken from the cursor."]
DeviceRef = Annotated[str, "The device: device name (short name or FQDN), Defender for Endpoint device ID "
                           "(40 hex characters) or Entra device ID."]
Days = Annotated[int, "Look-back window in days (1-30; advanced hunting keeps 30 days of data)."]
Workspace = Annotated[Optional[str], "Microsoft Sentinel / ISOC workspace (name from list_sentinel_workspaces or "
                                     "workspace ID). Omit for your primary workspace."]
AccountFilter = Annotated[Optional[str], "Only this account: UPN, Entra object ID or on-premises SAM account name."]
DeviceFilter = Annotated[Optional[str], "Only this device: device name (short name or FQDN) or Defender device ID."]
IncidentId = Annotated[str, "Incident ID as shown in the Defender portal (a number, e.g. 29)."]
AlertId = Annotated[str, "Alert ID, e.g. da637551227677560813_-961444813."]
ConfirmationToken = Annotated[Optional[str], "Omit on the first call to get a preview. Only after the user explicitly "
                                             "confirmed the preview, call again with identical arguments plus the "
                                             "confirmation_token from the preview."]
Severity = Literal["informational", "low", "medium", "high"]


def one_of(value: object, allowed: Iterable[str], name: str) -> str:
    """Defense in depth for Literal parameters (FastMCP validates them; direct calls do not)."""
    options = tuple(allowed)
    if value not in options:
        raise InputError(f"{name} must be one of: {', '.join(options)}.")
    return str(value)


def contains(haystack: object, needle: str | None) -> bool:
    if not needle:
        return True
    return needle.strip().lower() in str(haystack or "").lower()
