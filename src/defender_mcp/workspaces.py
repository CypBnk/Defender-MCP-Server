"""Microsoft Sentinel / ISOC workspaces for advanced hunting.

In the Defender portal (Microsoft Sentinel or the Integrated SOC, ISOC) advanced hunting also reaches the tables of
the connected SIEM workspace. Graph runHuntingQuery accepts an optional 'workspaceId'; without it the service uses
the caller's primary workspace. Workspaces can be offered by name through SENTINEL_WORKSPACES (name=workspace-id).
No Azure Resource Manager access is needed: everything runs with the user's delegated ThreatHunting.Read.All."""
from __future__ import annotations

import re
from typing import Optional

from . import runtime
from .errors import InputError

_GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")

FALLBACK_NOTE = ("If you cannot access this workspace, the service silently answers from your primary workspace; "
                 "the TenantId column of Sentinel tables shows the workspace ID that answered.")


def configured() -> list[dict]:
    return [{"name": name, "workspaceId": wid} for name, wid in runtime.settings().sentinel_workspaces]


def resolve(workspace: Optional[str]) -> Optional[str]:
    """Workspace name or ID -> workspace ID (GUID); None/empty -> None (the user's primary workspace)."""
    if workspace is None or not str(workspace).strip():
        return None
    value = str(workspace).strip()
    if _GUID.match(value):
        return value.lower()
    for name, wid in runtime.settings().sentinel_workspaces:
        if name.lower() == value.lower():
            return wid
    names = ", ".join(n for n, _ in runtime.settings().sentinel_workspaces) or "none configured"
    raise InputError(f"Unknown workspace {value[:80]!r} (configured: {names}). Use the workspace ID (GUID), or omit "
                     "workspace for your primary workspace; list_sentinel_workspaces shows the options.")


def name_of(workspace_id: Optional[str]) -> Optional[str]:
    for name, wid in runtime.settings().sentinel_workspaces:
        if workspace_id and wid == workspace_id.lower():
            return name
    return None
