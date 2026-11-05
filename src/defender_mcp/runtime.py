"""Process-wide runtime objects (settings, API clients, signing helpers).
Configured once by app.create_server(); tests configure it with fakes."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .settings import Settings


@dataclass
class Runtime:
    settings: Settings
    graph: Any
    confirmer: Any
    cursor_key: bytes
    mde: Any = None  # Defender for Endpoint API client (response actions, indicators)
    mdca: Any = None  # Defender for Cloud Apps API client (sanction_cloud_apps); None = MDCA_API_URL not set


_rt: Optional[Runtime] = None


def configure(rt: Runtime) -> None:
    global _rt
    _rt = rt


def get() -> Runtime:
    if _rt is None:
        raise RuntimeError("Runtime not configured. Call defender_mcp.app.create_server() first.")
    return _rt


def settings() -> Settings:
    return get().settings


def graph() -> Any:
    return get().graph


def mdca() -> Any:
    client = get().mdca
    if client is None:
        from .errors import InputError
        raise InputError("The Defender for Cloud Apps API is not configured: set MDCA_API_URL (deploy.ps1: $MDCA_API_URL, "
                         "value from Settings > Cloud Apps > System > About). Until then tag apps in the portal: "
                         "Cloud apps > Cloud discovery > Discovered apps.")
    return client


def mde() -> Any:
    client = get().mde
    if client is None:
        raise RuntimeError("Defender for Endpoint API client not configured.")
    return client
