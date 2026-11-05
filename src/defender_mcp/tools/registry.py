"""Tool registry: tools are plain async functions; app.create_server() registers them with
FastMCP according to the profile (full/admin = all tools, read = read tools only)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from .. import scopes as scope_names


@dataclass(frozen=True)
class ToolSpec:
    fn: Callable[..., Any]
    name: str
    kind: str  # "read" | "admin"
    scopes: tuple[str, ...]
    title: Optional[str] = None
    destructive: bool = False
    idempotent: bool = True
    # Admin tools that never change anything (they only need a write-level permission to read, e.g. the status
    # of Defender for Endpoint response actions): readOnlyHint=true.
    read_only: bool = False
    # Returns True for calls that run without the two-step confirmation (audit phase 'execute').
    immediate: Optional[Callable[[dict], bool]] = None

    def annotations(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "readOnlyHint": self.kind == "read" or self.read_only,
            "destructiveHint": self.destructive,
            "idempotentHint": self.idempotent,
            "openWorldHint": False,
        }
        if self.title:
            data["title"] = self.title
        return data

    def runs_immediately(self, arguments: Optional[dict]) -> bool:
        if self.immediate is None:
            return False
        try:
            return bool(self.immediate(dict(arguments or {})))
        except Exception:  # noqa: BLE001 - audit must never fail a call
            return False


_SPECS: dict[str, ToolSpec] = {}


def _register(spec: ToolSpec) -> None:
    existing = _SPECS.get(spec.name)
    if existing is not None and (existing.fn.__module__, existing.fn.__qualname__) != (spec.fn.__module__,
                                                                                      spec.fn.__qualname__):
        raise RuntimeError(f"Duplicate tool name: {spec.name} ({existing.fn.__module__} and {spec.fn.__module__})")
    if not (spec.fn.__doc__ or "").strip():
        raise RuntimeError(f"Tool {spec.name} needs a docstring (it becomes the tool description).")
    _SPECS[spec.name] = spec


def read_tool(*, scopes: tuple[str, ...], title: Optional[str] = None) -> Callable:
    def deco(fn: Callable) -> Callable:
        _register(ToolSpec(fn=fn, name=fn.__name__, kind="read", scopes=tuple(scopes), title=title))
        return fn
    return deco


def admin_tool(*, scopes: tuple[str, ...], title: Optional[str] = None, destructive: bool = True,
               idempotent: bool = False, read_only: bool = False,
               immediate: Optional[Callable[[dict], bool]] = None) -> Callable:
    def deco(fn: Callable) -> Callable:
        _register(ToolSpec(fn=fn, name=fn.__name__, kind="admin", scopes=tuple(scopes), title=title,
                           destructive=destructive, idempotent=idempotent, read_only=read_only, immediate=immediate))
        return fn
    return deco


def all_specs() -> list[ToolSpec]:
    from . import load_all

    load_all()
    return list(_SPECS.values())


def specs_for(profile: str) -> list[ToolSpec]:
    specs = all_specs()
    if profile == "full":
        return specs
    return [s for s in specs if s.kind == "read"]


def scopes_for(profile: str) -> list[str]:
    """All delegated permissions of the profile; Defender for Endpoint API scopes carry the prefix
    'WindowsDefenderATP/'."""
    return sorted({scope for spec in specs_for(profile) for scope in spec.scopes})


def graph_scopes_for(profile: str) -> list[str]:
    return sorted(name for api, name in map(scope_names.split, scopes_for(profile)) if api == "graph")


def mde_scopes_for(profile: str) -> list[str]:
    return sorted(name for api, name in map(scope_names.split, scopes_for(profile)) if api == scope_names.MDE_API)


def mdca_scopes_for(profile: str) -> list[str]:
    return sorted(name for api, name in map(scope_names.split, scopes_for(profile)) if api == scope_names.MDCA_API)
