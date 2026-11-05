"""Small async helpers."""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable

from .errors import DefenderToolError

log = logging.getLogger("defender_mcp")


async def gather_sections(tasks: dict[str, Awaitable[Any]]) -> tuple[dict[str, Any], dict[str, str]]:
    """Run independent calls concurrently; return (results, errors) so one failing section
    (e.g. a missing permission) does not fail the whole tool."""
    names = list(tasks)
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    ok: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for name, result in zip(names, results, strict=True):
        if isinstance(result, asyncio.CancelledError):
            raise result
        if isinstance(result, DefenderToolError):
            errors[name] = str(result)
        elif isinstance(result, BaseException):
            log.error("section %s failed", name, exc_info=result)
            errors[name] = f"Unexpected error ({type(result).__name__})."
        else:
            ok[name] = result
    return ok, errors
