"""python -m defender_mcp  -> uvicorn with proxy headers (Container Apps ingress terminates TLS)."""
from __future__ import annotations

import sys

from .custom_hunts import CatalogError, load_catalog
from .settings import Settings, SettingsError


def main() -> int:
    try:
        settings = Settings.from_env()
    except SettingsError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        load_catalog(settings.custom_hunts_file)
    except CatalogError as exc:
        print(f"Invalid custom hunt catalog: {exc}", file=sys.stderr)
        return 2
    import uvicorn

    uvicorn.run("defender_mcp.asgi:app", host=settings.host, port=settings.port, workers=settings.workers,
                proxy_headers=True, forwarded_allow_ips="*", log_config=None, access_log=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
