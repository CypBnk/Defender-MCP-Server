"""Central configuration. All environment variables are read here and nowhere else."""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Mapping, Optional

_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_DOMAIN = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_WS_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{2,62}$")   # Log Analytics workspace name
# Defender for Cloud Apps API URL (portal: Settings > Cloud Apps > System > About), e.g.
# https://contoso.eu2.portal.cloudappsecurity.com
_MDCA_URL = re.compile(r"^https://(?:[a-z0-9-]+\.)*portal\.cloudappsecurity\.(?:com|us)$")
# Defender for Endpoint API hosts (global, regional, US Gov). The user's access token is sent there, so only
# Microsoft endpoints are accepted.
_MDE_HOST = re.compile(r"^(?:[a-z0-9-]+\.)*(?:security\.microsoft\.com|securitycenter\.microsoft\.com|"
                       r"security\.microsoft\.us|securitycenter\.microsoft\.us)$")


class SettingsError(RuntimeError):
    """Raised at startup when the configuration is incomplete or invalid."""


class Secret:
    """String wrapper that never reveals its value in repr/str/logs."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def get(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret('***')"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and hmac.compare_digest(self._value, other._value)

    def __hash__(self) -> int:
        return hash(("Secret", hashlib.sha256(self._value.encode()).hexdigest()))


def load_dotenv_file(path: str = ".env") -> None:
    """Minimal .env loader for local development. Never overrides real environment variables."""
    p = Path(path)
    if not p.is_file():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        if name.startswith("export "):
            name = name[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(name, value)


def _parse_workspaces(raw: str) -> tuple[tuple[str, str], ...]:
    """'soc-ws=<guid>, <guid2>' -> (('soc-ws', '<guid>'), ('<guid2>', '<guid2>')); checked in Settings.problems()."""
    out = []
    for item in re.split(r"[,;\s]+", raw.strip()):
        if item:
            name, sep, wid = item.partition("=")
            out.append((name.strip(), wid.strip().lower()) if sep else (item, item.lower()))
    return tuple(out)


class _Env:
    def __init__(self, environ: Mapping[str, str]) -> None:
        self._e = environ
        self.errors: list[str] = []

    def str(self, name: str, default: Optional[str] = None) -> Optional[str]:
        value = self._e.get(name)
        if value is None:
            return default
        value = value.strip()
        return value if value else default

    def int(self, name: str, default: int, lo: int, hi: int) -> int:
        raw = self.str(name)
        if raw is None:
            return default
        try:
            value = int(raw)
        except ValueError:
            self.errors.append(f"{name} must be an integer.")
            return default
        if not lo <= value <= hi:
            self.errors.append(f"{name} must be between {lo} and {hi}.")
            return default
        return value

    def float(self, name: str, default: float, lo: float, hi: float) -> float:
        raw = self.str(name)
        if raw is None:
            return default
        try:
            value = float(raw)
        except ValueError:
            self.errors.append(f"{name} must be a number.")
            return default
        if not lo <= value <= hi:
            self.errors.append(f"{name} must be between {lo} and {hi}.")
            return default
        return value

    def list(self, name: str) -> tuple[str, ...]:
        raw = self.str(name)
        if not raw:
            return ()
        return tuple(x.strip() for x in raw.split(",") if x.strip())

    def secret(self, name: str) -> Optional[Secret]:
        raw = self.str(name)
        return Secret(raw) if raw else None


@dataclass(frozen=True)
class Settings:
    tenant_id: str
    client_id: str
    client_secret: Secret
    base_url: str
    # Delegated scope of the server app ("Expose an API"), without prefix.
    required_scope: str = "access_as_user"
    # Application IDs whose tokens are accepted (azp/appid claim), e.g. the Copilot Studio client app.
    allowed_client_app_ids: tuple[str, ...] = ()
    # full = all tools (default); read = read-only tools (optional)
    profile: str = "full"
    environment: str = "production"
    jwt_signing_key: Optional[Secret] = None
    log_level: str = "INFO"
    log_format: str = "json"
    default_max_items: int = 50
    hard_max_items: int = 300
    max_response_bytes: int = 100_000
    scan_limit: int = 5000
    graph_host: str = "graph.microsoft.com"
    authority_host: str = "login.microsoftonline.com"
    # Defender for Endpoint API (response actions, indicators). Tokens are requested for mde_resource
    # (WindowsDefenderATP); calls go to mde_api_host, e.g. eu.api.security.microsoft.com.
    mde_api_host: str = "api.security.microsoft.com"
    mde_resource: str = "https://api.securitycenter.microsoft.com"
    graph_timeout_seconds: float = 30.0
    # Advanced hunting queries can run much longer than ordinary Graph calls.
    hunting_timeout_seconds: float = 90.0
    # Own KQL queries offered by run_custom_hunt; empty = the catalog shipped in the package (custom_hunts.json).
    custom_hunts_file: str = ""
    # Microsoft Sentinel / ISOC workspaces offered by name ((name, workspace ID) pairs); empty = only the user's
    # primary workspace, which advanced hunting uses when no workspace ID is given.
    sentinel_workspaces: tuple[tuple[str, str], ...] = ()
    # Defender for Cloud Apps API (only sanction_cloud_apps, undocumented endpoint). Empty = tool not configured.
    mdca_api_url: str = ""
    # obo: token for the signed-in user (resource 'Microsoft Cloud App Security', delegated Discovery.manage);
    # token: legacy Defender for Cloud Apps API token (MDCA_API_TOKEN, Key Vault) - acts with the token owner's rights.
    mdca_auth: str = "obo"
    mdca_api_token: Optional[Secret] = None
    mdca_resource: str = "05a65629-4c1b-48c1-a78b-804c4abdd4af"
    graph_max_retries: int = 3
    graph_retry_max_wait_seconds: float = 30.0
    graph_max_concurrency: int = 16
    rate_limit_rps: float = 5.0
    rate_limit_burst: int = 20
    response_cache_ttl_seconds: int = 0
    confirmation_ttl_seconds: int = 300
    appinsights_connection_string: Optional[Secret] = None
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1

    # ------------------------------------------------------------------ factory
    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None, *, dotenv: bool = True) -> "Settings":
        if environ is None:
            if dotenv:
                load_dotenv_file(os.getenv("MCP_DOTENV_PATH", ".env"))
            environ = os.environ
        env = _Env(environ)
        tenant_id = env.str("TENANT_ID", "") or ""
        client_id = env.str("CLIENT_ID", "") or ""
        client_secret = env.str("CLIENT_SECRET", "") or ""
        base_url = (env.str("BASE_URL", "") or "").rstrip("/")
        for name, value in (("TENANT_ID", tenant_id), ("CLIENT_ID", client_id),
                            ("CLIENT_SECRET", client_secret), ("BASE_URL", base_url)):
            if not value:
                env.errors.append(f"{name} is required.")
        settings = cls(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=Secret(client_secret),
            base_url=base_url,
            required_scope=env.str("MCP_REQUIRED_SCOPE", "access_as_user") or "access_as_user",
            allowed_client_app_ids=tuple(x.lower() for x in env.list("ALLOWED_CLIENT_APP_IDS")),
            profile=(env.str("MCP_PROFILE", "full") or "full").lower(),
            environment=(env.str("MCP_ENV", "production") or "production").lower(),
            jwt_signing_key=env.secret("JWT_SIGNING_KEY"),
            log_level=(env.str("LOG_LEVEL", "INFO") or "INFO").upper(),
            log_format=(env.str("LOG_FORMAT", "json") or "json").lower(),
            default_max_items=env.int("MCP_DEFAULT_MAX_ITEMS", 50, 1, 1000),
            hard_max_items=env.int("MCP_HARD_MAX_ITEMS", 300, 1, 1000),
            max_response_bytes=env.int("MCP_MAX_RESPONSE_BYTES", 100_000, 10_000, 2_000_000),
            scan_limit=env.int("MCP_SCAN_LIMIT", 5000, 100, 50_000),
            graph_host=env.str("GRAPH_HOST", "graph.microsoft.com") or "graph.microsoft.com",
            authority_host=env.str("AUTHORITY_HOST", "login.microsoftonline.com") or "login.microsoftonline.com",
            mde_api_host=(env.str("MDE_API_HOST", "api.security.microsoft.com") or "api.security.microsoft.com").lower(),
            mde_resource=(env.str("MDE_RESOURCE", "https://api.securitycenter.microsoft.com")
                          or "https://api.securitycenter.microsoft.com").rstrip("/"),
            graph_timeout_seconds=env.float("GRAPH_TIMEOUT_SECONDS", 30.0, 5.0, 120.0),
            hunting_timeout_seconds=env.float("HUNTING_TIMEOUT_SECONDS", 90.0, 10.0, 300.0),
            custom_hunts_file=env.str("CUSTOM_HUNTS_FILE", "") or "",
            sentinel_workspaces=_parse_workspaces(env.str("SENTINEL_WORKSPACES", "") or ""),
            mdca_api_url=_mdca_url(env.str("MDCA_API_URL", "") or ""),
            mdca_auth=(env.str("MDCA_AUTH", "obo") or "obo").lower(),
            mdca_api_token=env.secret("MDCA_API_TOKEN"),
            graph_max_retries=env.int("GRAPH_MAX_RETRIES", 3, 0, 8),
            graph_retry_max_wait_seconds=env.float("GRAPH_RETRY_MAX_WAIT_SECONDS", 30.0, 1.0, 120.0),
            graph_max_concurrency=env.int("GRAPH_MAX_CONCURRENCY", 16, 1, 128),
            rate_limit_rps=env.float("RATE_LIMIT_RPS", 5.0, 0.0, 1000.0),
            rate_limit_burst=env.int("RATE_LIMIT_BURST", 20, 1, 10_000),
            response_cache_ttl_seconds=env.int("RESPONSE_CACHE_TTL_SECONDS", 0, 0, 86_400),
            confirmation_ttl_seconds=env.int("CONFIRMATION_TTL_SECONDS", 300, 30, 3600),
            appinsights_connection_string=env.secret("APPLICATIONINSIGHTS_CONNECTION_STRING"),
            host=env.str("MCP_HOST", "0.0.0.0") or "0.0.0.0",
            port=env.int("PORT", env.int("MCP_PORT", 8000, 1, 65535), 1, 65535),
            workers=env.int("WEB_CONCURRENCY", 1, 1, 32),
        )
        errors = env.errors + settings.problems()
        if errors:
            raise SettingsError("Invalid configuration:\n- " + "\n- ".join(dict.fromkeys(errors)))
        return settings

    # --------------------------------------------------------------- validation
    def problems(self) -> list[str]:
        errors: list[str] = []
        if self.tenant_id:
            if self.tenant_id.lower() in {"common", "organizations", "consumers"}:
                errors.append("TENANT_ID must be the tenant GUID or primary domain, not a multi-tenant alias.")
            elif not (_GUID.match(self.tenant_id) or _DOMAIN.match(self.tenant_id)):
                errors.append("TENANT_ID must be a GUID or a domain name.")
        if self.client_id and not _GUID.match(self.client_id):
            errors.append("CLIENT_ID must be the application (client) ID GUID.")
        if self.base_url and not self.base_url.startswith(("https://", "http://")):
            errors.append("BASE_URL must start with https://")
        bad_apps = [a for a in self.allowed_client_app_ids if not _GUID.match(a)]
        if bad_apps:
            errors.append("ALLOWED_CLIENT_APP_IDS must contain application (client) ID GUIDs: " + ", ".join(bad_apps))
        if self.profile not in {"full", "read"}:
            errors.append("MCP_PROFILE must be 'full' (all tools) or 'read' (read tools only).")
        if self.environment not in {"development", "production"}:
            errors.append("MCP_ENV must be 'development' or 'production'.")
        if self.log_level not in _LEVELS:
            errors.append(f"LOG_LEVEL must be one of {sorted(_LEVELS)}.")
        if self.log_format not in {"json", "text"}:
            errors.append("LOG_FORMAT must be 'json' or 'text'.")
        names = [n.lower() for n, _ in self.sentinel_workspaces]
        if len(names) > 20:
            errors.append("SENTINEL_WORKSPACES supports at most 20 workspaces.")
        if len(set(names)) != len(names):
            errors.append("SENTINEL_WORKSPACES contains a workspace name twice.")
        for name, wid in self.sentinel_workspaces:
            if not _GUID.match(wid):
                errors.append(f"SENTINEL_WORKSPACES: {wid[:60]!r} is not a workspace ID (GUID); use name=workspace-id.")
            elif not (_WS_NAME.match(name) or _GUID.match(name)):
                errors.append(f"SENTINEL_WORKSPACES: {name[:60]!r} is not a valid workspace name.")
        if self.mdca_api_url and not _MDCA_URL.match(self.mdca_api_url):
            errors.append("MDCA_API_URL must be the Defender for Cloud Apps API URL, e.g. "
                          "https://contoso.eu2.portal.cloudappsecurity.com (Settings > Cloud Apps > System > About).")
        if self.mdca_auth not in {"obo", "token"}:
            errors.append("MDCA_AUTH must be 'obo' (signed-in user) or 'token' (Defender for Cloud Apps API token).")
        elif self.mdca_auth == "token" and self.mdca_api_url and self.mdca_api_token is None:
            errors.append("MDCA_AUTH=token needs MDCA_API_TOKEN (Defender for Cloud Apps API token, stored in Key Vault).")
        if not _MDE_HOST.match(self.mde_api_host or ""):
            errors.append("MDE_API_HOST must be a Microsoft Defender API host such as api.security.microsoft.com or "
                          "eu.api.security.microsoft.com.")
        resource_host = (self.mde_resource or "").removeprefix("https://")
        if not self.mde_resource.startswith("https://") or not _MDE_HOST.match(resource_host):
            errors.append("MDE_RESOURCE must be https://api.securitycenter.microsoft.com (or the national-cloud equivalent).")
        if self.default_max_items > self.hard_max_items:
            errors.append("MCP_DEFAULT_MAX_ITEMS must not exceed MCP_HARD_MAX_ITEMS.")
        if self.jwt_signing_key is not None and len(self.jwt_signing_key.get()) < 32:
            errors.append("JWT_SIGNING_KEY must be at least 32 characters.")
        if self.environment == "production":
            if self.base_url and not self.base_url.startswith("https://"):
                errors.append("BASE_URL must use https:// in production.")
            if self.jwt_signing_key is None:
                errors.append("JWT_SIGNING_KEY is required in production (signs cursors and confirmation tokens).")
        return errors

    # ------------------------------------------------------------------ helpers
    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def tenant_guid(self) -> Optional[str]:
        """Tenant ID as lower-case GUID, or None when TENANT_ID is a domain name."""
        return self.tenant_id.lower() if _GUID.match(self.tenant_id or "") else None

    def signing_key(self, purpose: str) -> bytes:
        """Derive a purpose-specific HMAC key (cursor, confirmation) from JWT_SIGNING_KEY,
        falling back to the client secret in development."""
        base = (self.jwt_signing_key or self.client_secret).get().encode("utf-8")
        return hmac.new(base, f"defender-mcp/{purpose}".encode(), hashlib.sha256).digest()

    def describe(self) -> dict:
        """Safe summary for startup logs (no secrets)."""
        out = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if isinstance(value, Secret):
                value = "set"
            out[f.name] = value
        return out


def _mdca_url(value: str) -> str:
    """Normalize the Defender for Cloud Apps API URL: lower case, no trailing slash, no /api suffix, https:// added."""
    url = value.strip().rstrip("/")
    if url and "://" not in url:
        url = "https://" + url
    return re.sub(r"/(?:cas/)?api$", "", url, flags=re.IGNORECASE).lower()

