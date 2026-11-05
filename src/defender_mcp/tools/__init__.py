"""Tool modules. Importing a module registers its tools in the registry."""
import importlib

MODULES = (
    "overview", "incidents", "hunting", "hunts", "devices", "endpoint_health", "vulnerabilities", "posture",
    "identity", "users", "threat_intel", "cloud_apps", "detections", "sentinel", "exposure", "analysis", "agents", "identity_risk",
    "admin_incidents", "admin_detections", "admin_identity", "admin_response", "admin_users", "admin_submissions",
    "admin_cloud_apps",
)


def load_all() -> None:
    for name in MODULES:
        importlib.import_module(f"{__name__}.{name}")
