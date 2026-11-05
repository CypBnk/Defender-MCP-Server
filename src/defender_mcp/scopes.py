"""Delegated permissions (names only).

Microsoft Graph scopes are plain names.
Defender for Endpoint API scopes (resource WindowsDefenderATP) carry the prefix 'WindowsDefenderATP/'.
The OBO exchange always uses '.default' per resource, so the admin consent in the app registration decides.
deploy.ps1 contains the same lists ($GRAPH_SCOPES, $MDE_SCOPES); tests/test_registry_app.py keeps them in sync.
Names ending in .Read / .Read.All are read permissions; deploy.ps1 grants all others only with -GrantWritePermissions."""

MDE_API = "WindowsDefenderATP"
MDE_APP_ID = "fc780465-2017-40d4-a0c5-307022471b92"   # first-party app ID of WindowsDefenderATP
# Defender for Cloud Apps API (API name in Entra ID: 'Microsoft Cloud App Security'); only used by sanction_cloud_apps
MDCA_API = "MicrosoftCloudAppSecurity"
MDCA_APP_ID = "05a65629-4c1b-48c1-a78b-804c4abdd4af"

# ---------------------------------------------------------------- Microsoft Graph, read
USER_READ = "User.Read"
THREAT_HUNTING_READ = "ThreatHunting.Read.All"
SECURITY_INCIDENT_READ = "SecurityIncident.Read.All"
SECURITY_ALERT_READ = "SecurityAlert.Read.All"
SECURITY_EVENTS_READ = "SecurityEvents.Read.All"            # Secure Score, control profiles
IDENTITY_HEALTH_READ = "SecurityIdentitiesHealth.Read.All"  # Defender for Identity health issues
CUSTOM_DETECTION_READ = "CustomDetection.Read.All"
ATTACK_SIMULATION_READ = "AttackSimulation.Read.All"
CLOUDAPP_DISCOVERY_READ = "CloudApp-Discovery.Read.All"
USER_READ_ALL = "User.Read.All"                             # resolve users (investigation, containment)
IDENTITY_RISKY_USER_READ = "IdentityRiskyUser.Read.All"     # Entra ID Protection user risk (Entra ID P2)
THREAT_INTEL_READ = "ThreatIntelligence.Read.All"           # Microsoft Threat Intelligence (hosts, CVEs, articles)
IDENTITY_SENSORS_READ = "SecurityIdentitiesSensors.Read.All"  # Defender for Identity sensors
IDENTITY_RISK_EVENT_READ = "IdentityRiskEvent.Read.All"     # Entra ID Protection risk detections (P1/P2)
IDENTITY_RISKY_SP_READ = "IdentityRiskyServicePrincipal.Read.All"  # risky workload identities (Workload ID Premium)
IDENTITY_ACCOUNTS_READ = "SecurityIdentitiesAccount.Read.All"     # Defender for Identity accounts (AD, Entra, Okta)
THREAT_SUBMISSION_READ = "ThreatSubmission.Read.All"        # submissions to Microsoft (incl. user-reported messages)

# ---------------------------------------------------------------- Microsoft Graph, write
SECURITY_INCIDENT_READWRITE = "SecurityIncident.ReadWrite.All"
SECURITY_ALERT_READWRITE = "SecurityAlert.ReadWrite.All"
CUSTOM_DETECTION_READWRITE = "CustomDetection.ReadWrite.All"
IDENTITY_HEALTH_READWRITE = "SecurityIdentitiesHealth.ReadWrite.All"
USER_REVOKE_SESSIONS = "User.RevokeSessions.All"            # contain_user: revoke sessions
USER_ENABLE_DISABLE = "User.EnableDisableAccount.All"       # contain_user: disable / enable the account
IDENTITY_RISKY_USER_READWRITE = "IdentityRiskyUser.ReadWrite.All"  # contain_user: confirm compromised / dismiss
IDENTITY_ACTIONS_READWRITE = "SecurityIdentitiesActions.ReadWrite.All"  # contain_user: AD account actions (MDI)
THREAT_SUBMISSION_READWRITE = "ThreatSubmission.ReadWrite.All"      # manage_submissions: submit URLs to Microsoft

# ---------------------------------------------------------------- Defender for Endpoint API (delegated)
MDE_MACHINE_READ = f"{MDE_API}/Machine.Read"                    # antivirus health report (read)
MDE_REMEDIATION_READ = f"{MDE_API}/RemediationTask.Read"        # vulnerability remediation activities (read)
MDE_ALERT_READWRITE = f"{MDE_API}/Alert.ReadWrite"              # start / list automated investigations
MDE_MACHINE_READWRITE = f"{MDE_API}/Machine.ReadWrite"          # list machine actions (status of response actions)
MDE_MACHINE_ISOLATE = f"{MDE_API}/Machine.Isolate"
MDE_MACHINE_SCAN = f"{MDE_API}/Machine.Scan"
MDE_MACHINE_COLLECT_FORENSICS = f"{MDE_API}/Machine.CollectForensics"
MDE_MACHINE_RESTRICT_EXECUTION = f"{MDE_API}/Machine.RestrictExecution"
MDE_MACHINE_STOP_AND_QUARANTINE = f"{MDE_API}/Machine.StopAndQuarantine"
MDE_TI_READWRITE = f"{MDE_API}/Ti.ReadWrite"                    # custom indicators (list, add, delete)

# ---------------------------------------------------------------- Defender for Cloud Apps API (delegated)
MDCA_DISCOVERY_MANAGE = f"{MDCA_API}/Discovery.manage"          # sanction_cloud_apps (undocumented endpoint)


def split(scope: str) -> tuple[str, str]:
    """('graph', 'User.Read') or ('WindowsDefenderATP', 'Machine.Isolate')."""
    if "/" in scope:
        api, name = scope.split("/", 1)
        return api, name
    return "graph", scope
