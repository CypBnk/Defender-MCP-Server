#Requires -Version 7.2
<#
.SYNOPSIS
  Deploys the Defender XDR MCP Server 2.10.0 to Azure Container Apps. Safe to run any number of times.

.DESCRIPTION
  - Sets up a new environment completely and can run again at any time (idempotent): resource group, container
    registry, Log Analytics, Container Apps environment, Key Vault (RBAC), managed identity, Application Insights,
    app registrations (server app and Copilot client app) and the container app.
  - On the first run the script determines the tenant ID and the globally unique names of the container registry
    and Key Vault itself (suffix derived from subscription and resource group; the next free one if a name is
    taken) and saves them to deploy.settings.psd1. A deleted but recoverable Key Vault of the same resource group is
    recovered (soft delete).
  - All settings (resource group, names, region, client IDs, options) are in deploy.settings.psd1, a data file
    the script creates from deploy.settings.example.psd1 on the first run. It is not overwritten when you unpack a
    new version.
  - All secrets are stored in Key Vault. This script contains no secrets and never prints any.
  - Builds the image with ACR Build, deploys it with infra/main.bicep and checks the result.

.PARAMETER Tag
  Image tag. Default: v<yyyyMMddHHmm> (a new tag per run). With -SkipBuild, pass the tag of an image that already
  exists in the registry (the script checks this).

.PARAMETER SkipBuild
  No image build: deploys the existing image -Tag again (e.g. to change permissions, ingress or secrets only).

.PARAMETER ConfigureAppRegistration
  Server app: Application ID URI, scope 'access_as_user', token version 2, delegated permissions for Microsoft Graph
  and the Defender for Endpoint API / WindowsDefenderATP (by default only Read/Read.All, write permissions with
  -GrantWritePermissions), admin consent. If no ClientId is configured, the script creates the server app itself
  (after confirmation), configures it and saves the ClientId to deploy.settings.psd1 (ServerClientId).
  Also creates the client app for Copilot Studio (permission on the server app's scope, admin consent, redirect
  URL). Copilot Studio signs in at Entra ID with it (OAuth 2.0 "Manual"); the server only validates the tokens.
  Requires an Entra role that may grant consent (e.g. Cloud Application Administrator).

.PARAMETER CopilotRedirectUris
  Redirect URL(s) shown by Copilot Studio after you create the connection. They are added to the client app
  (together with -ConfigureAppRegistration).

.PARAMETER AddRedirectUri
  Quick mode: only adds the redirect URL shown by Copilot Studio to the Copilot client app and exits (no build, no
  deployment, no other changes). Takes a few seconds.
    ./deploy.ps1 -AddRedirectUri 'https://global.consent.azure-apim.net/redirect/...'

.PARAMETER RestrictIngressToPowerPlatform
  Allow ingress only from the IP ranges of the Power Platform connectors (service tags in
  -PowerPlatformServiceTags) and -ExtraAllowedCidrs. Enable only once Copilot Studio works. Without the switch an
  existing restriction is removed again.

.PARAMETER PowerPlatformServiceTags
  Azure service tags whose IPv4 ranges -RestrictIngressToPowerPlatform allows. Default:
  AzureConnectors.WestEurope and AzureConnectors.NorthEurope (Power Platform environments in the Europe region).
  Use the tags of the region of your Power Platform environment, e.g. 'AzureConnectors.EastUS',
  'AzureConnectors.WestUS' for the United States. Can also be set as PowerPlatformServiceTags in deploy.settings.psd1.

.PARAMETER ExtraAllowedCidrs
  Additional IPv4 ranges (CIDR) allowed with -RestrictIngressToPowerPlatform, e.g. your own public IP for the
  smoke test ('203.0.113.10/32').

.PARAMETER RotateClientSecret
  Creates a new client secret for the server app (az ad app credential reset --append, 1 year), writes it only to
  Key Vault (never to the output) and forces a new revision. Without the required permission the secret is prompted for.

.PARAMETER RemoveOldClientSecrets
  After confirmation, deletes all secrets of the server app except the one stored in Key Vault. Run it only after the
  agent works with the new secret.

.PARAMETER AllowedGroupIds
  Object IDs of the groups whose direct members may use the server (added to AllowedGroupIds of deploy.settings.psd1).
  The script assigns them to the server app (and the Copilot client app) and turns on "Assignment required".
  If nothing is given and assignment is not required, the script asks for a group name or object ID at the end and
  offers to save the selection to deploy.settings.psd1.

.PARAMETER GrantWritePermissions
  Also grants the write permissions of the admin tools: Graph (incidents, alerts, custom detections, Defender for
  Identity health, user containment: revoke sessions, disable account, confirm risk) and the Defender for Endpoint
  API / WindowsDefenderATP (isolate, scan, investigation package, restrict app execution, stop and quarantine file,
  automated investigation, device tags, action status, indicators). Without the switch the app only gets
  Read/Read.All; the admin tools are then visible but fail with 403. If the WindowsDefenderATP service principal is
  missing in the tenant, the script creates it (AADSTS650052).

.PARAMETER PruneGraphPermissions
  Removes permissions of the server app (Graph and WindowsDefenderATP) the server does not need (e.g. old write
  permissions) and trims the granted admin consent. Without the switch they are only reported.

.PARAMETER NoPrompt
  No questions (e.g. in pipelines). The group prompt is skipped; only a warning remains.

.PARAMETER KeepAcrAdmin
  Leaves the admin user of the container registry as it is. By default the script turns it off (the container app
  pulls with its managed identity).

.PARAMETER LocalBuild
  Builds the image with local Docker and pushes it to the ACR instead of using ACR Tasks
  (e.g. when ACR Tasks are blocked in the subscription). Requires Docker Desktop.

.EXAMPLE
  ./deploy.ps1
  ./deploy.ps1 -ConfigureAppRegistration
  ./deploy.ps1 -RotateClientSecret
  ./deploy.ps1 -AddRedirectUri 'https://global.consent.azure-apim.net/redirect/...'
  ./deploy.ps1 -SkipBuild -Tag v202610301200 -RestrictIngressToPowerPlatform
  ./deploy.ps1 -SkipBuild -Tag v202610301200 -ConfigureAppRegistration -GrantWritePermissions
#>
[CmdletBinding()]
param(
    [string] $Tag = ('v' + (Get-Date -Format 'yyyyMMddHHmm')),
    [switch] $SkipBuild,
    [switch] $ConfigureAppRegistration,
    [switch] $RotateClientSecret,
    [switch] $RemoveOldClientSecrets,
    [string[]] $AllowedGroupIds = @(),
    [switch] $NoPrompt,
    [switch] $GrantWritePermissions,
    [switch] $PruneGraphPermissions,
    [switch] $KeepAcrAdmin,
    [switch] $LocalBuild,
    [string[]] $CopilotRedirectUris = @(),
    [string[]] $AddRedirectUri = @(),
    [switch] $RestrictIngressToPowerPlatform,
    [string[]] $PowerPlatformServiceTags = @('AzureConnectors.WestEurope', 'AzureConnectors.NorthEurope'),
    [string[]] $ExtraAllowedCidrs = @()
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '2026-11-05.d15'  # please include when asking for support

# ── Constants of this version (not settings: they belong to the code) ──────────
# Delegated permissions of all tools (from src/defender_mcp/tools/registry.py; tests/test_registry_app.py checks
# that both lists match). Graph: write permissions only with -GrantWritePermissions.
$GRAPH_SCOPES = @('AttackSimulation.Read.All',
                  'CloudApp-Discovery.Read.All',
                  'CustomDetection.Read.All',
                  'CustomDetection.ReadWrite.All',
                  'IdentityRiskEvent.Read.All',
                  'IdentityRiskyServicePrincipal.Read.All',
                  'IdentityRiskyUser.Read.All',
                  'IdentityRiskyUser.ReadWrite.All',
                  'SecurityAlert.Read.All',
                  'SecurityAlert.ReadWrite.All',
                  'SecurityEvents.Read.All',
                  'SecurityIdentitiesAccount.Read.All',
                  'SecurityIdentitiesActions.ReadWrite.All',
                  'SecurityIdentitiesHealth.Read.All',
                  'SecurityIdentitiesHealth.ReadWrite.All',
                  'SecurityIdentitiesSensors.Read.All',
                  'SecurityIncident.Read.All',
                  'SecurityIncident.ReadWrite.All',
                  'ThreatHunting.Read.All',
                  'ThreatIntelligence.Read.All',
                  'ThreatSubmission.Read.All',
                  'ThreatSubmission.ReadWrite.All',
                  'User.EnableDisableAccount.All',
                  'User.Read',
                  'User.Read.All',
                  'User.RevokeSessions.All')
# Defender for Endpoint API (resource WindowsDefenderATP): read permissions always (Machine.Read: antivirus health and
# risk score, RemediationTask.Read: remediation tasks); all others (response actions, investigations, tags,
# indicators) only with -GrantWritePermissions. Machine.ReadWrite is needed by get_response_actions and device tags,
# Alert.ReadWrite to start and list automated investigations.
$MDE_SCOPES = @('Alert.ReadWrite',
                'Machine.CollectForensics',
                'Machine.Isolate',
                'Machine.Read',
                'Machine.ReadWrite',
                'Machine.RestrictExecution',
                'Machine.Scan',
                'Machine.StopAndQuarantine',
                'RemediationTask.Read',
                'Ti.ReadWrite')
$MDE_APP_ID = 'fc780465-2017-40d4-a0c5-307022471b92'   # WindowsDefenderATP (Microsoft first-party app)
# Defender for Cloud Apps API (resource 'Microsoft Cloud App Security'): only sanction_cloud_apps; only if
# $MDCA_API_URL is set, $MDCA_AUTH is 'obo' and with -GrantWritePermissions.
$MDCA_SCOPES = @('Discovery.manage')
$MDCA_APP_ID = '05a65629-4c1b-48c1-a78b-804c4abdd4af'   # Microsoft Cloud App Security (Microsoft first-party app)
$GRAPH_APP_ID = '00000003-0000-0000-c000-000000000000'
$COPILOT_DEFAULT_REDIRECT = 'https://global.consent.azure-apim.net/redirect'

# ── Settings (deploy.settings.psd1, no secrets) ────────────────────────────────
# Everything an organization adjusts is in deploy.settings.psd1 next to this script: a data file (no code) that is
# validated on reading. Template with defaults and explanations: deploy.settings.example.psd1 (part of the package).
$SettingsFile = Join-Path $PSScriptRoot 'deploy.settings.psd1'
$SettingsTemplate = Join-Path $PSScriptRoot 'deploy.settings.example.psd1'

# Setting -> script variable ('SERVER.<field>' = field of the $SERVER hashtable).
$SETTINGS_MAP = [ordered]@{
    ResourceGroup = 'RG'; Location = 'LOCATION'; TenantId = 'TENANT_ID'; ContainerRegistry = 'ACR'; KeyVault = 'KEYVAULT'
    ContainerAppsEnvironment = 'ENV_NAME'; LogAnalyticsWorkspace = 'LOG_WS'; ContainerApp = 'SERVER.App'
    ImageName = 'IMAGE'
    AppRegEnvironment = 'APPREG_ENV'; ServerAppRegName = 'SERVER.AppRegName'
    CopilotClientAppRegName = 'SERVER.CopilotClientAppName'; ServerClientId = 'SERVER.ClientId'
    CopilotClientAppId = 'SERVER.CopilotClientAppId'; ServerScope = 'SERVER.Scope'; SecretPrefix = 'SERVER.SecretPrefix'
    AllowedGroupIds = 'SERVER.AllowedGroupIds'; ProtectedAppIds = 'PROTECTED_APP_IDS'
    MdeApiHost = 'MDE_API_HOST'; SentinelWorkspaces = 'SENTINEL_WORKSPACES'; MdcaApiUrl = 'MDCA_API_URL'
    MdcaAuth = 'MDCA_AUTH'; PowerPlatformServiceTags = 'POWER_PLATFORM_SERVICE_TAGS'
}
$SETTINGS_LISTS = @('AllowedGroupIds', 'ProtectedAppIds', 'PowerPlatformServiceTags')

# Reads a settings file: data only (Import-PowerShellDataFile runs no code), known names, strings or string lists.
function Read-SettingsFile([string] $Path) {
    try { $data = Import-PowerShellDataFile -LiteralPath $Path }
    catch {
        throw ("Cannot read ${Path}: $($_.Exception.Message) The file may only contain values: text in quotes " +
               "('value'), lists as @('a', 'b'); no variables or commands.")
    }
    $unknown = @($data.Keys | Where-Object { -not $SETTINGS_MAP.Contains($_) })
    if ($unknown) {
        throw ("Unknown setting(s) in ${Path}: $($unknown -join ', '). Correct the spelling or delete the line(s); " +
               "valid names: $($SETTINGS_MAP.Keys -join ', ').")
    }
    foreach ($key in @($data.Keys)) {
        $value = $data[$key]
        if ($key -in $SETTINGS_LISTS) {
            $items = @($value | Where-Object { $null -ne $_ })
            if (@($items | Where-Object { $_ -isnot [string] }).Count) {
                throw "$key in $Path must be a list of text values, e.g. $key = @('a', 'b')."
            }
            $data[$key] = [string[]] $items
        } elseif ($null -ne $value -and $value -isnot [string]) {
            throw "$key in $Path must be text in quotes, e.g. $key = 'value'."
        }
    }
    return $data
}

function Set-SettingValue([string] $Key, $Value) {
    $target = $SETTINGS_MAP[$Key]
    if ($Key -in $SETTINGS_LISTS) { $Value = [string[]] @($Value | Where-Object { $_ }) } else { $Value = "$Value" }
    if ($target -like 'SERVER.*') { $script:SERVER[$target.Substring(7)] = $Value }
    else { Set-Variable -Name $target -Scope Script -Value $Value }
}

function Get-SettingValue([string] $Key) {
    $target = $SETTINGS_MAP[$Key]
    if ($target -like 'SERVER.*') { return , $script:SERVER[$target.Substring(7)] }
    return , (Get-Variable -Name $target -Scope Script -ValueOnly)
}

function ConvertTo-SettingLiteral([string] $Key, $Value) {
    if ($Key -in $SETTINGS_LISTS) {
        $items = @($Value | Where-Object { $_ } | ForEach-Object { "'" + ("$_" -replace "'", "''") + "'" })
        return '@(' + ($items -join ', ') + ')'
    }
    return "'" + ("$Value" -replace "'", "''") + "'"
}

# Writes one value into deploy.settings.psd1: replaces the line "<Key> = ..." (a list spread over several lines
# included) or adds it before the closing brace. Comments stay. The file must still be valid afterwards, otherwise
# the previous content is restored. Never use it for secrets.
function Save-Setting([string] $Key, $Value) {
    if (-not $SETTINGS_MAP.Contains($Key)) { throw "Internal error: unknown setting '$Key'." }
    Set-SettingValue $Key $Value
    $literal = ConvertTo-SettingLiteral $Key $Value
    $original = Get-Content -LiteralPath $SettingsFile -Raw -Encoding utf8
    $lines = [System.Collections.Generic.List[string]]::new([string[]] ($original -split "`r?`n"))
    $pattern = '^(\s*)' + [regex]::Escape($Key) + '\s*='
    $index = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match $pattern) { $index = $i; break } }
    if ($index -ge 0) {
        $indent = [regex]::Match($lines[$index], $pattern).Groups[1].Value
        $last = $index
        if ($lines[$index] -match '@\(' -and $lines[$index] -notmatch '\)') {
            while ($last + 1 -lt $lines.Count -and $lines[$last] -notmatch '\)') { $last++ }
        }
        if ($last -gt $index) { $lines.RemoveRange($index + 1, $last - $index) }
        $lines[$index] = "$indent$Key = $literal"
    } else {
        $close = -1
        for ($i = $lines.Count - 1; $i -ge 0; $i--) { if ($lines[$i].Trim() -eq '}') { $close = $i; break } }
        if ($close -lt 0) { throw "$SettingsFile has no closing '}'." }
        $lines.Insert($close, "    $Key = $literal")
    }
    Set-Content -LiteralPath $SettingsFile -Encoding utf8 -NoNewline -Value ($lines -join [Environment]::NewLine)
    try { $null = Read-SettingsFile $SettingsFile }
    catch {
        Set-Content -LiteralPath $SettingsFile -Encoding utf8 -NoNewline -Value $original
        throw "Could not save $Key to ${SettingsFile} (file restored): $($_.Exception.Message)"
    }
    Write-Host "  Saved to ${SettingsFile}: $Key = $literal"
}

if (-not (Test-Path -LiteralPath $SettingsTemplate)) {
    throw "deploy.settings.example.psd1 is missing next to deploy.ps1. Unpack the complete package."
}
# Defaults from the template, so settings missing in your file (e.g. new ones of a later version) are defined.
$SERVER = @{}
$SettingsDefaults = Read-SettingsFile $SettingsTemplate
foreach ($key in $SETTINGS_MAP.Keys) { Set-SettingValue $key $SettingsDefaults[$key] }

if (-not (Test-Path -LiteralPath $SettingsFile)) {
    Copy-Item -LiteralPath $SettingsTemplate -Destination $SettingsFile
    Write-Host "Settings file created from the template: $SettingsFile"
    Write-Host "  Adjust names there if needed; the script fills in the values it determines."
}
$UserSettings = Read-SettingsFile $SettingsFile
foreach ($key in $UserSettings.Keys) { Set-SettingValue $key $UserSettings[$key] }
Write-Host "Settings loaded: $SettingsFile"

if (-not $PSBoundParameters.ContainsKey('PowerPlatformServiceTags') -and @($POWER_PLATFORM_SERVICE_TAGS).Count -gt 0) {
    $PowerPlatformServiceTags = @($POWER_PLATFORM_SERVICE_TAGS)
}
$unset = @($SETTINGS_MAP.Keys | Where-Object { $_ -notin $SETTINGS_LISTS } | Where-Object {
               $value = "$(Get-SettingValue $_)"; $value -match '<' -and $value -ne '<auto>' })
if ($unset) { throw "Placeholders not replaced in ${SettingsFile}: $($unset -join ', ')." }
$MDCA_API_URL = "$MDCA_API_URL".Trim().TrimEnd('/') -replace '/(cas/)?api$', ''
if ($MDCA_API_URL -and $MDCA_API_URL -notmatch '^https://([a-z0-9-]+\.)*portal\.cloudappsecurity\.(com|us)$') {
    throw ("MdcaApiUrl '$MDCA_API_URL' is not a Defender for Cloud Apps API URL (portal: Settings > Cloud Apps > " +
           "System > About, e.g. https://contoso.eu2.portal.cloudappsecurity.com).")
}
if ($MDCA_AUTH -notin @('obo', 'token')) { throw "MdcaAuth must be 'obo' or 'token' (deploy.settings.psd1)." }

# ── Helper functions ───────────────────────────────────────────────────────────
function Write-Step([string] $Text) { Write-Host "`n==> $Text" -ForegroundColor Cyan }
function Write-Info([string] $Text) { Write-Host "    $Text" }
function Write-Warn([string] $Text) { Write-Host "    WARNING: $Text" -ForegroundColor Yellow }
function Test-Yes([string] $Answer) { return "$Answer".Trim() -match '^(y|yes)$' }

# Network errors that are typical in corporate networks (proxy, TLS inspection, firewall timeouts) and usually
# disappear on a retry. All write calls of this script are idempotent (PUT).
$TransientAzError = 'ConnectionResetError|Connection aborted|ConnectionError|RemoteDisconnected|10054|10060|' +
                    'Read timed out|timed out|SSLError|SSLEOFError|EOF occurred|Max retries exceeded|ProtocolError|' +
                    'IncompleteRead|ChunkedEncodingError|GatewayTimeout|ServiceUnavailable|TooManyRequests'

function Invoke-AzCli {
    param([Parameter(Mandatory)] [string[]] $Arguments, [switch] $AllowFailure, [int] $Retries = 4)
    $cmd = ($Arguments | Select-Object -First 4) -join ' '
    for ($attempt = 1; ; $attempt++) {
        $output = & az @Arguments --only-show-errors 2>&1
        $code = $LASTEXITCODE
        $stdout = (@($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n").Trim()
        if ($code -eq 0) { return $stdout }
        $stderr = (@($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } |
                     ForEach-Object { $_.ToString() }) -join "`n")
        $stderr = ($stderr -replace '(?:[\\|/-]\s+)?Running \.\.\s*', '').Trim()   # remove the progress indicator
        $script:LastAzError = $stderr
        if ($attempt -lt $Retries -and $stderr -match $TransientAzError) {
            $wait = 15 * $attempt
            Write-Warn "Connection dropped during 'az $cmd' (attempt $attempt/$Retries, probably proxy/firewall). Retrying in $wait s."
            Start-Sleep -Seconds $wait
            continue
        }
        if ($AllowFailure) { return $null }
        if ($stderr -match 'Traceback \(most recent') { $stderr = ($stderr -split 'Traceback \(most recent')[0].Trim() + ' [traceback truncated]' }
        if ($stderr -match $TransientAzError) {
            $stderr += ("`nThe connection to Azure was dropped repeatedly (proxy/firewall in the corporate network). Run the " +
                        "script again (it continues where it stopped) or run it in Azure Cloud Shell (PowerShell).")
        }
        throw "az $cmd failed (exit $code):`n$stderr"
    }
}

# Waits for a final state by polling briefly and repeatedly. Long-lived connections (az ... without
# --no-wait) are often cut by corporate proxies after a few minutes; short requests are not.
function Wait-AzState {
    param([Parameter(Mandatory)] [string[]] $StateArguments, [Parameter(Mandatory)] [string] $What,
          [int] $TimeoutMinutes = 45, [int] $IntervalSeconds = 20)
    $start = Get-Date
    $last = $null
    while ($true) {
        $state = Invoke-AzCli -Arguments ($StateArguments + @('-o', 'tsv')) -AllowFailure
        if ($state -eq 'Succeeded') {
            Write-Info ("{0}: ready ({1:mm\:ss} min)." -f $What, ((Get-Date) - $start))
            return
        }
        if ($state -match '^(Failed|Canceled|Cancelled|Error|Timeout)$') {
            throw "${What}: operation ended with status '$state'."
        }
        if (((Get-Date) - $start).TotalMinutes -gt $TimeoutMinutes) {
            throw "${What}: not finished after $TimeoutMinutes minutes (status '$state'). Run the script again later."
        }
        if ($state -ne $last) { Write-Info ("{0}: {1} ..." -f $What, ($state ?? 'creating')); $last = $state }
        Start-Sleep -Seconds $IntervalSeconds
    }
}

# Graph URL of an app registration by its object ID. Deliberately not "applications(appId='...')": on Windows
# az is a batch file (az.cmd), and cmd.exe interprets parentheses in arguments without spaces.
function Get-AppGraphUrl([string] $AppId) {
    $objectId = Invoke-AzCli -Arguments @('ad', 'app', 'show', '--id', $AppId, '--query', 'id', '-o', 'tsv')
    if (-not $objectId) { throw "App registration $AppId not found." }
    return "https://graph.microsoft.com/v1.0/applications/$objectId"
}

# Sets the web redirect URIs of an app registration through Microsoft Graph (an empty list too).
function Set-AppRedirectUris([string] $AppId, [string[]] $Uris) {
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($tmp, (@{ web = @{ redirectUris = @($Uris | Where-Object { $_ }) } } | ConvertTo-Json -Depth 5 -Compress))
        Invoke-AzCli -Arguments @('rest', '--method', 'patch', '--url', (Get-AppGraphUrl $AppId),
                                  '--headers', 'Content-Type=application/json', '--body', "@$tmp") | Out-Null
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

# Microsoft Graph call with a JSON body through a temporary file (no quoting issues in PowerShell).
function Invoke-GraphJson([string] $Method, [string] $Url, [hashtable] $Body) {
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($tmp, ($Body | ConvertTo-Json -Depth 5 -Compress))
        return Invoke-AzCli -Arguments @('rest', '--method', $Method, '--url', $Url,
                                         '--headers', 'Content-Type=application/json', '--body', "@$tmp")
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

# Assigns groups to the enterprise application (default access) and turns on "Assignment required".
function Set-AppAssignment([string] $AppId, [string] $Label, [string[]] $GroupIds) {
    $spId = Invoke-AzCli -Arguments @('ad', 'sp', 'show', '--id', $AppId, '--query', 'id', '-o', 'tsv')
    $existing = @((Invoke-AzCli -Arguments @('rest', '--method', 'get', '--url',
                     "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignedTo?`$select=principalId,principalType",
                     '--query', 'value[].principalId', '-o', 'tsv')) -split "`n" | Where-Object { $_ })
    foreach ($groupId in $GroupIds) {
        $groupName = Invoke-AzCli -Arguments @('ad', 'group', 'show', '--group', $groupId, '--query', 'displayName', '-o', 'tsv') -AllowFailure
        if (-not $groupName) { throw "Group $groupId not found (specify the object ID of the group)." }
        if ($existing -contains $groupId) { Write-Info "${Label}: group '$groupName' already assigned."; continue }
        Invoke-GraphJson 'post' "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignedTo" @{
            principalId = $groupId; resourceId = $spId; appRoleId = '00000000-0000-0000-0000-000000000000'
        } | Out-Null
        Write-Info "${Label}: group '$groupName' assigned (default access)."
        $existing += $groupId
    }
    if ($existing.Count -eq 0) {
        throw "${Label}: no assignment exists. 'Assignment required' would lock everyone out; specify a group."
    }
    $required = Invoke-AzCli -Arguments @('ad', 'sp', 'show', '--id', $AppId, '--query', 'appRoleAssignmentRequired', '-o', 'tsv')
    if ($required -ne 'true') {
        Invoke-AzCli -Arguments @('ad', 'sp', 'update', '--id', $AppId, '--set', 'appRoleAssignmentRequired=true') | Out-Null
        Write-Info "${Label}: 'Assignment required' turned on ($($existing.Count) assignment(s))."
    }
}

function Test-Interactive { return (-not $NoPrompt) -and [Environment]::UserInteractive }

# Only reuse app registrations owned by the signed-in user. Any user can (depending on
# tenant settings) create apps with any name; an app owned by someone else must never receive consent or secrets.
function Find-OwnedApp([string] $DisplayName) {
    $raw = Invoke-AzCli -Arguments @('ad', 'app', 'list', '--display-name', $DisplayName, '--query',
                                     "[?displayName=='$DisplayName'].appId", '-o', 'tsv') -AllowFailure
    $found = @("$raw" -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $mine = @()
    if ($meId) {
        foreach ($appId in $found) {
            $owners = "$(Invoke-AzCli -Arguments @('ad', 'app', 'owner', 'list', '--id', $appId, '--query', '[].id', '-o', 'tsv') -AllowFailure)"
            if ($owners -split "`n" -contains $meId) { $mine += $appId }
        }
    }
    return [pscustomobject]@{ Found = $found; Mine = $mine }
}

# Creates the service principal (enterprise application) if missing; waits for the replication of new apps.
function Confirm-ServicePrincipal([string] $AppId) {
    for ($i = 1; $i -le 6; $i++) {
        if (Invoke-AzCli -Arguments @('ad', 'sp', 'show', '--id', $AppId, '--query', 'id', '-o', 'tsv') -AllowFailure) { return }
        if (Invoke-AzCli -Arguments @('ad', 'sp', 'create', '--id', $AppId, '--query', 'id', '-o', 'tsv') -AllowFailure) {
            Write-Info "Service principal for $AppId created."
            return
        }
        Start-Sleep -Seconds 10
    }
    throw "Service principal for $AppId could not be created: $($script:LastAzError)"
}

# Application ID URI api://<appId>, delegated scope and token version 2 on the server app.
function Set-ApiScope([string] $AppId, [string] $ScopeName) {
    $appUrl = Get-AppGraphUrl $AppId
    $app = Invoke-AzCli -Arguments @('rest', '--method', 'get', '--url', "${appUrl}?`$select=id,identifierUris,api",
                                     '-o', 'json') | ConvertFrom-Json
    $uri = "api://$AppId"
    if (@($app.identifierUris) -notcontains $uri) {
        Invoke-GraphJson 'patch' $appUrl @{
            identifierUris = @(@($app.identifierUris | Where-Object { $_ }) + $uri)
        } | Out-Null
        Write-Info "Application ID URI set: $uri"
    }
    $scopes = @($app.api.oauth2PermissionScopes | Where-Object { $_ })
    $needScope = -not ($scopes | Where-Object { $_.value -eq $ScopeName })
    if ($needScope -or $app.api.requestedAccessTokenVersion -ne 2) {
        if ($needScope) {
            $text = 'Allows Copilot Studio to call the Defender XDR MCP Server on behalf of the signed-in user. ' +
                    'The server reads Defender data and performs actions only with the permissions of this user.'
            $scopes += [pscustomobject]@{
                id = [guid]::NewGuid().ToString(); value = $ScopeName; type = 'Admin'; isEnabled = $true
                adminConsentDisplayName = 'Use Defender XDR MCP Server'; adminConsentDescription = $text
                userConsentDisplayName = 'Use Defender XDR MCP Server'; userConsentDescription = $text
            }
        }
        # Send back the complete api object (existing scopes, pre-authorized apps etc. are preserved).
        $api = @{}
        if ($app.api) { $app.api.PSObject.Properties | ForEach-Object { $api[$_.Name] = $_.Value } }
        $api.requestedAccessTokenVersion = 2
        $api.oauth2PermissionScopes = @($scopes)
        Invoke-GraphJson 'patch' $appUrl @{ api = $api } | Out-Null
        if ($needScope) { Write-Info "Scope '$ScopeName' created under 'Expose an API' (consent by admins only)." }
        Write-Info "requestedAccessTokenVersion = 2."
    }
}

# Asks interactively for groups (name or object ID) and returns their object IDs; empty = skipped.
function Request-AllowedGroups {
    Write-Host ""
    Write-Warn "'Assignment required' is off: every user of the tenant who can reach the agent can use the server."
    while ($true) {
        $answer = Read-Host "    Group(s) with access (display name or object ID, several separated by commas; Enter = skip)"
        if ([string]::IsNullOrWhiteSpace($answer)) { return @() }
        $picked = [System.Collections.Generic.List[object]]::new()
        $failed = $false
        foreach ($term in @($answer -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
            $query = if ($term -match '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') {
                @('ad', 'group', 'show', '--group', $term, '--query', '[{id:id, name:displayName}]', '-o', 'json')
            } else {
                @('ad', 'group', 'list', '--display-name', $term, '--query', '[].{id:id, name:displayName}', '-o', 'json')
            }
            $raw = Invoke-AzCli -Arguments $query -AllowFailure
            $found = @(if ($raw) { $raw | ConvertFrom-Json })
            $exact = @($found | Where-Object { $_.name -eq $term })
            if ($exact.Count -eq 1) { $found = $exact }
            if ($found.Count -eq 0) {
                Write-Warn "No group found for '$term'."
                $failed = $true
            } elseif ($found.Count -eq 1) {
                $picked.Add($found[0])
            } else {
                Write-Host "    Several groups start with '$term':"
                $shown = @($found | Select-Object -First 15)
                for ($n = 0; $n -lt $shown.Count; $n++) { Write-Host ("      [{0}] {1}  ({2})" -f ($n + 1), $shown[$n].name, $shown[$n].id) }
                $choice = Read-Host "    Choose a number (Enter = none)"
                if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $shown.Count) {
                    $picked.Add($shown[[int]$choice - 1])
                } else { $failed = $true }
            }
        }
        if ($failed -or $picked.Count -eq 0) { Write-Host "    Please enter again."; continue }
        $picked | ForEach-Object { Write-Host ("      - {0}  ({1})" -f $_.name, $_.id) }
        Write-Host "    Note: only DIRECT members of these groups get access (no nested groups)."
        $ok = Read-Host "    Restrict access to these group(s)? (yes/no)"
        if (-not (Test-Yes $ok)) { continue }
        $ids = @($picked | ForEach-Object { $_.id } | Sort-Object -Unique)
        $save = Read-Host "    Save the selection to deploy.settings.psd1 so future runs do not ask again? (yes/no)"
        if (Test-Yes $save) { Save-Setting 'AllowedGroupIds' $ids }
        return $ids
    }
}

function Get-ArmApiVersion([string] $Namespace, [string] $ResourceType) {
    $versions = @(Invoke-AzCli -Arguments @('provider', 'show', '--namespace', $Namespace, '--query',
                                            "resourceTypes[?resourceType=='$ResourceType'] | [0].apiVersions", '-o', 'json') |
                  ConvertFrom-Json) | Sort-Object -Descending
    if (-not $versions) { throw "No API version found for $Namespace/$ResourceType." }
    return ($versions | Where-Object { $_ -notmatch 'preview' } | Select-Object -First 1) ?? $versions[0]
}

function Test-AzExists([string[]] $ShowArguments) {
    return [bool](Invoke-AzCli -Arguments ($ShowArguments + @('--query', 'id', '-o', 'tsv')) -AllowFailure)
}

# Names in the global namespace (container registry, Key Vault). Suffix from subscription and resource group;
# attempt 0 is the default suffix, further attempts yield other suffixes.
function Get-NameSuffix([int] $Attempt) {
    $seed = "$($account.id)/$RG".ToLower()
    if ($Attempt -gt 0) { $seed += "/$Attempt" }
    $hash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($seed))
    return ([System.BitConverter]::ToString($hash) -replace '-', '').Substring(0, 6).ToLower()
}

# Is the registry name free? $true / $false; $null = unknown (check not possible). Reason in $script:NameReason.
function Test-AcrNameFree([string] $Name) {
    $script:NameReason = ''
    $raw = Invoke-AzCli -Arguments @('acr', 'check-name', '--name', $Name, '-o', 'json') -AllowFailure
    if (-not $raw) { return $null }
    $res = $raw | ConvertFrom-Json
    $script:NameReason = "$($res.reason) $($res.message)".Trim()
    return [bool]$res.nameAvailable
}

# Is the Key Vault name free (ARM checkNameAvailability)? $true / $false; $null = unknown. Reason in $script:NameReason.
# 'az keyvault check-name' only checks Managed HSM names.
function Test-KeyVaultNameFree([string] $Name) {
    $script:NameReason = ''
    try { $api = Get-ArmApiVersion 'Microsoft.KeyVault' 'checkNameAvailability' } catch { $api = '2024-11-01' }
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($tmp, (@{ name = $Name; type = 'Microsoft.KeyVault/vaults' } | ConvertTo-Json -Compress))
        $raw = Invoke-AzCli -Arguments @('rest', '--method', 'post', '--url',
                   "/subscriptions/$($account.id)/providers/Microsoft.KeyVault/checkNameAvailability?api-version=$api",
                   '--headers', 'Content-Type=application/json', '--body', "@$tmp", '-o', 'json') -AllowFailure
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    if (-not $raw) { return $null }
    $res = $raw | ConvertFrom-Json
    $script:NameReason = "$($res.reason) $($res.message)".Trim()
    return [bool]$res.nameAvailable
}

# Deleted but still recoverable Key Vault of this name in this subscription (soft delete):
# resource ID of the original vault, otherwise $null.
function Get-DeletedKeyVaultId([string] $Name) {
    return Invoke-AzCli -Arguments @('keyvault', 'show-deleted', '--name', $Name, '--query', 'properties.vaultId',
                                     '-o', 'tsv') -AllowFailure
}

# State of a Key Vault name for this resource group: 'ours' (exists, or deleted and recoverable),
# 'free', 'taken' or 'unknown'.
function Get-KeyVaultNameState([string] $Name) {
    if (Test-AzExists @('keyvault', 'show', '--name', $Name, '--resource-group', $RG)) { return 'ours' }
    $deletedId = Get-DeletedKeyVaultId $Name
    if ($deletedId) {
        if ($deletedId -match "/resourceGroups/$([regex]::Escape($RG))/") { return 'ours' }
        $script:NameReason = "deleted vault of another resource group: $deletedId"
        return 'taken'
    }
    $free = Test-KeyVaultNameFree $Name
    if ($null -eq $free) { return 'unknown' }
    if ($free) { return 'free' }
    return 'taken'
}

# Secrets are read/written through the management plane (ARM, management.azure.com), not through
# <vault>.vault.azure.net. This PC therefore needs neither network access to the Key Vault data plane (proxy/firewall
# in the corporate network) nor the role 'Key Vault Secrets Officer'. ARM only returns metadata, never secret values.
function Test-KvSecret([string] $Name) {
    return [bool](Invoke-AzCli -Arguments @('resource', 'show', '--ids', "$($script:KV_ID)/secrets/$Name",
                                            '--query', 'id', '-o', 'tsv') -AllowFailure)
}

function Set-KvSecret([string] $Name, [string] $Value, [string] $ContentType = '') {
    # Pass the value through a temporary file: not in the process list, not in the output.
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        $props = @{ value = $Value }
        if ($ContentType) { $props.contentType = $ContentType }
        [System.IO.File]::WriteAllText($tmp, ($props | ConvertTo-Json -Compress))
        Invoke-AzCli -Arguments @('resource', 'create', '--id', "$($script:KV_ID)/secrets/$Name",
                                  '--properties', "@$tmp", '--query', 'id', '-o', 'tsv') | Out-Null
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function New-UrlSafeKey([int] $Bytes) {
    $buffer = [byte[]]::new($Bytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
    $key = [Convert]::ToBase64String($buffer).Replace('+', '-').Replace('/', '_')
    return $key.TrimEnd('=')
}

# ── Preparation ────────────────────────────────────────────────────────────────
$Root = $PSScriptRoot
if ("$($SERVER.App)$($SERVER.ClientId)" -match '<') { throw "Placeholders for ContainerApp/ServerClientId not replaced (deploy.settings.psd1)." }
$APP = $SERVER.App
$CLIENT_ID = $SERVER.ClientId
$SCOPE = $SERVER.Scope
$PREFIX = $SERVER.SecretPrefix
$GROUP_IDS = @((@($SERVER.AllowedGroupIds) + $AllowedGroupIds) | Where-Object { $_ } | Sort-Object -Unique)
$APPREG_NAME = if ($SERVER.AppRegName) { $SERVER.AppRegName } else { "appreg-defender-mcp-api-$APPREG_ENV" }
$COPILOT_APP_NAME = if ($SERVER.CopilotClientAppName) { $SERVER.CopilotClientAppName } else { "appreg-defender-mcp-copilot-client-$APPREG_ENV" }

# ── Quick mode: only add the redirect URL of the Copilot client app ───────────
if ($AddRedirectUri.Count -gt 0) {
    Write-Host "deploy.ps1 version $ScriptVersion (redirect URL only)" -ForegroundColor Green
    $newUris = @($AddRedirectUri | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    foreach ($u in $newUris) {
        $parsed = $null
        if (-not [Uri]::TryCreate($u, [UriKind]::Absolute, [ref] $parsed) -or $parsed.Scheme -ne 'https') {
            throw "Not a valid https URL: '$u'"
        }
        if ($parsed.Host -notlike '*.consent.azure-apim.net') {
            Write-Warn "'$u' does not look like a Copilot Studio redirect URL (expected *.consent.azure-apim.net)."
        }
    }
    $tenantNow = Invoke-AzCli -Arguments @('account', 'show', '--query', 'tenantId', '-o', 'tsv')
    if ($TENANT_ID -and $TENANT_ID -ne '<auto>' -and $tenantNow -ne $TENANT_ID) {
        throw "az is signed in to tenant $tenantNow, expected: $TENANT_ID (az login --tenant $TENANT_ID)."
    }
    $COPILOT_APP_ID = $SERVER.CopilotClientAppId
    if (-not $COPILOT_APP_ID) {
        $lookup = Find-OwnedApp $COPILOT_APP_NAME
        if ($lookup.Mine.Count -ge 1) { $COPILOT_APP_ID = $lookup.Mine[0] }
    }
    if (-not $COPILOT_APP_ID) {
        throw "Copilot client app '$COPILOT_APP_NAME' not found. Run ./deploy.ps1 -ConfigureAppRegistration first."
    }
    if ($PROTECTED_APP_IDS -contains $COPILOT_APP_ID) { throw "The client app $COPILOT_APP_ID is protected." }
    Write-Step "Add redirect URL to client app $COPILOT_APP_ID ($COPILOT_APP_NAME)"
    $current = @("$(Invoke-AzCli -Arguments @('ad', 'app', 'show', '--id', $COPILOT_APP_ID, '--query', 'web.redirectUris',
                                              '-o', 'tsv'))" -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $wanted = @(($current + $newUris) | Sort-Object -Unique)
    $added = @($newUris | Where-Object { $current -notcontains $_ } | Sort-Object -Unique)
    if ($added.Count -eq 0) {
        Write-Info "Already present, nothing to do."
    } else {
        Set-AppRedirectUris $COPILOT_APP_ID $wanted
        $added | ForEach-Object { Write-Info "Eingetragen: $_" }
    }
    Write-Info ("Redirect URLs now: " + ($wanted -join ', '))
    Write-Host "`nDone. Create the connection in Copilot Studio or sign in again (the change can take 1-2 minutes)." -ForegroundColor Green
    return
}

Write-Host "deploy.ps1 version $ScriptVersion" -ForegroundColor Green
Write-Step "Checking sign-in and prerequisites"
$account = Invoke-AzCli -Arguments @('account', 'show', '--query', '{name:name, id:id, tenant:tenantId}', '-o', 'json') | ConvertFrom-Json
if (-not $TENANT_ID -or $TENANT_ID -eq '<auto>') {
    $TENANT_ID = $account.tenant
    Save-Setting 'TenantId' $TENANT_ID
}
if ($account.tenant -ne $TENANT_ID) { throw "az is signed in to tenant $($account.tenant), expected: $TENANT_ID (az login --tenant $TENANT_ID)." }
Write-Info "Subscription: $($account.name) ($($account.id))"
Write-Info "App: $APP | Image-Tag: $Tag"
# No CLI extensions needed: 'az containerapp' is part of the Azure CLI.
# This avoids the pip download that often fails in networks with proxy/TLS inspection.
$cliVersion = (Invoke-AzCli -Arguments @('version', '-o', 'json') | ConvertFrom-Json).'azure-cli'
Write-Info "Azure CLI $cliVersion"
if ([version]$cliVersion -lt [version]'2.60.0') { throw "Azure CLI $cliVersion is too old (at least 2.60): winget upgrade -e --id Microsoft.AzureCLI" }
if (-not (Invoke-AzCli -Arguments @('bicep', 'version') -AllowFailure)) {
    Write-Info "Bicep CLI missing, trying 'az bicep install'..."
    if ($null -eq (Invoke-AzCli -Arguments @('bicep', 'install') -AllowFailure)) {
        throw ("Bicep CLI could not be downloaded (github.com blocked?). Alternative: " +
               "'winget install -e --id Microsoft.Bicep' and then 'az config set bicep.use_binary_from_path=true'.")
    }
}
foreach ($ns in 'Microsoft.App', 'Microsoft.ContainerRegistry', 'Microsoft.OperationalInsights', 'Microsoft.Insights',
                'Microsoft.KeyVault', 'Microsoft.ManagedIdentity') {
    $state = Invoke-AzCli -Arguments @('provider', 'show', '--namespace', $ns, '--query', 'registrationState', '-o', 'tsv')
    if ($state -ne 'Registered') {
        Write-Info "Registering resource provider $ns..."
        Invoke-AzCli -Arguments @('provider', 'register', '--namespace', $ns, '--wait') | Out-Null
    }
}

# Globally unique names (container registry, Key Vault): fixed suffix from subscription and resource group
# (same input = same name). If a name is taken (another tenant, deleted vault of another resource
# group), the script takes the next suffix. The result is then saved in deploy.settings.psd1.
# Only after the resource providers are registered: otherwise Azure cannot check availability.
$nameSuffix = Get-NameSuffix 0
if (-not $ACR -or $ACR -eq '<auto>') {
    $ACR = $null
    foreach ($attempt in 0..4) {
        $candidate = "crdefendermcpprod$(Get-NameSuffix $attempt)"
        $usable = Test-AzExists @('acr', 'show', '--name', $candidate, '--resource-group', $RG)
        if (-not $usable) { $usable = ((Test-AcrNameFree $candidate) -ne $false) }
        if ($usable) {
            $ACR = $candidate
            break
        }
        Write-Info "Registry name $candidate is taken ($script:NameReason); trying the next one."
    }
    if (-not $ACR) { throw "No free name found for the container registry. Set one in deploy.settings.psd1: ContainerRegistry = '<name>'." }
    Save-Setting 'ContainerRegistry' $ACR
}
if (-not $KEYVAULT -or $KEYVAULT -eq '<auto>') {
    $KEYVAULT = $null
    foreach ($attempt in 0..4) {
        $candidate = "kv-defxdrmcp-prod-$(Get-NameSuffix $attempt)"
        if ((Get-KeyVaultNameState $candidate) -ne 'taken') {
            $KEYVAULT = $candidate
            break
        }
        Write-Info "Key Vault name $candidate is taken ($script:NameReason); trying the next one."
    }
    if (-not $KEYVAULT) { throw "No free name found for the Key Vault. Set one in deploy.settings.psd1: KeyVault = '<name>'." }
    Save-Setting 'KeyVault' $KEYVAULT
}
# Check the naming rules before anything is created (also for names set manually).
if ($KEYVAULT -notmatch '^[A-Za-z](?!.*--)[A-Za-z0-9-]{1,22}[A-Za-z0-9]$') {
    throw ("Key Vault name '$KEYVAULT' is invalid: 3-24 characters (letters, digits, hyphens), starting with a " +
           "letter, ending with a letter or digit, no consecutive hyphens.")
}
if ($ACR -notmatch '^[A-Za-z0-9]{5,50}$') { throw "Registry name '$ACR' is invalid: 5-50 characters, letters and digits only." }
Write-Info "Resource Group: $RG | Region: $LOCATION | ACR: $ACR | Key Vault: $KEYVAULT"

$meId = Invoke-AzCli -Arguments @('ad', 'signed-in-user', 'show', '--query', 'id', '-o', 'tsv') -AllowFailure
if ($meId) {
    $rgScope = "/subscriptions/$($account.id)/resourceGroups/$RG"
    $myRoles = @((Invoke-AzCli -Arguments @('role', 'assignment', 'list', '--assignee', $meId, '--scope', $rgScope,
                                            '--include-inherited', '--include-groups', '--query', '[].roleDefinitionName',
                                            '-o', 'tsv') -AllowFailure) -split "`n" | Where-Object { $_ })
    Write-Info ("Your roles on {0}: {1}" -f $RG, ($(if ($myRoles) { $myRoles -join ', ' } else { '(none found)' })))
    $canAssign = @($myRoles | Where-Object { $_ -in 'Owner', 'User Access Administrator', 'Role Based Access Control Administrator' })
    if (-not $canAssign) {
        Write-Warn ("Your account probably cannot assign roles (needs Owner, User Access Administrator or " +
                    "Role Based Access Control Administrator on $RG, activate via PIM if needed). Bicep assigns " +
                    "'Key Vault Secrets User' and 'AcrPull' to the app's managed identity.")
    }
} else {
    Write-Warn "The signed-in identity is not a user (service principal?): role check skipped."
}

# ── App registration of the server ─────────────────────────────────────────────
$serverAppCreated = $false
if ($CLIENT_ID -and $PROTECTED_APP_IDS -contains $CLIENT_ID) {
    Write-Warn "The configured server app $CLIENT_ID is protected and is not changed by this script."
    $useNew = if (Test-Interactive) {
        Read-Host "    Create or use a new app registration '$APPREG_NAME' instead? (yes/no)"
    } else { 'no' }
    if (Test-Yes $useNew) { $CLIENT_ID = '' }
}
if (-not $CLIENT_ID) {
    Write-Step "App registration for the server ($APPREG_NAME)"
    $lookup = Find-OwnedApp $APPREG_NAME
    if ($lookup.Mine.Count -eq 1) {
        $CLIENT_ID = $lookup.Mine[0]
        Write-Info "Existing app registration '$APPREG_NAME' reused (you are an owner): $CLIENT_ID"
    } elseif ($lookup.Mine.Count -gt 1) {
        throw "You own several app registrations '$APPREG_NAME' ($($lookup.Mine -join ', ')). Set ServerClientId in deploy.settings.psd1."
    } elseif ($lookup.Found.Count -gt 0) {
        throw ("There are app registration(s) '$APPREG_NAME' ($($lookup.Found -join ', ')) you do not own. For " +
               "security reasons the script never takes over an app it does not own. If it is yours: set the ClientId in " +
               "deploy.settings.psd1. Otherwise change ServerAppRegName in deploy.settings.psd1.")
    } else {
        if (Test-Interactive) {
            $ok = Read-Host "    No ClientId configured. Create a new app registration '$APPREG_NAME' (own tenant only)? (yes/no)"
            if (-not (Test-Yes $ok)) { throw 'Cancelled: set ServerClientId in deploy.settings.psd1 or confirm the creation.' }
        } elseif (-not $ConfigureAppRegistration) {
            throw 'No ClientId configured. Without a prompt the script only creates the app with -ConfigureAppRegistration.'
        }
        $CLIENT_ID = Invoke-AzCli -Arguments @('ad', 'app', 'create', '--display-name', $APPREG_NAME, '--sign-in-audience', 'AzureADMyOrg',
                                               '--query', 'appId', '-o', 'tsv')
        Write-Info "App registration '$APPREG_NAME' created: $CLIENT_ID (waiting 20 s for replication in Entra)"
        Start-Sleep -Seconds 20
        $serverAppCreated = $true
    }
    Save-Setting 'ServerClientId' $CLIENT_ID
    # Fully set up a new or reused app (scope, token v2, permissions, consent).
    $ConfigureAppRegistration = $true
}
$SERVER_APP_PROTECTED = $PROTECTED_APP_IDS -contains $CLIENT_ID
Write-Info ("Server app: $CLIENT_ID" + $(if ($SERVER_APP_PROTECTED) { ' (protected: no changes)' } else { '' }))

# ── Base resources (idempotent) ────────────────────────────────────────────────
Write-Step "Resource group, container registry, Log Analytics, environment"
Invoke-AzCli -Arguments @('group', 'create', '--name', $RG, '--location', $LOCATION) | Out-Null

if (-not (Test-AzExists @('acr', 'show', '--name', $ACR, '--resource-group', $RG))) {
    if ((Test-AcrNameFree $ACR) -eq $false) {
        throw ("The registry name $ACR is taken ($script:NameReason). Container registry names are globally " +
               "unique: set another name in deploy.settings.psd1 (ContainerRegistry = '<name>') or '<auto>'.")
    }
    Invoke-AzCli -Arguments @('acr', 'create', '--name', $ACR, '--resource-group', $RG, '--sku', 'Basic',
                              '--admin-enabled', 'false') | Out-Null
    Write-Info "ACR $ACR created."
}
$ACR_SERVER = Invoke-AzCli -Arguments @('acr', 'show', '--name', $ACR, '--query', 'loginServer', '-o', 'tsv')

if (-not (Test-AzExists @('monitor', 'log-analytics', 'workspace', 'show', '--resource-group', $RG, '--workspace-name', $LOG_WS))) {
    Invoke-AzCli -Arguments @('monitor', 'log-analytics', 'workspace', 'create', '--resource-group', $RG,
                              '--workspace-name', $LOG_WS, '--location', $LOCATION, '--no-wait') | Out-Null
    Write-Info "Creating Log Analytics $LOG_WS."
}
$logWsId = "/subscriptions/$($account.id)/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$LOG_WS"
Wait-AzState -What "Log Analytics $LOG_WS" -StateArguments @('resource', 'show', '--ids', $logWsId,
    '--query', 'properties.provisioningState')

if (-not (Test-AzExists @('containerapp', 'env', 'show', '--name', $ENV_NAME, '--resource-group', $RG))) {
    $logId = Invoke-AzCli -Arguments @('monitor', 'log-analytics', 'workspace', 'show', '--resource-group', $RG,
                                       '--workspace-name', $LOG_WS, '--query', 'customerId', '-o', 'tsv')
    $logKey = Invoke-AzCli -Arguments @('monitor', 'log-analytics', 'workspace', 'get-shared-keys', '--resource-group', $RG,
                                        '--workspace-name', $LOG_WS, '--query', 'primarySharedKey', '-o', 'tsv')
    Invoke-AzCli -Arguments @('containerapp', 'env', 'create', '--name', $ENV_NAME, '--resource-group', $RG,
                              '--location', $LOCATION, '--logs-workspace-id', $logId, '--logs-workspace-key', $logKey,
                              '--no-wait') | Out-Null
    Remove-Variable logKey
    Write-Info "Creating Container Apps environment $ENV_NAME (usually takes 3-10 minutes)."
}
Wait-AzState -What "Container Apps environment $ENV_NAME" -StateArguments @('containerapp', 'env', 'show',
    '--name', $ENV_NAME, '--resource-group', $RG, '--query', 'properties.provisioningState')
$envDomain = Invoke-AzCli -Arguments @('containerapp', 'env', 'show', '--name', $ENV_NAME, '--resource-group', $RG,
                                       '--query', 'properties.defaultDomain', '-o', 'tsv')
$BASE_URL = "https://$APP.$envDomain"
Write-Info "BASE_URL: $BASE_URL"

# ── Key Vault ──────────────────────────────────────────────────────────────────
Write-Step "Key Vault $KEYVAULT"
if (-not (Test-AzExists @('keyvault', 'show', '--name', $KEYVAULT, '--resource-group', $RG))) {
    $deletedId = Get-DeletedKeyVaultId $KEYVAULT
    if ($deletedId) {
        if ($deletedId -notmatch "/resourceGroups/$([regex]::Escape($RG))/") {
            throw ("Key Vault $KEYVAULT is deleted but still recoverable (soft delete) and belonged to another " +
                   "resource group ($deletedId). Recover it there, purge it (az keyvault purge -n $KEYVAULT, only " +
                   "without purge protection) or set another name in deploy.settings.psd1 (KeyVault).")
        }
        Write-Info "Key Vault $KEYVAULT is deleted but recoverable (soft delete): recovering it with its secrets ..."
        Invoke-AzCli -Arguments @('keyvault', 'recover', '--name', $KEYVAULT) | Out-Null
        Write-Info "Key Vault recovered. The script replaces secrets that belong to another app registration automatically."
    } else {
        if ((Test-KeyVaultNameFree $KEYVAULT) -eq $false) {
            throw ("The Key Vault name $KEYVAULT is taken ($script:NameReason). Key Vault names are globally " +
                   "unique: set another name in deploy.settings.psd1 (KeyVault = '<name>') or '<auto>'.")
        }
        Invoke-AzCli -Arguments @('keyvault', 'create', '--name', $KEYVAULT, '--resource-group', $RG, '--location', $LOCATION,
                                  '--enable-rbac-authorization', 'true', '--retention-days', '90') | Out-Null
        Write-Info "Key Vault created (RBAC mode)."
    }
}
$kv = Invoke-AzCli -Arguments @('keyvault', 'show', '--name', $KEYVAULT, '--query',
                                '{id:id, rbac:properties.enableRbacAuthorization, publicAccess:properties.publicNetworkAccess, firewall:properties.networkAcls.defaultAction}',
                                '-o', 'json') | ConvertFrom-Json
Write-Info ("RBAC mode: {0} | public access: {1} | firewall: {2}" -f $kv.rbac, $kv.publicAccess, $kv.firewall)
if ($kv.rbac -ne $true) {
    throw ("Key Vault $KEYVAULT uses access policies instead of Azure RBAC. Switch with " +
           "'az keyvault update -n $KEYVAULT --enable-rbac-authorization true' or set a new vault name (KeyVault) in deploy.settings.psd1.")
}
if ($kv.publicAccess -eq 'Disabled' -or $kv.firewall -eq 'Deny') {
    throw ("Key Vault $KEYVAULT blocks public network access (publicNetworkAccess=$($kv.publicAccess), " +
           "firewall=$($kv.firewall)), probably because of an Azure Policy. The container app (without VNet) then cannot " +
           "read its secrets. Request an exemption for the resource group or switch to VNet + private endpoint.")
}

$script:KV_ID = $kv.id
Write-Info "Secrets are written through ARM (no access to $KEYVAULT.vault.azure.net needed from this PC)."

# ── Secrets in Key Vault ───────────────────────────────────────────────────────
Write-Step "Secrets in Key Vault (prefix $PREFIX)"
$name = "${PREFIX}client-secret"
$rotatedSecret = $null
# Which app does the secret in Key Vault belong to? (content type "appId=<id>;keyId=<id>", set at creation)
$kvSecretPath = "$($script:KV_ID)/secrets/$name"
$kvCt = $null
if (Test-KvSecret $name) {
    $kvCt = "" + (Invoke-AzCli -Arguments @('resource', 'show', '--ids', $kvSecretPath, '--query', 'properties.contentType', '-o', 'tsv') -AllowFailure)
}
$kvAppId = if ("$kvCt" -match 'appId=([0-9a-fA-F-]{36})') { $Matches[1].ToLower() } else { '' }
# Protected app: an existing (manually entered) secret without appId is reused.
# Own app: only a secret that provably belongs to it is reused; otherwise create a new secret.
$secretForOtherApp = $false
if ($null -ne $kvCt) {
    if ($SERVER_APP_PROTECTED) { $secretForOtherApp = [bool]($kvAppId -and $kvAppId -ne $CLIENT_ID.ToLower()) }
    else { $secretForOtherApp = ($kvAppId -ne $CLIENT_ID.ToLower()) }
}
if ($secretForOtherApp) { Write-Info "The secret in Key Vault does not belong to the server app ${CLIENT_ID}: creating a new secret." }
if ($RotateClientSecret -and $SERVER_APP_PROTECTED) {
    throw "The server app $CLIENT_ID is protected: -RotateClientSecret is not allowed."
}
if ($RotateClientSecret -or $null -eq $kvCt -or $secretForOtherApp) {
    # Let Entra create the secret: it never appears in the output or in the clipboard.
    $rotatedSecret = "defender-mcp-$(Get-Date -Format 'yyyyMMddHHmmss')"
    $secretKeyId = 'unknown'
    $plain = if ($SERVER_APP_PROTECTED) { $null } else {
        Invoke-AzCli -Arguments @('ad', 'app', 'credential', 'reset', '--id', $CLIENT_ID, '--append',
                                  '--display-name', $rotatedSecret, '--years', '1', '--query', 'password', '-o', 'tsv') -AllowFailure
    }
    if ($plain) {
        # Remember the keyId: -RemoveOldClientSecrets keeps exactly the secret stored in Key Vault.
        $found = Invoke-AzCli -Arguments @('ad', 'app', 'credential', 'list', '--id', $CLIENT_ID, '--query',
                                           "[?displayName=='$rotatedSecret'].keyId | [0]", '-o', 'tsv') -AllowFailure
        if ($found) { $secretKeyId = $found }
        Write-Info "New client secret '$rotatedSecret' (1 year) created, stored only in Key Vault."
    } else {
        if (-not $SERVER_APP_PROTECTED) {
            Write-Warn "The secret could not be created automatically (role Application Administrator or app owner required): $($script:LastAzError)"
        }
        $secure = Read-Host -AsSecureString "Enter the client secret of app registration $CLIENT_ID"
        $plain = [System.Net.NetworkCredential]::new('', $secure).Password
        Remove-Variable secure
        if ([string]::IsNullOrWhiteSpace($plain)) { throw 'No client secret entered.' }
        $rotatedSecret = 'manual'
    }
    Set-KvSecret $name $plain "appId=$CLIENT_ID;keyId=$secretKeyId"
    Remove-Variable plain
    Write-Info "$name saved."
} else { Write-Info "$name exists (unchanged)." }
# The secret's change time is passed to the app as an environment variable: after a rotation this creates a
# new revision that loads the new secret from Key Vault.
$SECRET_STAMP = Invoke-AzCli -Arguments @('resource', 'show', '--ids', "$($script:KV_ID)/secrets/$name",
                                          '--query', 'properties.attributes.updated', '-o', 'tsv') -AllowFailure

$name = "${PREFIX}jwt-signing-key"
if (-not (Test-KvSecret $name)) { Set-KvSecret $name (New-UrlSafeKey 48); Write-Info "$name created." }
else { Write-Info "$name exists (unchanged; otherwise all users would have to reconnect)." }

if ($MDCA_API_URL -and $MDCA_AUTH -eq 'token') {
    # Legacy Defender for Cloud Apps API token for sanction_cloud_apps (MDCA_AUTH = 'token').
    $name = "${PREFIX}mdca-api-token"
    if (-not (Test-KvSecret $name)) {
        if (-not (Test-Interactive)) {
            throw ("MDCA_AUTH = 'token': secret $name is missing in Key Vault. Create an API token in the portal " +
                   "(Settings > Cloud Apps > System > API tokens) and run the script interactively.")
        }
        $secure = Read-Host -AsSecureString "Enter the Defender for Cloud Apps API token (Settings > Cloud Apps > System > API tokens)"
        $plain = [System.Net.NetworkCredential]::new('', $secure).Password
        Remove-Variable secure
        if ([string]::IsNullOrWhiteSpace($plain)) { throw 'No API token entered.' }
        Set-KvSecret $name $plain 'Defender for Cloud Apps API token (legacy)'
        Remove-Variable plain
        Write-Info "$name saved."
    } else { Write-Info "$name exists (unchanged; restart the revision after replacing it)." }
}

# ── Image ──────────────────────────────────────────────────────────────────────
if (-not $SkipBuild) {
    Write-Step "Building image: ${IMAGE}:$Tag"
    # Separate name: PowerShell variables are case-insensitive ($image would be $IMAGE).
    $imageRef = "${IMAGE}:$Tag"
    if ($LocalBuild) {
        if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw '-LocalBuild requires Docker (Docker Desktop).' }
        Invoke-AzCli -Arguments @('acr', 'login', '--name', $ACR) | Out-Null
        & docker build --pull --build-arg 'BASE_IMAGE=python:3.12-slim' -t "$ACR_SERVER/$imageRef" $Root
        if ($LASTEXITCODE -ne 0) { throw 'docker build failed (output above).' }
        & docker push "$ACR_SERVER/$imageRef"
        if ($LASTEXITCODE -ne 0) { throw 'docker push failed (output above).' }
    } else {
        # Import the base image into our own ACR: ACR Tasks run on shared IPs and quickly hit the Docker Hub
        # pull limit for anonymous access. --force fetches current security updates on every run.
        $baseImage = 'python:3.12-slim'
        # -Retries 1: a Docker Hub limit (429) lasts for hours, retrying only prolongs the run.
        $imported = Invoke-AzCli -Arguments @('acr', 'import', '--name', $ACR, '--source', "docker.io/library/$baseImage",
                                              '--image', "base/$baseImage", '--force') -AllowFailure -Retries 1
        $importError = "$($script:LastAzError)"
        $haveCopy = Invoke-AzCli -Arguments @('acr', 'repository', 'show', '--name', $ACR, '--image', "base/$baseImage",
                                              '--query', 'name', '-o', 'tsv') -AllowFailure -Retries 1
        if ($null -ne $imported) {
            $baseImage = "$ACR_SERVER/base/$baseImage"
            Write-Info "Base image updated: $baseImage"
        } elseif ($haveCopy) {
            $baseImage = "$ACR_SERVER/base/$baseImage"
            Write-Warn "The base image could not be updated (Docker Hub); using the existing copy $baseImage."
        } else {
            $reason = if ($importError -match 'TOOMANYREQUESTS|429') { 'Docker Hub limit for anonymous pulls reached' } else { ($importError -split "`n")[0] }
            Write-Warn "Importing the base image failed ($reason). ACR Build pulls it directly from Docker Hub."
        }

        # Important: no --file with an absolute path. The path is passed unchanged to the build agent (Linux);
        # a Windows path like C:\...\Dockerfile does not exist there. Without --file, ./Dockerfile in the context applies.
        # Only queue the build (--no-wait) and poll the status briefly instead of streaming logs for minutes.
        # Without --only-show-errors: the run ID only appears in the status line "Queued a build with ID: xx" (stderr);
        # with --no-wait, az acr build prints no JSON depending on the CLI version.
        $runId = $null
        $queued = ''
        $code = 0
        for ($attempt = 1; $attempt -le 3 -and -not $runId; $attempt++) {
            $since = [DateTime]::UtcNow.AddMinutes(-2)
            $queued = (& az acr build --registry $ACR --image $imageRef --build-arg "BASE_IMAGE=$baseImage" `
                           --no-wait -o json $Root 2>&1 | ForEach-Object { $_.ToString() }) -join "`n"
            $code = $LASTEXITCODE
            if ($queued -match '"runId":\s*"([A-Za-z0-9]+)"' -or $queued -match 'build with ID:\s*([A-Za-z0-9]+)') {
                $runId = $Matches[1]
                break
            }
            # ID not in the output: find the latest run since the start in the run list (do not queue again).
            for ($look = 1; $look -le 6 -and -not $runId; $look++) {
                $runs = Invoke-AzCli -Arguments @('acr', 'task', 'list-runs', '--registry', $ACR, '--top', '5',
                                                  '--query', '[].{id:runId, created:createTime}', '-o', 'json') -AllowFailure
                if ($runs) {
                    $runId = @($runs | ConvertFrom-Json | Where-Object { ([DateTime]$_.created).ToUniversalTime() -ge $since } |
                               Sort-Object { [DateTime]$_.created } -Descending | Select-Object -First 1).id
                }
                if (-not $runId) { Start-Sleep -Seconds 5 }
            }
            if ($runId) { break }
            if ($code -eq 0) { break }   # the call succeeded but no run was found: do not queue twice
            if ($attempt -lt 3) {
                Write-Warn "The build could not be queued (attempt $attempt/3, exit $code), retrying in 20 s."
                Start-Sleep -Seconds 20
            }
        }
        if (-not $runId) {
            $msg = ($queued -replace '(?:[\\|/-]\s+)?Running \.\.\s*', '').Trim()
            if (-not $msg) { $msg = '(no output from az acr build)' }
            if ($msg -match 'TasksOperationsNotAllowed|not allowed|not permitted') {
                $msg += "`nACR Tasks are blocked in this subscription. Alternative: ./deploy.ps1 -LocalBuild (Docker Desktop)."
            }
            throw ("ACR Build could not be started (exit $code):`n$msg`n" +
                   "Check: az acr task list-runs --registry $ACR --top 3 -o table")
        }
        Write-Info "ACR build run $runId started."
        try {
            Wait-AzState -What "ACR Build $runId" -TimeoutMinutes 30 -IntervalSeconds 15 -StateArguments @(
                'acr', 'task', 'show-run', '--registry', $ACR, '--run-id', $runId, '--query', 'status')
        } catch {
            Write-Warn "Build failed. Last log lines (full log in the portal: $ACR > Services > Tasks > Runs > $runId):"
            & az acr task logs --registry $ACR --run-id $runId --only-show-errors 2>&1 | Select-Object -Last 60 | Out-Host
            throw
        }
    }
} else {
    Write-Step "Build skipped, using ${IMAGE}:$Tag"
    if (-not $PSBoundParameters.ContainsKey('Tag')) { throw '-SkipBuild requires -Tag with an existing image tag.' }
    # 1) Successful ACR build run with exactly this image (management plane, no access to <acr>.azurecr.io needed)
    $builtBy = Invoke-AzCli -Arguments @('acr', 'task', 'list-runs', '--registry', $ACR, '--top', '50', '--query',
        "[?status=='Succeeded' && outputImages[?repository=='$IMAGE' && tag=='$Tag']] | [0].runId", '-o', 'tsv') -AllowFailure
    if ($builtBy) {
        Write-Info "Image found (ACR build run $builtBy)."
    } else {
        # 2) Tag list of the registry (data plane <acr>.azurecr.io, e.g. after -LocalBuild)
        $tags = Invoke-AzCli -Arguments @('acr', 'repository', 'show-tags', '--name', $ACR, '--repository', $IMAGE, '-o', 'tsv') -AllowFailure
        if ($null -eq $tags) {
            Write-Warn ("Tags of $ACR not readable ($($script:LastAzError)). Continuing; if the image is missing, " +
                        "the deployment reports it.")
        } elseif (@($tags -split "`n" | ForEach-Object { $_.Trim() }) -notcontains $Tag) {
            throw ("Image ${IMAGE}:$Tag does not exist in $ACR. Existing tags: " + (($tags -split "`n") -join ', ') +
                   ". Run without -SkipBuild to build it.")
        } else {
            Write-Info "Image found (tag list)."
        }
    }
}

# ── Client app for Copilot Studio ──────────────────────────────────────────────
# Copilot Studio signs in at Entra with its own app registration and requests the scope of the server app.
# The server only accepts tokens of this client app (ALLOWED_CLIENT_APP_IDS). The secret of the server app therefore
# stays in Key Vault only.
Write-Step "Client app for Copilot Studio"
$COPILOT_APP_ID = $SERVER.CopilotClientAppId
$copilotForeign = $false
if (-not $COPILOT_APP_ID) {
    $lookup = Find-OwnedApp $COPILOT_APP_NAME
    if ($lookup.Mine.Count -ge 1) {
        $COPILOT_APP_ID = $lookup.Mine[0]
        Save-Setting 'CopilotClientAppId' $COPILOT_APP_ID
    } elseif ($lookup.Found.Count -gt 0) {
        $copilotForeign = $true
        Write-Warn ("App registration(s) '$COPILOT_APP_NAME' ($($lookup.Found -join ', ')) are not owned by you and are " +
                    "not reused (they would otherwise get consent to the server). If one of them is yours: set " +
                    "CopilotClientAppId in deploy.settings.psd1.")
    }
}
if (-not $COPILOT_APP_ID -and $ConfigureAppRegistration -and -not $copilotForeign) {
    $COPILOT_APP_ID = Invoke-AzCli -Arguments (@('ad', 'app', 'create', '--display-name', $COPILOT_APP_NAME,
                                                 '--sign-in-audience', 'AzureADMyOrg', '--web-redirect-uris',
                                                 $COPILOT_DEFAULT_REDIRECT) + $CopilotRedirectUris +
                                               @('--query', 'appId', '-o', 'tsv'))
    Write-Info "Client app '$COPILOT_APP_NAME' created: $COPILOT_APP_ID (waiting 20 s for replication in Entra)"
    Start-Sleep -Seconds 20
    Save-Setting 'CopilotClientAppId' $COPILOT_APP_ID
}
if ($COPILOT_APP_ID -and $PROTECTED_APP_IDS -contains $COPILOT_APP_ID) {
    throw ("The client app $COPILOT_APP_ID is protected and must not be used as the Copilot client app " +
           "(it would receive permissions, consent and assignments). Clear CopilotClientAppId.")
}
if ($COPILOT_APP_ID) {
    Write-Info "Client app: $COPILOT_APP_ID (only tokens of this app are accepted)"
} else {
    Write-Warn ("No client app '$COPILOT_APP_NAME' found. Let -ConfigureAppRegistration create it or set " +
                "CopilotClientAppId in deploy.settings.psd1. Until then the server accepts tokens of any client app of the tenant.")
}

# ── Ingress IP restriction (optional) ──────────────────────────────────────────
$ingressCidrs = @()
if ($RestrictIngressToPowerPlatform) {
    Write-Step "Restricting ingress to Power Platform connectors ($($PowerPlatformServiceTags -join ', '))"
    $serviceTags = Invoke-AzCli -Arguments @('network', 'list-service-tags', '--location', $LOCATION, '-o', 'json') | ConvertFrom-Json
    foreach ($tagName in $PowerPlatformServiceTags) {
        $entry = @($serviceTags.values | Where-Object { $_.name -eq $tagName }) | Select-Object -First 1
        if (-not $entry) { throw "Service tag $tagName not found (spelling like 'AzureConnectors.WestEurope')." }
        $ingressCidrs += @($entry.properties.addressPrefixes | Where-Object { $_ -notmatch ':' })   # IPv4 only
    }
    $ingressCidrs = @(($ingressCidrs + $ExtraAllowedCidrs) | Sort-Object -Unique)
    Write-Info "$($ingressCidrs.Count) IPv4 ranges allowed (service tags + -ExtraAllowedCidrs)."
}

# ── Deployment (Bicep) ─────────────────────────────────────────────────────────
Write-Step "Deploying container app $APP (Bicep)"
# Array parameters through a file: PowerShell passes inline JSON to native programs unreliably.
$paramFile = Join-Path ([System.IO.Path]::GetTempPath()) "defender-mcp-params-$Tag.json"
[System.IO.File]::WriteAllText($paramFile, (@{
    '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
    contentVersion = '1.0.0.0'
    parameters = @{ allowedIngressCidrs = @{ value = @($ingressCidrs) }; sentinelWorkspaces = @{ value = "$SENTINEL_WORKSPACES" } }
} | ConvertTo-Json -Depth 5))
$params = @(
    "@$paramFile", "allowedClientAppIds=$COPILOT_APP_ID", "secretStamp=$SECRET_STAMP",
    "appName=$APP", "profile=full", "image=$ACR_SERVER/${IMAGE}:$Tag", "acrName=$ACR",
    "keyVaultName=$KEYVAULT", "secretPrefix=$PREFIX", "environmentName=$ENV_NAME", "logAnalyticsName=$LOG_WS",
    "tenantId=$TENANT_ID", "clientId=$CLIENT_ID", "requiredScope=$SCOPE",
    "minReplicas=1", "maxReplicas=5", "mdeApiHost=$MDE_API_HOST",
    "mdcaApiUrl=$MDCA_API_URL", "mdcaAuth=$MDCA_AUTH"
)
$deployName = "defender-mcp-$Tag"
$deployArgs = @('deployment', 'group', 'create', '--resource-group', $RG, '--name', $deployName,
                '--template-file', (Join-Path $Root 'infra/main.bicep'), '--no-wait', '--parameters') + $params
$deployShow = @('deployment', 'group', 'show', '--resource-group', $RG, '--name', $deployName)
# On failure, collects the actual cause: the container app's error message from the
# deployment operations, the state of the revisions, system and console logs of the container.
function Get-AppDiagnostics {
    $lines = [System.Collections.Generic.List[string]]::new()
    $ops = Invoke-AzCli -Arguments @('deployment', 'operation', 'group', 'list', '--resource-group', $RG, '--name', $deployName,
        '--query', "[?properties.provisioningState=='Failed'].{resource:properties.targetResource.resourceName, message:properties.statusMessage}",
        '-o', 'json') -AllowFailure
    if ($ops) { $lines.Add("--- Failed resources ---"); $lines.Add($ops) }
    $revs = Invoke-AzCli -Arguments @('containerapp', 'revision', 'list', '--name', $APP, '--resource-group', $RG, '--query',
        "[].{name:name, created:properties.createdTime, provisioning:properties.provisioningState, health:properties.healthState, running:properties.runningState, details:properties.runningStateDetails}",
        '-o', 'json') -AllowFailure
    if ($revs) { $lines.Add("--- Revisions ---"); $lines.Add($revs) }
    foreach ($type in 'system', 'console') {
        $format = if ($type -eq 'system') { 'json' } else { 'text' }   # system logs are only available as JSON
        $log = Invoke-AzCli -Arguments @('containerapp', 'logs', 'show', '--name', $APP, '--resource-group', $RG,
                                         '--type', $type, '--tail', '60', '--format', $format) -Retries 1 -AllowFailure
        if ($log) { $lines.Add("--- Container log ($type) ---"); $lines.Add($log) }
    }
    return ($lines -join "`n")
}

# Retrying only helps when a fresh role assignment (Key Vault, ACR) is not effective yet.
$RetryableDeployError = 'Key ?Vault|KeyVault|vault\.azure\.net|fetch secret|Unauthorized|unauthorized|ImagePullBackOff|AcrPull|PrincipalNotFound|Forbidden|AuthorizationFailed'

$outputs = $null
for ($attempt = 1; $attempt -le 3 -and -not $outputs; $attempt++) {
    Invoke-AzCli -Arguments $deployArgs | Out-Null
    Start-Sleep -Seconds 10
    try {
        Wait-AzState -What "Deployment $deployName" -StateArguments ($deployShow + @('--query', 'properties.provisioningState'))
        $outputs = Invoke-AzCli -Arguments ($deployShow + @('--query', 'properties.outputs', '-o', 'json')) | ConvertFrom-Json
    } catch {
        Write-Warn "Deployment attempt $attempt failed. Determining the cause..."
        $diag = Get-AppDiagnostics
        Write-Host $diag
        $diagFile = Join-Path $Root "deploy-diagnose-$Tag.txt"
        Set-Content -LiteralPath $diagFile -Value $diag -Encoding utf8
        if ($attempt -ge 3 -or $diag -notmatch $RetryableDeployError) {
            throw "Deployment $deployName failed. Cause see above, saved to: $diagFile"
        }
        Write-Warn "Looks like a role assignment that is not active yet. Retrying in 90 s."
        Start-Sleep -Seconds 90
    }
}
Remove-Item -LiteralPath $paramFile -Force -ErrorAction SilentlyContinue
if ($outputs.baseUrl.value -ne $BASE_URL) { Write-Warn "BASE_URL from Bicep ($($outputs.baseUrl.value)) differs." }

# ── Verification ───────────────────────────────────────────────────────────────
Write-Step "Smoke test"
if ($RestrictIngressToPowerPlatform -and -not $ExtraAllowedCidrs) {
    Write-Warn ("Skipped: ingress is restricted to Power Platform IPs, this PC cannot get through. " +
                "To run the test, allow your own public IP with -ExtraAllowedCidrs '<ip>/32'.")
} else {
    & (Join-Path $Root 'scripts/smoke_test.ps1') -BaseUrl $BASE_URL
}

# ── ACR admin user off (pull uses the managed identity) ────────────────────────
if (-not $KeepAcrAdmin) {
    $adminOn = Invoke-AzCli -Arguments @('acr', 'show', '--name', $ACR, '--query', 'adminUserEnabled', '-o', 'tsv')
    if ($adminOn -eq 'true') {
        Invoke-AzCli -Arguments @('acr', 'update', '--name', $ACR, '--admin-enabled', 'false') | Out-Null
        Write-Info "ACR admin user disabled."
    }
}

# ── App registrations (optional) ───────────────────────────────────────────────
# Default: read-only Graph permissions (Read, Read.All, Read.Directory). Write permissions only with -GrantWritePermissions.
$readPattern = '\.Read(\.All|\.Directory)?$'
$isGranted = { param($s) return [bool]($GrantWritePermissions -or $s -match $readPattern) }
$scopes = @($GRAPH_SCOPES | Where-Object { & $isGranted $_ })
$withheld = @($GRAPH_SCOPES | Where-Object { -not (& $isGranted $_) })
# Defender for Endpoint API: same rule (Machine.Read always, everything else only with -GrantWritePermissions).
$mdeScopes = @($MDE_SCOPES | Where-Object { & $isGranted $_ })
$withheld += @($MDE_SCOPES | Where-Object { -not (& $isGranted $_) } | ForEach-Object { "WindowsDefenderATP/$_" })
# Defender for Cloud Apps API: only with $MDCA_API_URL and $MDCA_AUTH 'obo' (Discovery.manage counts as a write permission).
$mdcaWanted = [bool]($MDCA_API_URL -and $MDCA_AUTH -eq 'obo')
$mdcaScopes = @(if ($mdcaWanted) { $MDCA_SCOPES | Where-Object { & $isGranted $_ } })
if ($mdcaWanted) {
    $withheld += @($MDCA_SCOPES | Where-Object { -not (& $isGranted $_) } | ForEach-Object { "MicrosoftCloudAppSecurity/$_" })
}
if ($ConfigureAppRegistration -and $SERVER_APP_PROTECTED) {
    Write-Step "Server app $CLIENT_ID (protected, read only)"
    $appReg = Invoke-AzCli -Arguments @('ad', 'app', 'show', '--id', $CLIENT_ID, '-o', 'json') | ConvertFrom-Json
    $serverScope = @($appReg.api.oauth2PermissionScopes) | Where-Object { $_.value -eq $SCOPE } | Select-Object -First 1
    Write-Warn "No changes to the server app (scope, token version, permissions, consent, redirect URIs)."
}
if ($ConfigureAppRegistration) {
  if (-not $SERVER_APP_PROTECTED) {
    Write-Step "Configuring server app $CLIENT_ID"
    Set-ApiScope $CLIENT_ID $SCOPE
    Confirm-ServicePrincipal $CLIENT_ID
    $appReg = Invoke-AzCli -Arguments @('ad', 'app', 'show', '--id', $CLIENT_ID, '-o', 'json') | ConvertFrom-Json

    $uris = @($appReg.web.redirectUris | Where-Object { $_ })
    if ($uris) {
        # The server app performs no sign-in and needs no redirect URI; an unused one is attack surface.
        Write-Warn ("The server app has redirect URI(s) it does not need: $($uris -join ', '). Remove them in Entra ID " +
                    "(App registrations > Authentication) unless another application uses this app registration.")
    }
    if ($appReg.signInAudience -ne 'AzureADMyOrg') {
        Write-Warn "signInAudience is '$($appReg.signInAudience)', expected 'AzureADMyOrg' (own tenant only). Please check."
    }
    $serverScope = @($appReg.api.oauth2PermissionScopes) | Where-Object { $_.value -eq $SCOPE } | Select-Object -First 1
    if (-not $serverScope) {
        Write-Warn "Scope '$SCOPE' is not visible yet (replication). Run the script again in a few minutes."
    }

    $graphScopes = Invoke-AzCli -Arguments @('ad', 'sp', 'show', '--id', $GRAPH_APP_ID, '--query',
                                             'oauth2PermissionScopes[].{id:id, value:value}', '-o', 'json') | ConvertFrom-Json
    $existing = @($appReg.requiredResourceAccess | Where-Object { $_.resourceAppId -eq $GRAPH_APP_ID } |
                  ForEach-Object { $_.resourceAccess })
    $appRoles = @($existing | Where-Object { $_.type -eq 'Role' })
    if ($appRoles.Count -gt 0) {
        Write-Warn "The app has $($appRoles.Count) Graph application permission(s). The server rejects app-only tokens; please remove them."
    }
    $added = 0
    foreach ($scopeName in $scopes) {
        $perm = $graphScopes | Where-Object { $_.value -eq $scopeName } | Select-Object -First 1
        if (-not $perm) { Write-Warn "Graph permission $scopeName not found."; continue }
        if (@($existing | Where-Object { $_.id -eq $perm.id -and $_.type -eq 'Scope' }).Count -eq 0) {
            Invoke-AzCli -Arguments @('ad', 'app', 'permission', 'add', '--id', $CLIENT_ID, '--api', $GRAPH_APP_ID,
                                      '--api-permissions', "$($perm.id)=Scope") | Out-Null
            Write-Info "Delegated permission added: $scopeName"
            $added++
        }
    }
    if ($withheld.Count -gt 0) {
        Write-Warn ("Not granted: $($withheld -join ', '). The admin tools are visible but only work after " +
                    "./deploy.ps1 -SkipBuild -Tag $Tag -ConfigureAppRegistration -GrantWritePermissions.")
    }
    # Permissions the server does not need (or must not have without -GrantWritePermissions)
    $wantedIds = @($scopes | ForEach-Object { $n = $_; ($graphScopes | Where-Object { $_.value -eq $n } | Select-Object -First 1).id })
    $extra = @($existing | Where-Object { $_.type -eq 'Scope' -and $wantedIds -notcontains $_.id })
    $extraNames = @($extra | ForEach-Object { $i = $_.id; ($graphScopes | Where-Object { $_.id -eq $i } | Select-Object -First 1).value })
    if ($extra.Count -gt 0 -and $PruneGraphPermissions) {
        Invoke-AzCli -Arguments (@('ad', 'app', 'permission', 'delete', '--id', $CLIENT_ID, '--api', $GRAPH_APP_ID,
                                   '--api-permissions') + @($extra | ForEach-Object { $_.id })) | Out-Null
        Write-Info "Removed: $($extraNames -join ', ')"
    } elseif ($extra.Count -gt 0) {
        Write-Warn ("The server app has Graph permissions that are not intended: $($extraNames -join ', '). " +
                    "Remove them with -PruneGraphPermissions.")
    }
    # Defender for Endpoint API (WindowsDefenderATP): antivirus health (read) plus response actions, tags,
    # investigations and indicators of the admin tools.
    $mdeExisting = @($appReg.requiredResourceAccess | Where-Object { $_.resourceAppId -eq $MDE_APP_ID } |
                     ForEach-Object { $_.resourceAccess })
    $mdeSpId = $null
    $mdeCatalog = @()
    if ($mdeScopes.Count -gt 0 -or $mdeExisting.Count -gt 0) {
        $mdeSpId = Invoke-AzCli -Arguments @('ad', 'sp', 'show', '--id', $MDE_APP_ID, '--query', 'id', '-o', 'tsv') -AllowFailure
        if (-not $mdeSpId -and $mdeScopes.Count -gt 0) {
            # Without this service principal, consent and token exchange fail (AADSTS650052).
            $mdeSpId = Invoke-AzCli -Arguments @('ad', 'sp', 'create', '--id', $MDE_APP_ID, '--query', 'id', '-o', 'tsv') -AllowFailure
            if ($mdeSpId) {
                Write-Info "Service principal WindowsDefenderATP ($MDE_APP_ID) created (waiting 20 s for replication)."
                Start-Sleep -Seconds 20
            }
        }
        if ($mdeSpId) {
            $mdeCatalog = @(Invoke-AzCli -Arguments @('ad', 'sp', 'show', '--id', $MDE_APP_ID, '--query',
                                                      'oauth2PermissionScopes[].{id:id, value:value}', '-o', 'json') | ConvertFrom-Json)
        } elseif ($mdeScopes.Count -gt 0) {
            Write-Warn ("Service principal WindowsDefenderATP ($MDE_APP_ID) is missing and could not be created " +
                        "(e.g. role Application Administrator required): $($script:LastAzError) -- Defender for Endpoint " +
                        "must be active in the tenant. Until then get_antivirus_health and the response tools fail " +
                        "(isolate, scan, investigation, tags, indicators).")
        }
    }
    $mdeRoles = @($mdeExisting | Where-Object { $_.type -eq 'Role' })
    if ($mdeRoles.Count -gt 0) {
        Write-Warn "The app has $($mdeRoles.Count) WindowsDefenderATP application permission(s). The server rejects app-only tokens; please remove them."
    }
    if ($mdeCatalog.Count -gt 0) {
        foreach ($scopeName in $mdeScopes) {
            $perm = $mdeCatalog | Where-Object { $_.value -eq $scopeName } | Select-Object -First 1
            if (-not $perm) { Write-Warn "WindowsDefenderATP permission $scopeName not found."; continue }
            if (@($mdeExisting | Where-Object { $_.id -eq $perm.id -and $_.type -eq 'Scope' }).Count -eq 0) {
                Invoke-AzCli -Arguments @('ad', 'app', 'permission', 'add', '--id', $CLIENT_ID, '--api', $MDE_APP_ID,
                                          '--api-permissions', "$($perm.id)=Scope") | Out-Null
                Write-Info "Delegated permission added: WindowsDefenderATP/$scopeName"
                $added++
            }
        }
        $mdeWantedIds = @($mdeScopes | ForEach-Object { $n = $_; ($mdeCatalog | Where-Object { $_.value -eq $n } | Select-Object -First 1).id })
        $mdeExtra = @($mdeExisting | Where-Object { $_.type -eq 'Scope' -and $mdeWantedIds -notcontains $_.id })
        $mdeExtraNames = @($mdeExtra | ForEach-Object { $i = $_.id; ($mdeCatalog | Where-Object { $_.id -eq $i } | Select-Object -First 1).value })
        if ($mdeExtra.Count -gt 0 -and $PruneGraphPermissions) {
            Invoke-AzCli -Arguments (@('ad', 'app', 'permission', 'delete', '--id', $CLIENT_ID, '--api', $MDE_APP_ID,
                                       '--api-permissions') + @($mdeExtra | ForEach-Object { $_.id })) | Out-Null
            Write-Info "Removed: WindowsDefenderATP/$($mdeExtraNames -join ', WindowsDefenderATP/')"
        } elseif ($mdeExtra.Count -gt 0) {
            Write-Warn ("The server app has WindowsDefenderATP permissions that are not intended: " +
                        "$($mdeExtraNames -join ', '). Remove them with -PruneGraphPermissions.")
        }
    }
    # Defender for Cloud Apps API ('Microsoft Cloud App Security'): Discovery.manage for sanction_cloud_apps.
    $mdcaExisting = @($appReg.requiredResourceAccess | Where-Object { $_.resourceAppId -eq $MDCA_APP_ID } |
                      ForEach-Object { $_.resourceAccess })
    $mdcaSpId = $null
    if ($mdcaScopes.Count -gt 0 -or $mdcaExisting.Count -gt 0) {
        $mdcaSpId = Invoke-AzCli -Arguments @('ad', 'sp', 'show', '--id', $MDCA_APP_ID, '--query', 'id', '-o', 'tsv') -AllowFailure
        if (-not $mdcaSpId -and $mdcaScopes.Count -gt 0) {
            Write-Warn ("Service principal 'Microsoft Cloud App Security' ($MDCA_APP_ID) is missing: Defender for Cloud Apps " +
                        "is not active in the tenant. sanction_cloud_apps only works after that (run again).")
        }
    }
    if ($mdcaSpId) {
        $mdcaCatalog = @(Invoke-AzCli -Arguments @('ad', 'sp', 'show', '--id', $MDCA_APP_ID, '--query',
                                                   'oauth2PermissionScopes[].{id:id, value:value}', '-o', 'json') | ConvertFrom-Json)
        foreach ($scopeName in $mdcaScopes) {
            $perm = $mdcaCatalog | Where-Object { $_.value -eq $scopeName } | Select-Object -First 1
            if (-not $perm) { Write-Warn "Permission Microsoft Cloud App Security/$scopeName not found."; continue }
            if (@($mdcaExisting | Where-Object { $_.id -eq $perm.id -and $_.type -eq 'Scope' }).Count -eq 0) {
                Invoke-AzCli -Arguments @('ad', 'app', 'permission', 'add', '--id', $CLIENT_ID, '--api', $MDCA_APP_ID,
                                          '--api-permissions', "$($perm.id)=Scope") | Out-Null
                Write-Info "Delegated permission added: Microsoft Cloud App Security/$scopeName"
                $added++
            }
        }
        $mdcaWantedIds = @($mdcaScopes | ForEach-Object { $n = $_; ($mdcaCatalog | Where-Object { $_.value -eq $n } | Select-Object -First 1).id })
        $mdcaExtra = @($mdcaExisting | Where-Object { $mdcaWantedIds -notcontains $_.id })
        if ($mdcaExtra.Count -gt 0 -and $PruneGraphPermissions) {
            Invoke-AzCli -Arguments (@('ad', 'app', 'permission', 'delete', '--id', $CLIENT_ID, '--api', $MDCA_APP_ID,
                                       '--api-permissions') + @($mdcaExtra | ForEach-Object { $_.id })) | Out-Null
            Write-Info "Removed: $($mdcaExtra.Count) permission(s) for Microsoft Cloud App Security"
        } elseif ($mdcaExtra.Count -gt 0) {
            Write-Warn ("The server app has permissions for Microsoft Cloud App Security that are not intended " +
                        "(e.g. MDCA_API_URL empty or MDCA_AUTH 'token'). Remove them with -PruneGraphPermissions.")
        }
    }
    Write-Info "Granting admin consent for the permissions of the server app (Graph$(if ($mdeScopes.Count -gt 0) { ', WindowsDefenderATP' })$(if ($mdcaScopes.Count -gt 0) { ', Microsoft Cloud App Security' }))..."
    # A freshly created service principal is not replicated everywhere immediately: try consent up to three times.
    for ($try = 1; ; $try++) {
        $consent = Invoke-AzCli -Arguments @('ad', 'app', 'permission', 'admin-consent', '--id', $CLIENT_ID) -AllowFailure
        if ($null -ne $consent) { break }
        if ($try -ge 3) { throw "Admin consent failed: $($script:LastAzError)" }
        Write-Warn "Admin consent not possible yet (attempt $try/3, replication?). Retrying in 30 s."
        Start-Sleep -Seconds 30
    }
    Write-Info "Admin consent granted ($added new permission(s))."
    if ($PruneGraphPermissions) {
        # The granted consent (oauth2PermissionGrant) can still contain removed permissions, also from earlier,
        # cancelled runs or changes in the portal: check on every run and trim to the intended permissions.
        $spId = Invoke-AzCli -Arguments @('ad', 'sp', 'show', '--id', $CLIENT_ID, '--query', 'id', '-o', 'tsv')
        $graphSpId = Invoke-AzCli -Arguments @('ad', 'sp', 'show', '--id', $GRAPH_APP_ID, '--query', 'id', '-o', 'tsv')
        $grantsRaw = Invoke-AzCli -Arguments @('rest', '--method', 'get', '--url',
                       "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$spId'",
                       '--query', "value[?resourceId=='$graphSpId'].{id:id, scope:scope, type:consentType}", '-o', 'json')
        $allowed = @($scopes) + @('openid', 'profile', 'email', 'offline_access')
        foreach ($g in @(if ($grantsRaw) { $grantsRaw | ConvertFrom-Json })) {
            $have = @("$($g.scope)" -split ' ' | Where-Object { $_ })
            $surplus = @($have | Where-Object { $allowed -notcontains $_ })
            if ($surplus.Count -eq 0) { continue }
            $newScope = (@($have | Where-Object { $allowed -contains $_ }) + @($scopes) | Sort-Object -Unique) -join ' '
            Invoke-GraphJson 'patch' "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($g.id)" @{ scope = $newScope } | Out-Null
            Write-Info "Consent ($($g.type)) trimmed, removed: $($surplus -join ', ')"
        }
        if ($mdeSpId) {
            $mdeGrantsRaw = Invoke-AzCli -Arguments @('rest', '--method', 'get', '--url',
                              "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$spId'",
                              '--query', "value[?resourceId=='$mdeSpId'].{id:id, scope:scope, type:consentType}", '-o', 'json')
            foreach ($g in @(if ($mdeGrantsRaw) { $mdeGrantsRaw | ConvertFrom-Json })) {
                $have = @("$($g.scope)" -split ' ' | Where-Object { $_ })
                $keep = @($have | Where-Object { $mdeScopes -contains $_ })
                $surplus = @($have | Where-Object { $mdeScopes -notcontains $_ })
                if ($surplus.Count -eq 0) { continue }
                if ($keep.Count -eq 0) {
                    Invoke-AzCli -Arguments @('rest', '--method', 'delete', '--url',
                                              "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($g.id)") | Out-Null
                } else {
                    Invoke-GraphJson 'patch' "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($g.id)" @{ scope = ($keep -join ' ') } | Out-Null
                }
                Write-Info "Consent WindowsDefenderATP ($($g.type)) trimmed, removed: $($surplus -join ', ')"
            }
        }
        # Defender for Cloud Apps API: trim consent to $mdcaScopes (empty if MDCA_API_URL is missing or
        # MDCA_AUTH is 'token'), even if the permission was already removed from the app earlier.
        $mdcaGrantSp = if ($mdcaSpId) { $mdcaSpId } else {
            Invoke-AzCli -Arguments @('ad', 'sp', 'show', '--id', $MDCA_APP_ID, '--query', 'id', '-o', 'tsv') -AllowFailure }
        if ($mdcaGrantSp) {
            $mdcaGrantsRaw = Invoke-AzCli -Arguments @('rest', '--method', 'get', '--url',
                               "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$spId'",
                               '--query', "value[?resourceId=='$mdcaGrantSp'].{id:id, scope:scope, type:consentType}", '-o', 'json')
            foreach ($g in @(if ($mdcaGrantsRaw) { $mdcaGrantsRaw | ConvertFrom-Json })) {
                $have = @("$($g.scope)" -split ' ' | Where-Object { $_ })
                $keep = @($have | Where-Object { $mdcaScopes -contains $_ })
                $surplus = @($have | Where-Object { $mdcaScopes -notcontains $_ })
                if ($surplus.Count -eq 0) { continue }
                if ($keep.Count -eq 0) {
                    Invoke-AzCli -Arguments @('rest', '--method', 'delete', '--url',
                                              "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($g.id)") | Out-Null
                } else {
                    Invoke-GraphJson 'patch' "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($g.id)" @{ scope = ($keep -join ' ') } | Out-Null
                }
                Write-Info "Consent Microsoft Cloud App Security ($($g.type)) trimmed, removed: $($surplus -join ', ')"
            }
        }
    }

  }

    if ($COPILOT_APP_ID) {
        Write-Step "Configuring client app $COPILOT_APP_ID ($COPILOT_APP_NAME)"
        $client = Invoke-AzCli -Arguments @('ad', 'app', 'show', '--id', $COPILOT_APP_ID, '-o', 'json') | ConvertFrom-Json
        if (-not (Invoke-AzCli -Arguments @('ad', 'sp', 'show', '--id', $COPILOT_APP_ID, '--query', 'id', '-o', 'tsv') -AllowFailure)) {
            Invoke-AzCli -Arguments @('ad', 'sp', 'create', '--id', $COPILOT_APP_ID) | Out-Null
            Write-Info "Service principal of the client app created."
        }
        $clientUris = @($client.web.redirectUris | Where-Object { $_ })
        $wanted = @(($clientUris + @($COPILOT_DEFAULT_REDIRECT) + $CopilotRedirectUris) | Where-Object { $_ } | Sort-Object -Unique)
        if ((@($clientUris | Sort-Object -Unique) -join ' ') -ne ($wanted -join ' ')) {
            Set-AppRedirectUris $COPILOT_APP_ID $wanted
            Write-Info ("Redirect URLs of the client app: " + ($wanted -join ', '))
        }
        if ($client.signInAudience -ne 'AzureADMyOrg') {
            Write-Warn "Client app signInAudience is '$($client.signInAudience)', expected 'AzureADMyOrg'."
        }
        if ($serverScope) {
            $hasScope = @($client.requiredResourceAccess | Where-Object { $_.resourceAppId -eq $CLIENT_ID } |
                          ForEach-Object { $_.resourceAccess } | Where-Object { $_.id -eq $serverScope.id }).Count -gt 0
            if (-not $hasScope) {
                Invoke-AzCli -Arguments @('ad', 'app', 'permission', 'add', '--id', $COPILOT_APP_ID, '--api', $CLIENT_ID,
                                          '--api-permissions', "$($serverScope.id)=Scope") | Out-Null
                Write-Info "Permission on api://$CLIENT_ID/$SCOPE added."
            }
            Invoke-AzCli -Arguments @('ad', 'app', 'permission', 'admin-consent', '--id', $COPILOT_APP_ID) | Out-Null
            Write-Info "Admin consent granted for the client app."
        }
        $secretCount = @($client.passwordCredentials | Where-Object { $_ }).Count
        if ($secretCount -eq 0) {
            Write-Warn ("The client app has no secret yet. Create one in the portal (Entra > App registrations > " +
                        "$COPILOT_APP_NAME > Certificates & secrets) and enter it directly in Copilot Studio.")
        }
    }
}

# ── Restrict access to groups ("Assignment required") ─────────────────────────
$assignmentRequired = Invoke-AzCli -Arguments @('ad', 'sp', 'show', '--id', $CLIENT_ID, '--query', 'appRoleAssignmentRequired', '-o', 'tsv') -AllowFailure
if ($GROUP_IDS.Count -eq 0 -and $assignmentRequired -ne 'true' -and (Test-Interactive)) {
    Write-Step "Restricting access to the server"
    $GROUP_IDS = @(Request-AllowedGroups)
}
if ($GROUP_IDS.Count -gt 0) {
    Write-Step "Restricting access to $($GROUP_IDS.Count) group(s)"
    try {
        if ($SERVER_APP_PROTECTED) {
            Write-Warn "Server app $CLIENT_ID is protected: no assignment, 'Assignment required' stays unchanged."
        } else {
            Set-AppAssignment $CLIENT_ID 'Server-App' $GROUP_IDS
        }
        if ($COPILOT_APP_ID) {
            if (Invoke-AzCli -Arguments @('ad', 'sp', 'show', '--id', $COPILOT_APP_ID, '--query', 'id', '-o', 'tsv') -AllowFailure) {
                Set-AppAssignment $COPILOT_APP_ID 'Copilot-Client-App' $GROUP_IDS
            } else {
                Write-Warn "The Copilot client app has no service principal yet; run again with -ConfigureAppRegistration."
            }
        }
        if (-not $SERVER_APP_PROTECTED) { $assignmentRequired = 'true' }
        Write-Info "Note: Global Administrators can sign in even when assignment is required."
    } catch {
        Write-Warn ("Assignment failed (requires e.g. the role Cloud Application Administrator): " +
                    ((($_.Exception.Message -split "`n") | Select-Object -First 2) -join ' '))
    }
}
if ($assignmentRequired -ne 'true') {
    Write-Warn ("Server app: 'Assignment required' is OFF. Every user of the tenant who can reach the agent or connector " +
                "can use the server. Fix: ./deploy.ps1 -SkipBuild -Tag $Tag (asks for the group) " +
                "or -AllowedGroupIds '<object-id>'.")
}

# ── Remove old client secrets (optional, after a functional test) ──────────────
if ($RemoveOldClientSecrets -and $SERVER_APP_PROTECTED) {
    Write-Warn "Server app $CLIENT_ID is protected: -RemoveOldClientSecrets is not run."
} elseif ($RemoveOldClientSecrets) {
    Write-Step "Old client secrets of server app $CLIENT_ID"
    $creds = @(Invoke-AzCli -Arguments @('ad', 'app', 'credential', 'list', '--id', $CLIENT_ID, '-o', 'json') | ConvertFrom-Json)
    # Only the secret whose keyId was stored with the Key Vault secret during rotation is kept.
    $kvSecretId = "$($script:KV_ID)/secrets/${PREFIX}client-secret"
    $ct = Invoke-AzCli -Arguments @('resource', 'show', '--ids', $kvSecretId, '--query', 'properties.contentType', '-o', 'tsv') -AllowFailure
    $kvKeyId = if ("$ct" -match 'keyId=([0-9a-fA-F-]{36})') { $Matches[1].ToLower() } else { '' }
    $keep = @($creds | Where-Object { "$($_.keyId)".ToLower() -eq $kvKeyId }) | Select-Object -First 1
    if (-not $kvKeyId -or -not $keep) {
        Write-Warn ("Cannot determine which secret is stored in Key Vault (no keyId saved or secret no longer " +
                    "present). For safety nothing is deleted. First run ./deploy.ps1 -SkipBuild -Tag $Tag " +
                    "-RotateClientSecret, test the agent, then run -RemoveOldClientSecrets again.")
    } elseif ($creds.Count -le 1) {
        Write-Info "Only the active secret exists, nothing to delete."
    } else {
        $old = @($creds | Where-Object { $_.keyId -ne $keep.keyId })
        Write-Info ("Keep (in Key Vault): '{0}' created {1}, valid until {2}" -f $keep.displayName, $keep.startDateTime, $keep.endDateTime)
        $old | ForEach-Object { Write-Info ("Delete: '{0}' created {1}, valid until {2}, keyId {3}" -f $_.displayName, $_.startDateTime, $_.endDateTime, $_.keyId) }
        $answer = Read-Host "Permanently delete these $($old.Count) secret(s)? Confirm only if the agent works with the new secret (yes/no)"
        if (Test-Yes $answer) {
            foreach ($c in $old) {
                Invoke-AzCli -Arguments @('ad', 'app', 'credential', 'delete', '--id', $CLIENT_ID, '--key-id', $c.keyId) | Out-Null
                Write-Info "Deleted: '$($c.displayName)' ($($c.keyId))"
            }
        } else {
            Write-Info "Cancelled, nothing deleted."
        }
    }
}

# ── Summary ────────────────────────────────────────────────────────────────────
if ($rotatedSecret -and $rotatedSecret -ne 'manuell') {
    Write-Host "`nClient secret rotated ('$rotatedSecret'). Test the agent in Copilot Studio, then delete the old secrets:" -ForegroundColor Yellow
    Write-Host "  ./deploy.ps1 -SkipBuild -Tag $Tag -RemoveOldClientSecrets" -ForegroundColor Yellow
}
$authority = "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0"
Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " DEPLOYMENT COMPLETE (all tools)" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host " MCP endpoint  : $BASE_URL/mcp"
Write-Host " Server app    : $CLIENT_ID   Scope: api://$CLIENT_ID/$SCOPE"
Write-Host " Image         : $ACR_SERVER/${IMAGE}:$Tag"
Write-Host " Key Vault     : $KEYVAULT"
if ($RestrictIngressToPowerPlatform) { Write-Host " Ingress       : only $($ingressCidrs.Count) allowed IP ranges" }
Write-Host "============================================================"
Write-Host "`nCopilot Studio > Agent > Tools > Add a tool > Model Context Protocol:"
Write-Host "  Server URL          : $BASE_URL/mcp"
Write-Host "  Authentication      : OAuth 2.0 > Manual"
Write-Host "  Client ID           : $(if ($COPILOT_APP_ID) { $COPILOT_APP_ID } else { '<client app missing, see warning above>' })"
Write-Host "  Client secret       : create in the portal (Entra > App registrations > $COPILOT_APP_NAME > Certificates & secrets)"
Write-Host "  Authorization URL   : $authority/authorize"
Write-Host "  Token URL           : $authority/token"
Write-Host "  Refresh URL         : $authority/token"
Write-Host "  Scopes              : openid profile api://$CLIENT_ID/$SCOPE offline_access"
Write-Host "If Copilot Studio shows a redirect URL other than $COPILOT_DEFAULT_REDIRECT, add just that one (a few seconds):"
Write-Host "  ./deploy.ps1 -AddRedirectUri '<url>'"
Write-Host "After an update: refresh the tool list in Copilot Studio; changes per version: CHANGELOG.md."
if (-not $ConfigureAppRegistration) {
    Write-Host "`nApp registrations not configured yet? ./deploy.ps1 -SkipBuild -Tag $Tag -ConfigureAppRegistration"
}
