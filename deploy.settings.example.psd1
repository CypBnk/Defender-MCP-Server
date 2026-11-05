# =====================================================================================================================
# Settings for deploy.ps1 (Defender XDR MCP Server). Data only: values in quotes, lists as @('a', 'b'), no commands.
#
# deploy.ps1 reads deploy.settings.psd1 next to it. On the first run it creates that file from this template and
# writes the values it determines (tenant, globally unique names, app registration IDs, groups) into it. Edit
# deploy.settings.psd1, not this template; it is not part of the package and is kept when you unpack a new version.
# Settings missing in your file take the default from this template. Do not put secrets here: they are in Key Vault.
#
# Keep every setting on one line ("Name = value"); deploy.ps1 updates these lines and leaves the comments alone.
# '<auto>' = the script determines the value.
# =====================================================================================================================
@{
    # ---- Azure resources ----------------------------------------------------------------------------------------
    # Names below only need to be unique within the resource group, except where marked "globally unique".
    ResourceGroup = 'rg-defender-mcp-prod'
    # Azure region of all resources, e.g. 'westeurope', 'germanywestcentral', 'eastus'.
    Location = 'westeurope'
    # <auto>: tenant of the current az sign-in (the script checks that the subscription belongs to it).
    TenantId = '<auto>'
    # Globally unique, 5-50 characters a-z0-9. <auto>: crdefendermcpprod<suffix> (suffix from subscription and group).
    ContainerRegistry = '<auto>'
    # Globally unique, 3-24 characters. <auto>: kv-defxdrmcp-prod-<suffix>.
    KeyVault = '<auto>'
    ContainerAppsEnvironment = 'cae-defender-mcp-prod'
    LogAnalyticsWorkspace = 'log-defender-mcp-prod'
    ContainerApp = 'ca-defender-mcp-prod'
    # Image name in the container registry.
    ImageName = 'defender-mcp-server'

    # ---- App registrations --------------------------------------------------------------------------------------
    # Naming convention appreg-<workload>-<component>-<environment>; empty names follow it with this environment.
    AppRegEnvironment = 'prod'
    ServerAppRegName = ''
    CopilotClientAppRegName = ''
    # Empty: the script creates the app registrations (after asking) and fills in the IDs.
    ServerClientId = ''
    CopilotClientAppId = ''
    # Delegated scope that the server app exposes and Copilot Studio requests.
    ServerScope = 'access_as_user'
    # Prefix of the secrets in Key Vault.
    SecretPrefix = 'mcp-'
    # Object IDs of the groups whose DIRECT members may use the server. Empty: the script asks at the end.
    AllowedGroupIds = @()
    # App registrations the script must never change (no secrets, permissions, consents, assignments, redirect URIs).
    ProtectedAppIds = @()

    # ---- Server options -----------------------------------------------------------------------------------------
    # Defender for Endpoint API host. Regional hosts are faster and keep data in the region:
    # 'eu.api.security.microsoft.com', 'uk.api.security.microsoft.com', 'us.api.security.microsoft.com'.
    MdeApiHost = 'api.security.microsoft.com'
    # Microsoft Sentinel / ISOC workspaces the tools offer by name: 'name=workspace-id', several separated by commas.
    # Empty: queries go to the user's primary workspace (with ISOC usually the only one).
    SentinelWorkspaces = ''
    # sanction_cloud_apps only (UNDOCUMENTED Defender for Cloud Apps endpoint). API URL from the Defender portal:
    # Settings > Cloud Apps > System > About, e.g. 'https://contoso.eu2.portal.cloudappsecurity.com'. Empty: not configured.
    MdcaApiUrl = ''
    # 'obo': on behalf of the signed-in user (delegated Discovery.manage, granted with -GrantWritePermissions).
    # 'token': legacy Defender for Cloud Apps API token in Key Vault; acts with the token owner's permissions.
    MdcaAuth = 'obo'

    # ---- Network ------------------------------------------------------------------------------------------------
    # -RestrictIngressToPowerPlatform: service tags of the region of your Power Platform environment.
    # Empty: AzureConnectors.WestEurope and AzureConnectors.NorthEurope. United States e.g.
    # @('AzureConnectors.EastUS', 'AzureConnectors.WestUS').
    PowerPlatformServiceTags = @()
}
