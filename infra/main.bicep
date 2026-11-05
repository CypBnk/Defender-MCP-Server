// Defender XDR MCP Server on Azure Container Apps - one server with all tools (profile 'full'; 'read' = read tools only).
// Existing prerequisites (deploy.ps1 creates them if missing):
//   Container Registry, Container Apps environment + Log Analytics workspace, Key Vault (RBAC mode).
//   Key Vault secrets (name = secretPrefix + name): client-secret, jwt-signing-key (mdca-api-token with mdcaAuth 'token').
// Sign-in: Copilot Studio signs in at Entra ID; the server only validates the tokens (no token storage).
targetScope = 'resourceGroup'

@description('Container App name, e.g. ca-defender-mcp-prod')
param appName string
param location string = resourceGroup().location
@allowed(['full', 'read'])
param profile string = 'full'
@description('Full image reference, e.g. myacr.azurecr.io/defender-mcp-server:v202611021200')
param image string
param acrName string
param keyVaultName string
@description('Secret name prefix in Key Vault, e.g. mcp-')
param secretPrefix string
@description('Existing Container Apps environment')
param environmentName string
@description('Existing Log Analytics workspace (used for Application Insights)')
param logAnalyticsName string
param appInsightsName string = '${appName}-ai'
param identityName string = '${appName}-id'
param tenantId string
@description('Application (client) ID of the server app registration')
param clientId string
@description('Scope name from "Expose an API" without prefix, e.g. access_as_user')
param requiredScope string = 'access_as_user'
@description('Comma-separated application IDs whose tokens are accepted (Copilot Studio client app)')
param allowedClientAppIds string = ''
@description('Change marker of the client secret in Key Vault; a new value forces a new revision that loads the secret')
param secretStamp string = ''
@description('Optional: IPv4 CIDRs allowed to reach the ingress (empty = no IP restriction)')
param allowedIngressCidrs array = []
@description('Defender for Endpoint API host (regional endpoints are faster, e.g. eu.api.security.microsoft.com)')
param mdeApiHost string = 'api.security.microsoft.com'
@description('Advanced hunting timeout per query in seconds (10-300)')
param huntingTimeoutSeconds int = 90
@description('Microsoft Sentinel / ISOC workspaces offered by name: name=workspace-id, comma-separated (optional).')
param sentinelWorkspaces string = ''
@description('Optional: Defender for Cloud Apps API URL for sanction_cloud_apps (undocumented endpoint), e.g. https://contoso.eu2.portal.cloudappsecurity.com')
param mdcaApiUrl string = ''
@allowed(['obo', 'token'])
@description('obo: signed-in user (delegated Discovery.manage); token: legacy Defender for Cloud Apps API token from Key Vault (secret <prefix>mdca-api-token)')
param mdcaAuth string = 'obo'
param minReplicas int = 1
param maxReplicas int = 3

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: acrName
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

resource env 'Microsoft.App/managedEnvironments@2024-03-01' existing = {
  name: environmentName
}

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: logAnalyticsName
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logs.id
  }
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityName
  location: location
}

// AcrPull
resource acrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, identity.id, '7f951dda-4ed3-4680-a7ca-43fe172d538d')
  scope: acr
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
  }
}

// Key Vault Secrets User
resource kvSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, identity.id, '4633458b-17de-408a-b874-0445c86b69e6')
  scope: kv
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
  }
}

var baseUrl = 'https://${appName}.${env.properties.defaultDomain}'
var kvSecretsBase = [
  { name: 'client-secret', env: 'CLIENT_SECRET' }
  { name: 'jwt-signing-key', env: 'JWT_SIGNING_KEY' }
]
var kvSecretsMdca = (!empty(mdcaApiUrl) && mdcaAuth == 'token') ? [
  { name: 'mdca-api-token', env: 'MDCA_API_TOKEN' }
] : []
var kvSecrets = concat(kvSecretsBase, kvSecretsMdca)
var plainEnv = [
  { name: 'TENANT_ID', value: tenantId }
  { name: 'CLIENT_ID', value: clientId }
  { name: 'BASE_URL', value: baseUrl }
  { name: 'MCP_REQUIRED_SCOPE', value: requiredScope }
  { name: 'MCP_PROFILE', value: profile }
  { name: 'ALLOWED_CLIENT_APP_IDS', value: allowedClientAppIds }
  { name: 'CLIENT_SECRET_UPDATED', value: secretStamp }
  { name: 'MDE_API_HOST', value: mdeApiHost }
  { name: 'HUNTING_TIMEOUT_SECONDS', value: string(huntingTimeoutSeconds) }
  { name: 'SENTINEL_WORKSPACES', value: sentinelWorkspaces }
  { name: 'MDCA_API_URL', value: mdcaApiUrl }
  { name: 'MDCA_AUTH', value: mdcaAuth }
  { name: 'MCP_ENV', value: 'production' }
  { name: 'LOG_FORMAT', value: 'json' }
  { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', secretRef: 'appinsights' }
]
// For-expressions must be variable/property values (not nested in function calls) and their bodies must be
// deploy-time constants: the vault URI is therefore built from the name instead of kv.properties.vaultUri.
var vaultUri = 'https://${keyVaultName}${environment().suffixes.keyvaultDns}/'
var kvSecretRefs = [for s in kvSecrets: {
  name: s.name
  keyVaultUrl: '${vaultUri}secrets/${secretPrefix}${s.name}'
  identity: identity.id
}]
var secretEnv = [for s in kvSecrets: { name: s.env, secretRef: s.name }]
var ipRules = [for (cidr, i) in allowedIngressCidrs: {
  name: 'allow-${i}'
  description: 'deploy.ps1'
  ipAddressRange: cidr
  action: 'Allow'
}]

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: appName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identity.id}': {} }
  }
  dependsOn: [ acrPull, kvSecretsUser ]
  properties: {
    managedEnvironmentId: env.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 8000
        transport: 'auto'
        allowInsecure: false
        ipSecurityRestrictions: empty(allowedIngressCidrs) ? null : ipRules
      }
      registries: [ { server: acr.properties.loginServer, identity: identity.id } ]
      secrets: concat(kvSecretRefs, [ { name: 'appinsights', value: appInsights.properties.ConnectionString } ])
    }
    template: {
      containers: [
        {
          name: 'defender-mcp'
          image: image
          resources: { cpu: json('0.5'), memory: '1Gi' }
          env: concat(plainEnv, secretEnv)
          probes: [
            { type: 'Startup', httpGet: { path: '/healthz', port: 8000 }, initialDelaySeconds: 3, periodSeconds: 5, failureThreshold: 24 }
            { type: 'Liveness', httpGet: { path: '/healthz', port: 8000 }, periodSeconds: 30, failureThreshold: 3 }
            { type: 'Readiness', httpGet: { path: '/readyz', port: 8000 }, periodSeconds: 15, failureThreshold: 3 }
          ]
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
        rules: [ { name: 'http', http: { metadata: { concurrentRequests: '30' } } } ]
      }
    }
  }
}

output baseUrl string = baseUrl
output mcpEndpoint string = '${baseUrl}/mcp'
output identityPrincipalId string = identity.properties.principalId
