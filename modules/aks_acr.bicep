// ============================================================================
// Layer 1: Foundation - Azure Container Registry
// No dependencies on other modules
// Used for:
//   - Storing red team container images (Peirates, MTKPI, etc.)
//   - Storing victim app images (DVWA, vulnerable APIs)
//   - Testing T1525 (Implant Internal Image) scenarios
//   - Testing T1204.003 (Malicious Image) detection
// ============================================================================

param location string
param namePrefix string
param logAnalyticsWorkspaceId string
param tags object = {}

// ACR names must be globally unique, alphanumeric only
var acrName = '${toLower(replace(namePrefix, '-', ''))}acr${substring(uniqueString(resourceGroup().id), 0, 6)}'

resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' = {
  name: acrName
  location: location
  tags: tags
  sku: {
    name: 'Standard' // Standard supports webhooks, geo-replication not needed for lab
  }
  properties: {
    adminUserEnabled: false // Use managed identity, not admin creds
    publicNetworkAccess: 'Enabled'
    // Encryption at rest with service-managed keys
    encryption: {
      status: 'disabled' // Use platform-managed keys for lab
    }
    dataEndpointEnabled: false
  }
}

// ── Diagnostic Settings ─────────────────────────────────────────────────────
// Logs image push/pull/delete events for detection of:
//   T1525 (Implant Internal Image), T1204.003 (Malicious Image)
resource acrDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'acr-to-law'
  scope: acr
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      { categoryGroup: 'allLogs', enabled: true }
    ]
    metrics: [
      { category: 'AllMetrics', enabled: true }
    ]
  }
}

output acrName string = acr.name
output acrResourceId string = acr.id
output acrLoginServer string = acr.properties.loginServer
