// ============================================================================
// Layer 1: Foundation - Key Vault
// No dependencies on other modules
// Used for:
//   - Storing lab secrets (kubeconfig tokens, test credentials)
//   - AKS CSI Secrets Store Provider integration
//   - Testing T1552 (Unsecured Credentials) mitigations
//   - Demonstrating proper secret injection vs. K8s native secrets
// ============================================================================

param location string
param namePrefix string
param logAnalyticsWorkspaceId string
param tags object = {}

var keyVaultName = 'kv${toLower(replace(namePrefix, '-', ''))}${substring(uniqueString(resourceGroup().id), 0, 4)}'

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true // Use Azure RBAC, not access policies
    enableSoftDelete: true
    softDeleteRetentionInDays: 7 // Short for lab — easy cleanup
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

// ── Diagnostic Settings ─────────────────────────────────────────────────────
// Logs all secret/key/certificate operations for detection of:
//   T1552 (Unsecured Credentials), T1098 (Account Manipulation)
resource kvDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'kv-to-law'
  scope: keyVault
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

output keyVaultName string = keyVault.name
output keyVaultResourceId string = keyVault.id
output keyVaultUri string = keyVault.properties.vaultUri
