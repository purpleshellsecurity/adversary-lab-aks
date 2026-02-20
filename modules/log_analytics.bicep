// ============================================================================
// Layer 1: Foundation - Log Analytics Workspace
// No dependencies on other modules
// Enhanced for AKS Adversary Lab with resource-specific tables
// ============================================================================

param location string
param namePrefix string
param retentionInDays int = 90
param tags object = {}

var workspaceName = '${namePrefix}-aks-law'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
      // Enable resource-specific log ingestion for AKS dedicated tables
      // (AKSAudit, AKSAuditAdmin, AKSControlPlane vs AzureDiagnostics)
      disableLocalAuth: false
    }
    workspaceCapping: {
      dailyQuotaGb: -1 // No cap for security lab — need all telemetry
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// ── Custom table retention overrides ────────────────────────────────────────
// AKS audit logs are high-volume but critical for detection.
// Set longer retention on security-critical tables.

// Note: Resource-specific AKS tables (AKSAudit, AKSAuditAdmin, AKSControlPlane)
// are auto-created when diagnostic settings use 'Dedicated' destination type.
// Retention is inherited from workspace default but can be overridden via
// Tables API after first data ingestion.

output workspaceName string = workspace.name
output workspaceId string = workspace.properties.customerId
output workspaceResourceId string = workspace.id
