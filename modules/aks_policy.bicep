// ============================================================================
// Layer 4: Governance - Policy Assignment (Resource Group Scope)
//
// The policy definitions + initiative are in aks_policy_defs.bicep at
// subscription scope. This module creates the RG-scoped assignment and
// the role assignments the DINE policy's managed identity needs.
// ============================================================================

targetScope = 'resourceGroup'

@description('The resource ID of the policy initiative to assign')
param initiativeId string

@description('Log Analytics Workspace Resource ID for the initiative parameter')
param logAnalyticsWorkspaceId string

// ── Initiative Assignment ───────────────────────────────────────────────────

resource initiativeAssignment 'Microsoft.Authorization/policyAssignments@2022-06-01' = {
  name: 'aks-lab-mitre-logging'
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    displayName: 'AKS Adversary Lab - MITRE Logging Enforcement'
    description: 'DeployIfNotExists enforcement for all 11 AKS diagnostic categories. The policy managed identity auto-creates diagnostic settings on any AKS cluster missing them.'
    policyDefinitionId: initiativeId
    enforcementMode: 'Default'
    parameters: {
      logAnalyticsWorkspaceId: { value: logAnalyticsWorkspaceId }
    }
    nonComplianceMessages: [
      {
        message: 'This AKS cluster is missing full diagnostic logging. The policy will auto-deploy a diagnostic setting with all 11 categories in resource-specific mode.'
        policyDefinitionReferenceId: 'aksDineAllDiagCategories'
      }
      {
        message: 'This resource does not comply with the AKS Adversary Lab security requirements.'
      }
    ]
  }
}

// ── Role Assignments for DINE Managed Identity ──────────────────────────────

// Monitoring Contributor — create/modify diagnostic settings
resource assignmentMonitoringRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(initiativeAssignment.id, 'monitoring-contributor')
  properties: {
    principalId: initiativeAssignment.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '749f88d5-cbae-40b8-bcfc-e573ddc772fa')
    principalType: 'ServicePrincipal'
  }
}

// Log Analytics Contributor — write to workspace
resource assignmentLogAnalyticsRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(initiativeAssignment.id, 'log-analytics-contributor')
  properties: {
    principalId: initiativeAssignment.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '92aaf0da-9dab-42b6-94a3-d43ce8d16293')
    principalType: 'ServicePrincipal'
  }
}

// Contributor — ARM deployment operations for the inline template
resource assignmentContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(initiativeAssignment.id, 'contributor')
  properties: {
    principalId: initiativeAssignment.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c')
    principalType: 'ServicePrincipal'
  }
}

// ── Outputs ─────────────────────────────────────────────────────────────────

output assignmentId string = initiativeAssignment.id
output assignmentPrincipalId string = initiativeAssignment.identity.principalId
