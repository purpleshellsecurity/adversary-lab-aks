// ============================================================================
// AKS Adversary Lab - Main Deployment Orchestrator
// MITRE ATT&CK Containers Matrix Coverage
// Extension of purpleshellsecurity/adversary_lab for Kubernetes threats
// ============================================================================
// Architecture: Single AKS cluster with namespace isolation
// Networking: Azure CNI Overlay + Cilium (eBPF dataplane)
// Logging: All 11 AKS diagnostic categories + Container Insights + Defender
// Policy: Custom initiative enforcing comprehensive logging
// ============================================================================

targetScope = 'resourceGroup'

// ── Parameters ──────────────────────────────────────────────────────────────

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Name prefix for all resources (lowercase, no special chars)')
@minLength(3)
@maxLength(15)
param namePrefix string

@description('Entra ID group Object ID for AKS cluster-admin access')
param adminGroupObjectId string

@description('Your public IP address for API server authorized access')
param authorizedIpRange string

@description('Log Analytics retention in days')
@minValue(30)
@maxValue(730)
param logRetentionDays int = 90

@description('Kubernetes version')
param kubernetesVersion string = '1.34.2'

@description('AKS system node pool VM size')
param systemNodeVmSize string = 'Standard_D2s_v3'

@description('AKS user (workload) node pool VM size')
param userNodeVmSize string = 'Standard_D2s_v3'

@description('Enable Microsoft Defender for Containers')
param enableDefender bool = true

@description('Enable Azure Policy add-on for AKS')
param enableAzurePolicy bool = true

@description('Deploy Sentinel solutions for AKS/Container monitoring')
param enableSentinelSolutions bool = true

@description('Tags applied to all resources')
param tags object = {
  Environment: 'SecurityLab'
  Project: 'AKS-Adversary-Lab'
  Purpose: 'MITRE-ATT&CK-Containers'
  ManagedBy: 'Bicep'
}

// ── Layer 1: Foundation ─────────────────────────────────────────────────────

// Log Analytics Workspace (reuse existing or create new)
module logAnalytics 'modules/log_analytics.bicep' = {
  name: 'deploy-log-analytics'
  params: {
    location: location
    namePrefix: namePrefix
    retentionInDays: logRetentionDays
    tags: tags
  }
}

// Networking: VNet with AKS-optimized subnets
module networking 'modules/aks_networking.bicep' = {
  name: 'deploy-aks-networking'
  params: {
    location: location
    namePrefix: namePrefix
    tags: tags
  }
}

// Azure Container Registry
module acr 'modules/aks_acr.bicep' = {
  name: 'deploy-acr'
  params: {
    location: location
    namePrefix: namePrefix
    logAnalyticsWorkspaceId: logAnalytics.outputs.workspaceResourceId
    tags: tags
  }
}

// Key Vault for secrets management
module keyVault 'modules/aks_keyvault.bicep' = {
  name: 'deploy-keyvault'
  params: {
    location: location
    namePrefix: namePrefix
    logAnalyticsWorkspaceId: logAnalytics.outputs.workspaceResourceId
    tags: tags
  }
}

// ── Layer 2: Compute ────────────────────────────────────────────────────────

// AKS Cluster with full security profile
module aksCluster 'modules/aks_cluster.bicep' = {
  name: 'deploy-aks-cluster'
  params: {
    location: location
    namePrefix: namePrefix
    kubernetesVersion: kubernetesVersion
    systemNodeVmSize: systemNodeVmSize
    userNodeVmSize: userNodeVmSize
    systemSubnetId: networking.outputs.systemSubnetId
    userSubnetId: networking.outputs.userSubnetId
    logAnalyticsWorkspaceResourceId: logAnalytics.outputs.workspaceResourceId
    adminGroupObjectId: adminGroupObjectId
    authorizedIpRange: authorizedIpRange
    enableDefender: enableDefender
    enableAzurePolicy: enableAzurePolicy
    tags: tags
  }
}

// ACR Pull role assignment for AKS
module acrRoleAssignment 'modules/aks_acr_role.bicep' = {
  name: 'deploy-acr-role'
  params: {
    acrName: acr.outputs.acrName
    aksPrincipalId: aksCluster.outputs.kubeletIdentityObjectId
  }
}

// ── Layer 3: Monitoring ─────────────────────────────────────────────────────

// AKS Diagnostic Settings (all 11 categories)
module aksDiagnostics 'modules/aks_diagnostics.bicep' = {
  name: 'deploy-aks-diagnostics'
  params: {
    aksClusterName: aksCluster.outputs.clusterName
    logAnalyticsWorkspaceId: logAnalytics.outputs.workspaceResourceId
  }
}

// Container Insights via Data Collection Rule
module containerInsights 'modules/container_insights.bicep' = {
  name: 'deploy-container-insights'
  params: {
    location: location
    namePrefix: namePrefix
    aksClusterName: aksCluster.outputs.clusterName
    logAnalyticsWorkspaceResourceId: logAnalytics.outputs.workspaceResourceId
  }
}

// Sentinel onboarding + AKS/Container solutions
module sentinel 'modules/aks_sentinel.bicep' = if (enableSentinelSolutions) {
  name: 'deploy-aks-sentinel'
  params: {
    workspaceName: logAnalytics.outputs.workspaceName
  }
}

// ── Layer 4: Governance ─────────────────────────────────────────────────────

// Policy definitions + initiative at subscription scope (required by ARM)
module aksPolicyDefs 'modules/aks_policy_defs.bicep' = {
  name: 'deploy-aks-policy-defs'
  scope: subscription()
}

// Policy assignment + role assignments at resource group scope
module aksPolicy 'modules/aks_policy.bicep' = {
  name: 'deploy-aks-policy'
  params: {
    initiativeId: aksPolicyDefs.outputs.initiativeId
    logAnalyticsWorkspaceId: logAnalytics.outputs.workspaceResourceId
  }
  dependsOn: [ aksPolicyDefs ]
}

// ── Outputs ─────────────────────────────────────────────────────────────────

output clusterName string = aksCluster.outputs.clusterName
output clusterFqdn string = aksCluster.outputs.clusterFqdn
output kubectlConnectCommand string = 'az aks get-credentials --resource-group ${resourceGroup().name} --name ${aksCluster.outputs.clusterName}'
output logAnalyticsWorkspaceName string = logAnalytics.outputs.workspaceName
output logAnalyticsWorkspaceId string = logAnalytics.outputs.workspaceResourceId
output acrLoginServer string = acr.outputs.acrLoginServer
output keyVaultName string = keyVault.outputs.keyVaultName
output keyVaultUri string = keyVault.outputs.keyVaultUri

// Post-deployment instructions
output postDeploySteps array = [
  '1. Run: ${aksCluster.outputs.clusterName} | az aks get-credentials'
  '2. Apply namespaces: kubectl apply -f kubernetes/namespaces/'
  '3. Apply network policies: kubectl apply -f kubernetes/network-policies/'
  '4. Apply RBAC: kubectl apply -f kubernetes/rbac/'
  '5. Deploy victim apps: kubectl apply -f kubernetes/victim-apps/'
  '6. Deploy blue team tools: helm install falco falcosecurity/falco -n monitoring'
  '7. Deploy red team tools: kubectl apply -f kubernetes/red-team/'
  '8. Verify logs flowing: Run KQL queries from detection/kql-queries/'
  '9. Wait 15-30 min for Defender sensor initialization'
  '10. Begin attack simulations per MITRE ATT&CK Containers matrix'
]
