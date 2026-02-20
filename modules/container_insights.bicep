// ============================================================================
// Layer 3: Monitoring - Container Insights (Data Collection Rule)
// Dependencies: aks_cluster, log_analytics
//
// Container Insights collects workload-level telemetry:
//   - ContainerLogV2: stdout/stderr from containers
//   - KubeEvents: pod lifecycle events
//   - KubePodInventory: pod status and metadata
//   - InsightsMetrics: CPU, memory, network metrics per container
//   - KubeNodeInventory: node status
//   - KubeServices: service definitions
//
// NOTE: This is SEPARATE from AKS control plane diagnostic settings.
// Control plane logs = API server, audit, scheduler, etc.
// Container Insights = workload logs, metrics, inventory.
// Both are required for full MITRE ATT&CK coverage.
// ============================================================================

param location string
param namePrefix string
param aksClusterName string
param logAnalyticsWorkspaceResourceId string

var dcrName = '${namePrefix}-aks-ci-dcr'

// ── Data Collection Rule ────────────────────────────────────────────────────

resource containerInsightsDcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  kind: 'Linux'
  properties: {
    dataSources: {
      extensions: [
        {
          name: 'ContainerInsightsExtension'
          extensionName: 'ContainerInsights'
          streams: [
            'Microsoft-ContainerLogV2'
            'Microsoft-KubeEvents'
            'Microsoft-KubePodInventory'
            'Microsoft-KubeNodeInventory'
            'Microsoft-KubeServices'
            'Microsoft-KubeMonAgentEvents'
            'Microsoft-InsightsMetrics'
            'Microsoft-ContainerInventory'
            'Microsoft-ContainerNodeInventory'
            'Microsoft-Perf'
          ]
          extensionSettings: {
            dataCollectionSettings: {
              interval: '1m'
              namespaceFilteringMode: 'Off' // Collect from ALL namespaces
              enableContainerLogV2: true     // Use V2 schema (structured)
            }
          }
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: logAnalyticsWorkspaceResourceId
          name: 'ciworkspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Microsoft-ContainerLogV2'
          'Microsoft-KubeEvents'
          'Microsoft-KubePodInventory'
          'Microsoft-KubeNodeInventory'
          'Microsoft-KubeServices'
          'Microsoft-KubeMonAgentEvents'
          'Microsoft-InsightsMetrics'
          'Microsoft-ContainerInventory'
          'Microsoft-ContainerNodeInventory'
          'Microsoft-Perf'
        ]
        destinations: [
          'ciworkspace'
        ]
      }
    ]
  }
}

// ── DCR Association with AKS Cluster ────────────────────────────────────────

resource aksCluster 'Microsoft.ContainerService/managedClusters@2025-03-01' existing = {
  name: aksClusterName
}

resource dcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2023-03-11' = {
  name: 'ContainerInsightsExtension'
  scope: aksCluster
  properties: {
    dataCollectionRuleId: containerInsightsDcr.id
    description: 'Container Insights DCR association for AKS adversary lab'
  }
}

// ── Outputs ─────────────────────────────────────────────────────────────────

output dcrId string = containerInsightsDcr.id
output dcrName string = containerInsightsDcr.name
output dcrAssociationId string = dcrAssociation.id
