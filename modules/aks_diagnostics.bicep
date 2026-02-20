// ============================================================================
// Layer 3: Monitoring - AKS Diagnostic Settings
// Dependencies: aks_cluster (clusterName), log_analytics (workspaceId)
//
// Enables ALL 11 AKS diagnostic log categories with resource-specific routing.
// Resource-specific mode writes to dedicated tables:
//   - AKSAudit (kube-audit) — HIGHEST VALUE: full API audit trail
//   - AKSAuditAdmin (kube-audit-admin) — state-changing operations only
//   - AKSControlPlane (all other categories)
//
// MITRE Coverage: kube-audit alone provides detection signal for 24/29 techniques
// ============================================================================

param aksClusterName string
param logAnalyticsWorkspaceId string

// Reference existing AKS cluster
resource aksCluster 'Microsoft.ContainerService/managedClusters@2025-02-01' existing = {
  name: aksClusterName
}

// ── Diagnostic Settings: ALL Categories ─────────────────────────────────────

resource aksDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: '${aksClusterName}-full-security-diag'
  scope: aksCluster
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    // CRITICAL: Use 'Dedicated' for resource-specific tables
    // This routes to AKSAudit/AKSAuditAdmin/AKSControlPlane tables
    // instead of the monolithic AzureDiagnostics table
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      // ── Category 1: kube-audit ──────────────────────────────────────────
      // Full Kubernetes API audit log including GET/LIST operations.
      // HIGHEST volume but ESSENTIAL for detecting:
      //   T1552.007 (Container API credential access — GET secrets)
      //   T1613 (Container and Resource Discovery — LIST pods/services)
      //   T1069 (Permission Groups Discovery — LIST roles/rolebindings)
      //   T1609 (Container Admin Command — exec subresource)
      //   T1610 (Deploy Container — pod creation)
      //   T1098.006 (Additional Cluster Roles — RBAC mutations)
      // Routes to: AKSAudit table
      {
        category: 'kube-audit'
        enabled: true
      }

      // ── Category 2: kube-audit-admin ────────────────────────────────────
      // State-changing operations only (create/update/delete/patch).
      // Lower volume subset of kube-audit. Useful for cost-sensitive environments.
      // In our lab we enable BOTH for maximum coverage.
      // Routes to: AKSAuditAdmin table
      {
        category: 'kube-audit-admin'
        enabled: true
      }

      // ── Category 3: kube-apiserver ──────────────────────────────────────
      // API server operational logs, health checks, request processing.
      // Detects: T1499 (Endpoint DoS against API server), misconfigurations
      // Routes to: AKSControlPlane table
      {
        category: 'kube-apiserver'
        enabled: true
      }

      // ── Category 4: kube-controller-manager ─────────────────────────────
      // Controller lifecycle: replication, SA token generation, namespace events.
      // Detects: T1136.001 (Account creation — SA controller activity),
      //          T1543.005 (Container Service — DaemonSet/ReplicaSet changes)
      // Routes to: AKSControlPlane table
      {
        category: 'kube-controller-manager'
        enabled: true
      }

      // ── Category 5: kube-scheduler ──────────────────────────────────────
      // Pod scheduling decisions, node affinity, resource availability.
      // Detects: anomalous scheduling patterns, T1496 (Resource Hijacking —
      //          crypto miners causing scheduling pressure)
      // Routes to: AKSControlPlane table
      {
        category: 'kube-scheduler'
        enabled: true
      }

      // ── Category 6: cluster-autoscaler ──────────────────────────────────
      // Node scaling decisions, resource exhaustion triggers.
      // Detects: T1496.001 (Compute Hijacking — miner pods trigger scale-up),
      //          T1499 (DoS — resource exhaustion causing autoscale)
      // Routes to: AKSControlPlane table
      {
        category: 'cluster-autoscaler'
        enabled: true
      }

      // ── Category 7: cloud-controller-manager ────────────────────────────
      // Azure resource provisioning: load balancers, routes, public IPs.
      // Detects: unauthorized infrastructure changes, T1498 (Network DoS setup)
      // Routes to: AKSControlPlane table
      {
        category: 'cloud-controller-manager'
        enabled: true
      }

      // ── Category 8: guard ───────────────────────────────────────────────
      // CRITICAL: Entra ID authentication and authorization events.
      // Captures Azure RBAC decisions, token validation, login attempts.
      // Detects: T1078 (Valid Accounts — auth events), T1110 (Brute Force —
      //          failed auth), T1550.001 (Application Access Token — token reuse)
      // Routes to: AKSControlPlane table
      {
        category: 'guard'
        enabled: true
      }

      // ── Category 9: csi-azuredisk-controller ────────────────────────────
      // Azure Disk CSI operations: volume attach/detach/snapshot.
      // Detects: T1485 (Data Destruction — PVC deletion),
      //          unauthorized storage access patterns
      // Routes to: AKSControlPlane table
      {
        category: 'csi-azuredisk-controller'
        enabled: true
      }

      // ── Category 10: csi-azurefile-controller ───────────────────────────
      // Azure File CSI operations: file share mount/unmount.
      // Detects: data exfiltration via file shares, unauthorized mounts
      // Routes to: AKSControlPlane table
      {
        category: 'csi-azurefile-controller'
        enabled: true
      }

      // ── Category 11: csi-snapshot-controller ────────────────────────────
      // Volume snapshot creation and management.
      // Detects: T1490 (Inhibit System Recovery — snapshot deletion),
      //          data theft via snapshot cloning
      // Routes to: AKSControlPlane table
      {
        category: 'csi-snapshot-controller'
        enabled: true
      }
    ]

    // ── Metrics ─────────────────────────────────────────────────────────────
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

// ── Outputs ─────────────────────────────────────────────────────────────────

output diagnosticSettingsName string = aksDiagnostics.name
output diagnosticSettingsId string = aksDiagnostics.id
output categoriesEnabled array = [
  'kube-audit'
  'kube-audit-admin'
  'kube-apiserver'
  'kube-controller-manager'
  'kube-scheduler'
  'cluster-autoscaler'
  'cloud-controller-manager'
  'guard'
  'csi-azuredisk-controller'
  'csi-azurefile-controller'
  'csi-snapshot-controller'
]
