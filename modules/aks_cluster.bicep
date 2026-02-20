// ============================================================================
// Layer 2: Compute - AKS Cluster
// Dependencies: networking (subnetIds), log_analytics (workspaceResourceId)
// 
// Security Profile:
//   - Azure CNI Overlay + Cilium eBPF dataplane (L7 network policies)
//   - Microsoft Defender for Containers sensor (eBPF DaemonSet)
//   - Entra ID RBAC (no local accounts)
//   - OIDC issuer + Workload Identity
//   - Azure Policy add-on (Gatekeeper)
//   - Key Vault Secrets Provider (CSI)
//   - Image Cleaner
//   - Node Restriction admission controller
//   - Authorized IP ranges on API server
// ============================================================================

param location string
param namePrefix string
param kubernetesVersion string = '1.34.2'
param systemNodeVmSize string = 'Standard_D2s_v3'
param userNodeVmSize string = 'Standard_D2s_v3'
param systemSubnetId string
param userSubnetId string
param logAnalyticsWorkspaceResourceId string
param adminGroupObjectId string
param authorizedIpRange string
param enableDefender bool = true
param enableAzurePolicy bool = true
param tags object = {}

var clusterName = '${namePrefix}-aks'
var nodeResourceGroup = '${namePrefix}-aks-nodes'

// ── AKS Managed Cluster ─────────────────────────────────────────────────────

resource aksCluster 'Microsoft.ContainerService/managedClusters@2025-03-01' = {
  name: clusterName
  location: location
  tags: tags
  sku: {
    name: 'Base'
    tier: 'Standard' // Uptime SLA — required for production-grade monitoring
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    kubernetesVersion: kubernetesVersion
    dnsPrefix: '${clusterName}-dns'
    enableRBAC: true

    // ── Entra ID Integration ──────────────────────────────────────────────
    // Disable local accounts = all auth goes through Entra ID
    // This ensures guard logs capture ALL authentication events (T1078)
    disableLocalAccounts: true
    aadProfile: {
      managed: true
      enableAzureRBAC: true
      adminGroupObjectIDs: [
        adminGroupObjectId
      ]
    }

    // ── Network Profile ───────────────────────────────────────────────────
    // Azure CNI Overlay + Cilium:
    //   - eBPF dataplane replaces kube-proxy
    //   - L7 network policies (HTTP/gRPC aware)
    //   - FQDN-based egress filtering
    //   - Hubble observability for network flow logging
    //   - Critical for detecting T1046 (Network Service Discovery),
    //     T1550.001 (Lateral Movement), T1498 (Network DoS)
    networkProfile: {
      networkPlugin: 'azure'
      networkPluginMode: 'overlay'
      networkDataplane: 'cilium'
      networkPolicy: 'cilium'
      podCidr: '10.244.0.0/16'
      serviceCidr: '10.245.0.0/16'
      dnsServiceIP: '10.245.0.10'
      loadBalancerSku: 'standard'
      outboundType: 'loadBalancer'
      loadBalancerProfile: {
        managedOutboundIPs: {
          count: 1
        }
      }
    }

    // ── Security Profile ──────────────────────────────────────────────────
    securityProfile: {
      // Workload Identity: Enables pod-level Entra ID authentication
      // Required for testing T1528 (Steal Application Access Token) scenarios
      workloadIdentity: {
        enabled: true
      }

      // Defender for Containers: eBPF sensor on every node
      // Detects: binary drift, web shells, crypto mining, network scanning,
      // container escape, suspicious exec, sensitive file access
      // Maps to 24+ MITRE ATT&CK Containers techniques
      defender: enableDefender ? {
        logAnalyticsWorkspaceResourceId: logAnalyticsWorkspaceResourceId
        securityMonitoring: {
          enabled: true
        }
      } : null

      // Image Cleaner: removes unused images to reduce attack surface
      imageCleaner: {
        enabled: true
        intervalHours: 48
      }
    }

    // ── OIDC + Workload Identity ──────────────────────────────────────────
    oidcIssuerProfile: {
      enabled: true
    }

    // ── Add-on Profiles ───────────────────────────────────────────────────
    addonProfiles: {
      // Azure Policy (Gatekeeper): enforces pod security standards
      // Critical for T1610 (Deploy Container), T1611 (Escape to Host)
      azurepolicy: {
        enabled: enableAzurePolicy
      }

      // Key Vault Secrets Provider (CSI Driver)
      // Enables testing of T1552 (Unsecured Credentials) mitigations
      azureKeyvaultSecretsProvider: {
        enabled: true
        config: {
          enableSecretRotation: 'true'
          rotationPollInterval: '2m'
        }
      }

      // OMS Agent: Container Insights for log collection
      // Populates ContainerLogV2, KubeEvents, KubePodInventory, etc.
      omsagent: {
        enabled: true
        config: {
          logAnalyticsWorkspaceResourceID: logAnalyticsWorkspaceResourceId
          useAADAuth: 'true'
        }
      }
    }

    // ── Azure Monitor Profile ─────────────────────────────────────────────
    // Container Insights is configured via DCR in container_insights.bicep
    azureMonitorProfile: {
      metrics: {
        enabled: true
      }
    }

    // ── Node Pools ────────────────────────────────────────────────────────
    agentPoolProfiles: [
      {
        name: 'system'
        count: 1
        vmSize: systemNodeVmSize
        mode: 'System'
        osType: 'Linux'
        osSKU: 'AzureLinux'
        vnetSubnetID: systemSubnetId
        enableAutoScaling: true
        minCount: 1
        maxCount: 3
        maxPods: 110
        // Taint system pool so only critical add-ons run here
        // Defender sensor, CoreDNS, konnectivity, etc.
        nodeTaints: [
          'CriticalAddonsOnly=true:NoSchedule'
        ]
        nodeLabels: {
          'adversary-lab/pool': 'system'
        }
        upgradeSettings: {
          maxSurge: '33%'
        }
      }
      {
        name: 'seclab'
        count: 1
        vmSize: userNodeVmSize
        mode: 'User'
        osType: 'Linux'
        osSKU: 'AzureLinux'
        vnetSubnetID: userSubnetId
        enableAutoScaling: true
        minCount: 1
        maxCount: 6
        maxPods: 110
        nodeLabels: {
          'adversary-lab/pool': 'workload'
        }
        upgradeSettings: {
          maxSurge: '33%'
        }
      }
    ]

    // ── API Server Access ─────────────────────────────────────────────────
    // Public cluster with authorized IP ranges
    // Avoids private cluster overhead (bastion/jumpbox) while restricting access
    apiServerAccessProfile: {
      enablePrivateCluster: false
      authorizedIPRanges: [
        '${authorizedIpRange}/32'
      ]
    }

    // ── Node Resource Group ───────────────────────────────────────────────
    nodeResourceGroup: nodeResourceGroup
    nodeResourceGroupProfile: {
      restrictionLevel: 'ReadOnly' // Prevent tampering with node-level resources
    }

    // ── Upgrade Profile ───────────────────────────────────────────────────
    autoUpgradeProfile: {
      upgradeChannel: 'stable'
      nodeOSUpgradeChannel: 'NodeImage'
    }

    // ── Storage Profile ───────────────────────────────────────────────────
    storageProfile: {
      diskCSIDriver: {
        enabled: true
      }
      fileCSIDriver: {
        enabled: true
      }
      snapshotController: {
        enabled: true
      }
    }
  }
}

// ── Outputs ─────────────────────────────────────────────────────────────────

output clusterName string = aksCluster.name
output clusterResourceId string = aksCluster.id
output clusterFqdn string = aksCluster.properties.fqdn
output kubeletIdentityObjectId string = aksCluster.properties.identityProfile.kubeletidentity.objectId
output clusterPrincipalId string = aksCluster.identity.principalId
output oidcIssuerUrl string = aksCluster.properties.oidcIssuerProfile.issuerURL
output nodeResourceGroup string = aksCluster.properties.nodeResourceGroup
