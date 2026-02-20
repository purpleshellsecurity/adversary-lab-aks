# KQL Container Log Reference

Quick reference for querying every AKS log table in the Adversary Lab environment. Each section covers table schema, key fields, and practical detection queries.

> **Schema verified against:** [Azure Monitor Logs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/) (January 2026)
>
> All field names use **resource-specific mode** (dedicated tables, not AzureDiagnostics). Dynamic fields use **dot notation** (e.g., `ObjectRef.resource`, not `ObjectRef_Resource`).

---

## Table Overview

| Table | Source | Primary Use |
|-------|--------|-------------|
| AKSAudit | API server (all operations) | Full audit trail — exec, create, get, list, delete |
| AKSAuditAdmin | API server (mutations only) | State changes — create, update, patch, delete |
| AKSControlPlane | guard, kube-apiserver, scheduler, controllers | Auth decisions, admission control, scheduling |
| ContainerLogV2 | Container stdout/stderr | Application logs, process output, error messages |
| KubeEvents | Kubernetes events | Pod lifecycle — scheduling, pulling, starting, failing |
| KubePodInventory | Pod metadata snapshots | Pod status, containers, labels, node placement |
| KubeNodeInventory | Node metadata snapshots | Node status, capacity, OS info |
| KubeServices | Service metadata | Service types, ports, selectors |
| InsightsMetrics | Prometheus metrics | CPU, memory, network, disk counters |
| ContainerInventory | Container metadata | Running containers, images, states |
| ContainerNodeInventory | Node Docker/containerd info | Container runtime version, OS |
| SecurityAlert | Defender for Containers | Runtime threat detections |
| AzureActivity | ARM control plane | Resource CRUD, policy, RBAC changes |
| Heartbeat | Agent health | Agent connectivity and health |

---

## AKSAudit

The primary detection table. Contains every API server request including reads.

### Key Fields

| Field | Type | Description |
|-------|------|-------------|
| `Verb` | string | get, list, watch, create, update, patch, delete |
| `ObjectRef` | dynamic | Target resource — access via `ObjectRef.resource`, `ObjectRef.subresource`, `ObjectRef.namespace`, `ObjectRef.name`, `ObjectRef.apiGroup`, `ObjectRef.apiVersion` |
| `User` | dynamic | Authenticated identity — access via `User.username`, `User.uid`, `User.groups` |
| `SourceIps` | dynamic | Client IP array |
| `UserAgent` | string | kubectl, client-go, etc. |
| `ResponseStatus` | dynamic | Response info — access via `ResponseStatus.code`, `ResponseStatus.message` |
| `RequestObject` | dynamic | Full request body (JSON), or "skipped-too-big-size-object" |
| `ResponseObject` | dynamic | Full response body (JSON) for mutations |
| `RequestUri` | string | The URI of the request made by the client |
| `AuditId` | string | Unique audit ID per request |
| `Level` | string | Audit level — Metadata, Request, RequestResponse |
| `Stage` | string | RequestReceived, ResponseStarted, ResponseComplete, Panic |
| `PodName` | string | Name of the pod emitting this audit event |
| `Annotations` | dynamic | Plugin-set annotations on the audit event |


---

## AKSAuditAdmin

Mutations only — smaller, faster to query for detecting state changes.

### Key Differences from AKSAudit

- Only `create`, `update`, `patch`, `delete` verbs (excludes `get`, `list`, `watch`)
- Same schema as AKSAudit
- Much lower volume — better for alerting

---

## AKSControlPlane

Lower-level control plane components — guard (auth), kube-apiserver, scheduler, controller-manager, CSI drivers.

### Key Fields

| Field | Type | Description |
|-------|------|-------------|
| `Category` | string | guard, kube-apiserver, kube-scheduler, kube-controller-manager, cluster-autoscaler, cloud-controller-manager, csi-azuredisk-controller, csi-azurefile-controller, csi-snapshot-controller |
| `Message` | string | Log message body |
| `Level` | string | Fatal, Error, Warning, Info |
| `Stream` | string | stdout or stderr |
| `PodName` | string | Name of the pod logging the request |

---

## ContainerLogV2

Container stdout/stderr — application logs, process output, command results.

### Key Fields

| Field | Type | Description |
|-------|------|-------------|
| `PodName` | string | Pod name |
| `PodNamespace` | string | Namespace |
| `ContainerName` | string | Container within the pod |
| `ContainerId` | string | Container ID from the container engine |
| `LogMessage` | dynamic | Log content — JSON logs can be queried directly without `parse_json()` |
| `LogSource` | string | stdout or stderr |
| `LogLevel` | string | CRITICAL, ERROR, WARNING, INFO, DEBUG, TRACE, UNKNOWN |
| `Computer` | string | Node name |
| `KubernetesMetadata` | dynamic | Optional. Requires ConfigMap `metadata_collection enabled = true` and managed identity auth. Fields: podLabels, podAnnotations, podUid, Image, ImageID, ImageRepo, ImageTag. See [Container insights log schema](https://learn.microsoft.com/en-us/azure/azure-monitor/containers/container-insights-logs-schema). |


---

## KubeEvents

Kubernetes events — pod scheduling, image pulling, container state changes, warnings.

### Key Fields

| Field | Type | Description |
|-------|------|-------------|
| `Name` | string | Involved object name (e.g., pod name) |
| `Namespace` | string | Involved object namespace |
| `ObjectKind` | string | Pod, Node, ReplicaSet, etc. |
| `Reason` | string | Scheduled, Pulled, Failed, OOMKilling, BackOff, etc. |
| `Message` | string | Human-readable event description |
| `KubeEventType` | string | Normal or Warning |
| `Count` | real | Cumulative occurrence count |
| `FirstSeen` | datetime | First time event was observed |
| `LastSeen` | datetime | Last time event was observed |
| `SourceComponent` | string | Component that generated the event (e.g., default-scheduler) |
| `ClusterId` | string | Cluster resource ID |
| `ClusterName` | string | Cluster name |

> **Note:** By default, only Warning events are collected. To collect Normal events, enable `collect_all_kube_events` in the container-azm-ms-agentconfig ConfigMap. See [Configure agent data collection for Container insights](https://learn.microsoft.com/en-us/azure/azure-monitor/containers/container-insights-data-collection-configmap).


---

## KubePodInventory

Periodic pod state snapshots — shows what's running, where, and container status.

### Key Fields

| Field | Type | Description |
|-------|------|-------------|
| `Name` | string | Pod name |
| `Namespace` | string | Kubernetes namespace |
| `PodStatus` | string | Running, Pending, Failed, Succeeded |
| `PodUid` | string | Unique pod ID |
| `PodIp` | string | Pod IP address |
| `PodLabel` | string | Pod labels |
| `PodCreationTimeStamp` | datetime | When the pod was created |
| `PodStartTime` | datetime | When the pod started |
| `PodRestartCount` | int | Sum of all container restart counts |
| `ContainerName` | string | Container name (format: poduid/containername) |
| `ContainerID` | string | Container ID |
| `ContainerStatus` | string | Container's current state |
| `ContainerStatusReason` | string | Reason for container status (e.g., CrashLoopBackOff) |
| `ContainerLastStatus` | string | Container's last observed status |
| `ContainerRestartCount` | int | Restart count for the container |
| `ContainerCreationTimeStamp` | datetime | Container creation time |
| `ControllerKind` | string | ReplicaSet, DaemonSet, StatefulSet, Job, etc. |
| `ControllerName` | string | Controller name |
| `Computer` | string | Node hosting the pod |
| `ServiceName` | string | Associated Kubernetes service |
| `ClusterId` | string | Cluster resource ID |
| `ClusterName` | string | Cluster name |

> **Note:** This table does NOT contain image names. To get image data, either join with **ContainerInventory** on `ContainerID`, or enable the `KubernetesMetadata` column in **ContainerLogV2** via ConfigMap (`metadata_collection enabled = true`), which includes `Image`, `ImageTag`, `ImageRepo`, `ImageID`, `PodLabels`, `PodAnnotations`, and `PodUid`. See [Container insights log schema](https://learn.microsoft.com/en-us/azure/azure-monitor/containers/container-insights-logs-schema).


---

## InsightsMetrics

Prometheus-style metrics — CPU, memory, network, disk.

### Key Fields

| Field | Type | Description |
|-------|------|-------------|
| `Namespace` | string | Metric namespace (e.g., `container.azm.ms/disk`, `container.azm.ms/net`, `container.azm.ms/cpu`) |
| `Name` | string | Metric name (e.g., `cpuUsageNanoCores`, `memoryWorkingSetBytes`, `requests_count`) |
| `Val` | real | Metric value |
| `Tags` | string | Dimensions as JSON string — parse with `parse_json(Tags)` to access `.podName`, `.podNamespace`, `.containerName`, `.controllerName` |
| `Computer` | string | Node name |
| `AgentId` | string | Unique agent ID |
| `Origin` | string | Source (e.g., `container.azm.ms/telegraf`) |

> **Important:** `Tags` is a **string**, not dynamic. Always use `parse_json(Tags)` before accessing sub-fields.

---

## SecurityAlert

Defender for Containers runtime alerts.

### Key Fields

| Field | Type | Description |
|-------|------|-------------|
| `AlertName` | string | Detection rule name |
| `AlertSeverity` | string | High, Medium, Low, Informational |
| `AlertType` | string | Alert type identifier |
| `Description` | string | Alert description |
| `DisplayName` | string | Human-readable alert title |
| `Tactics` | string | MITRE ATT&CK tactic(s) |
| `Techniques` | string | MITRE ATT&CK technique ID(s) |
| `SubTechniques` | string | MITRE sub-technique ID(s) |
| `Entities` | string | Affected resources as JSON string — parse with `parse_json(Entities)` |
| `ExtendedProperties` | string | Additional alert properties as JSON string |
| `ProductName` | string | "Microsoft Defender for Containers" |
| `ProviderName` | string | Alert provider |
| `Status` | string | New, InProgress, Resolved |
| `CompromisedEntity` | string | Primary affected resource |
| `ConfidenceLevel` | string | Alert confidence |
| `ConfidenceScore` | real | Numeric confidence score |
| `AlertLink` | string | Link to the alert in the portal |
| `SystemAlertId` | string | Unique alert ID |
| `StartTime` | datetime | Alert start time |
| `EndTime` | datetime | Alert end time |

---

## AzureActivity

ARM-level operations — resource creation, deletion, policy changes, RBAC assignments.

### Key Fields

| Field | Type | Description |
|-------|------|-------------|
| `OperationNameValue` | string | Operation identifier (e.g., `Microsoft.ContainerService/managedClusters/write`) |
| `CategoryValue` | string | Administrative, Security, Policy, Alert, Recommendation, etc. |
| `ActivityStatusValue` | string | Started, Succeeded, Failed |
| `ActivitySubstatusValue` | string | Substatus (e.g., OK, Created, Forbidden) |
| `Caller` | string | User or service principal GUID/UPN |
| `CallerIpAddress` | string | Source IP |
| `ResourceGroup` | string | Target resource group |
| `Level` | string | Critical, Error, Warning, Informational, Verbose |
| `CorrelationId` | string | Groups related operations |
| `Authorization_d` | dynamic | RBAC properties — access via `.action`, `.role`, `.scope` |
| `Claims_d` | dynamic | JWT token claims |
| `Properties_d` | dynamic | Event details as dynamic column |
| `HTTPRequest` | string | Client request info (clientRequestId, clientIpAddress, method) |


---

## Reference Links

| Table | Official Schema |
|-------|----------------|
| AKSAudit | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aksaudit) |
| AKSAuditAdmin | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aksauditadmin) |
| AKSControlPlane | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/akscontrolplane) |
| ContainerLogV2 | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/containerlogv2) |
| KubeEvents | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/kubeevents) |
| KubePodInventory | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/kubepodinventory) |
| InsightsMetrics | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/insightsmetrics) |
| SecurityAlert | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityalert) |
| AzureActivity | [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity) |
