# SWT3 Witness Agent

Cross-silicon hardware attestation for Kubernetes AI infrastructure.

Runs as a **DaemonSet** -- one pod per node. Discovers accelerator hardware
(NVIDIA GPU, Google TPU, AMD MI, AWS Trainium/Inferentia, Intel Gaudi) and
mints AI-HW.1 Witness Anchors on a configurable interval.

> **Protocol Spec:** [swt3.ai/spec](https://swt3.ai/spec) | **Registry:** [swt3.ai/registry](https://swt3.ai/registry) | **Verify:** [swt3.ai/verify](https://swt3.ai/verify)

## What's New in v0.7.4

- Aligned agent, container image, and Helm chart with SDK v0.7.4 release.
- Underlying `@tenova/swt3-ai` SDK now at 0.7.4 with 278 procedures across 10 namespaces.
- 3 new procedures: runtime containment attestation (AI-SHELL.1), distillation provenance (AI-DIST.1), elicitation detection (AI-MCP.6). Incident lifecycle chains for forensic sequences.
- AI-SHELL.1 produces cryptographic evidence from any OCSF-compatible sandbox (OpenShell, gVisor, Kata, Firecracker, WASM). Kubernetes operators managing sandboxed agent workloads gain containment attestation alongside existing model integrity and inference witnessing.
- 75 MCP tools, 277 compliance guides. [NVIDIA OpenShell Crosswalk](https://sovereign.tenova.io/guides/nvidia-openshell-crosswalk.html).

**Why this matters for Kubernetes:** AI-SHELL.1 turns sandbox enforcement into auditable evidence. A DaemonSet already sees every node -- now it can attest that gVisor, Kata, Firecracker, or OpenShell containment policies were enforced during a specific observation window, not just that they were configured. Distillation provenance (AI-DIST.1) records teacher-to-student lineage for on-cluster model compression jobs. Elicitation detection (AI-MCP.6) captures prompt boundary violations in MCP sidecar deployments. All three procedures mint with the same fingerprint formula as every other SDK language -- zero image rebuild required.

## What's New in v0.7.3

- Aligned agent, container image, and Helm chart with SDK v0.7.3 "Agent Protocol" release.
- Underlying `@tenova/swt3-ai` SDK now at 0.7.3 with 284 procedures across 10 namespaces.
- 4 new procedures: task delegation lifecycle (AI-A2A.1), agent card discovery (AI-A2A.2), context chain linking (AI-A2A.3), OAuth token binding (AI-MCP.5). A2A namespace added (10th namespace).
- Kubernetes operators managing multi-agent deployments gain visibility into A2A task delegation across pod boundaries. The four new procedures complement the existing agent lifecycle and chain witnessing.
- 72 MCP tools, 269 compliance guides, `swt3 crosswalk <procedure>` CLI command for offline framework mapping lookup.

## What's New in v0.7.2

- Aligned agent, container image, and Helm chart with SDK v0.7.2 "Harness Governance" release.
- Underlying `@tenova/swt3-ai` SDK now at 0.7.2 with 280 procedures across 77 namespaces.
- 5 new harness governance procedures: orchestration topology (AI-ORCH.1), agent handoff (AI-ORCH.2), context window management (AI-CTX.1), sandbox enforcement (AI-SAND.1), eval gate (AI-GATE.1). The witness agent can now attest orchestration decisions for multi-agent Kubernetes workloads -- which agent ran on which node, whether context was truncated, and whether the eval gate passed before deployment.
- Witness Middleware (`withSWT3(transport)`) available in the companion MCP package. Any MCP server running as a sidecar or service in your cluster gains cryptographic attestation by wrapping its transport -- no tool handler changes.
- 68 MCP tools, 265 compliance guides, ~3,000 tests passing across 10 languages.

## What's New in v0.7.1

- Aligned agent, container image, and Helm chart with SDK v0.7.1 "MCP Security" release.
- Underlying `@tenova/swt3-ai` SDK now at 0.7.1 with 275 procedures across 77 namespaces.
- 3 new MCP security procedures: tool integrity attestation (AI-MCP.2), server auth attestation (AI-MCP.3), server discovery attestation (AI-MCP.4). Full OWASP MCP Top 10 coverage with cryptographic evidence.
- 68 MCP tools, ~3,000 tests passing across 10 languages.

## What's New in v0.7.0

- Aligned agent, container image, and Helm chart with SDK v0.7.0 "Infrastructure" release.
- Underlying `@tenova/swt3-ai` SDK now at 0.7.0 with 266 procedures across 75 namespaces.
- New procedure families: NHI (credential governance), HBOM/DPP (hardware + battery passport), ADR (demand response). The witness agent can now attest hardware inventory (HBOM-INV.1) and thermal profiles (HBOM-THERM.1) alongside existing GPU attestation (AI-HW.1).
- ~2,950 tests passing across all 10 SDK languages.

## What's New in v0.6.6

- Aligned agent, container image, and Helm chart with SDK v0.6.6 "Supply Chain" release.
- Underlying `@tenova/swt3-ai` SDK now at 0.6.6 with 118 procedures across 64 namespaces.
- 2,825 tests passing across all 10 SDK languages.

## Quick Start

```bash
# Local mode -- anchors emit as structured JSON to stdout
helm install swt3 oci://ghcr.io/tenova-labs/charts/swt3-witness --version 0.7.2

# Cloud mode -- anchors flush to the SWT3 clearing house
helm install swt3 oci://ghcr.io/tenova-labs/charts/swt3-witness --version 0.7.2 \
  --set config.mode=cloud \
  --set cloud.apiKey=axm_YOUR_KEY \
  --set cloud.tenantId=YOUR_TENANT
```

## How It Works

```
Node boot --> DaemonSet pod starts --> queryHardware() discovers accelerators
--> mintFingerprint() creates AI-HW.1 anchor --> emit to stdout or clearing house
--> repeat every interval (default: 1 hour)
```

**Local mode** (default): Anchors print as structured JSON to stdout. Scrape
with Fluentd, Promtail, or any log pipeline. Filter: `jq 'select(.swt3_witness == true)'`

**Cloud mode**: Anchors flush directly to the SWT3 clearing house via the
`Witness` class from `@tenova/swt3-ai`. Requires an API key and tenant ID.

## Silicon Coverage

| Vendor | Discovery Method | Accelerators |
|--------|-----------------|--------------|
| NVIDIA | `nvidia-smi` | A100, H100, H200, B200, etc. |
| Google | TPU metadata API | v2, v3, v4, v5e, v5p, Trillium |
| AMD | ROCm `rocm-smi` | MI250, MI300X, MI325X |
| AWS | Neuron `neuron-ls` | Trainium, Inferentia |
| Intel | Gaudi `hl-smi` | Gaudi 2, Gaudi 3 |
| Any | PCI bus scan | Fallback for unrecognized devices |

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `config.mode` | `local` | `local` (stdout) or `cloud` (clearing house) |
| `config.interval` | `3600` | Seconds between attestation cycles |
| `config.clearingLevel` | `1` | 0=analytics, 1=standard, 2=sensitive, 3=classified |
| `config.agentId` | auto | Agent identity tag (auto-generates from pod hostname) |
| `config.healthPort` | `9090` | Health endpoint port |
| `cloud.apiKey` | `""` | API key for clearing house (required in cloud mode) |
| `cloud.tenantId` | `""` | Tenant ID (required in cloud mode) |
| `cloud.signingKey` | `""` | HMAC-SHA256 signing key (optional) |
| `cloud.endpoint` | `https://sovereign.tenova.io` | Clearing house URL |
| `runtimeClassName` | `""` | Set to `nvidia` for full GPU discovery |
| `sysMount.enabled` | `true` | Mount /sys read-only for PCI fallback |

## Health Endpoint

```bash
kubectl port-forward ds/swt3-swt3-witness 9090:9090
curl http://localhost:9090/health
```

Returns:
```json
{
  "status": "ok",
  "version": "0.7.2",
  "mode": "local",
  "silicon_vendor": "nvidia",
  "topology": "single",
  "accelerator_count": 4,
  "gpu_count": 4
}
```

## Security

- Runs as non-root (UID 10001)
- Read-only root filesystem
- All capabilities dropped
- No privilege escalation
- `/sys` mounted read-only (for PCI discovery only)

## Container Image

```bash
docker pull ghcr.io/tenova-labs/swt3-witness:0.7.2
```

## License

Apache-2.0. Copyright 2026 Tenable Nova LLC.

Part of the [SWT3 AI Witness Protocol](https://swt3.ai/spec).
