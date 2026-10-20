# SWT3 Witness Agent

Cross-silicon hardware attestation for Kubernetes AI infrastructure.

Runs as a **DaemonSet** -- one pod per node. Discovers accelerator hardware
(NVIDIA GPU, Google TPU, AMD MI, AWS Trainium/Inferentia, Intel Gaudi) and
mints AI-HW.1 Witness Anchors on a configurable interval.

## What's New in v0.7.8

Six new adapters unify evidence collection across IBM watsonx, AWS Bedrock, AWS Strands, and Mistral AI. Organizations running models across multiple cloud providers no longer need to reconcile separate audit trails -- every inference and policy decision produces a witness anchor in the same format regardless of provider.

New adapters: IBM Granite (`wrap_granite`), AWS Bedrock Guardrails (`wrap_bedrock_guardrails`), AWS Strands (`wrap_strands`), Mistral AI (`wrap_mistral`), NVIDIA NemoClaw, and NVIDIA ROSClaw.

| Provider | Adapter | What it witnesses | Why it matters |
|----------|---------|-------------------|----------------|
| IBM watsonx.ai | `wrap_granite` | `generate()`, `generate_text()`, streaming | Enterprise AI on IBM's regulated cloud -- banks and insurers run Granite for document processing |
| AWS Bedrock Guardrails | `wrap_bedrock_guardrails` | `apply_guardrail()` policy decisions (AI-GRD.1) | Content filtering audit trail -- proves guardrails were active, not just configured |
| AWS Strands | `wrap_strands` | Agent callable invocations (AI-INF.1) | AWS agent orchestration framework -- 120+ enterprise customers with zero built-in audit |
| Mistral AI | `wrap_mistral` | `chat.complete()`, `chat.stream()`, async | European sovereign AI -- Mistral runs on EU infrastructure, GPAI compliance required since Aug 2 |
| NVIDIA NemoClaw | `NemoClawWitness` | Policy engine decisions (AI-GRD.1) | Hardware-level AI governance -- NeMo Guardrails policy decisions witnessed independently |
| NVIDIA ROSClaw | `ROSClawWitness` | ROS 2 robotics audit log events | Robotics compliance -- EU Machinery Regulation (Jan 2027) requires AI decision evidence in safety-critical robots |

Guides: [IBM Granite Adapter](https://sovereign.tenova.io/guides/ibm-granite-watsonx-crosswalk.html) | [AWS Bedrock Guardrails](https://sovereign.tenova.io/guides/aws-bedrock-guardrails-crosswalk.html) | [Mistral AI Adapter](https://sovereign.tenova.io/guides/mistral-ai-governance-crosswalk.html) | [NVIDIA NemoClaw](https://sovereign.tenova.io/guides/nvidia-nemoclaw-governance-crosswalk.html)

**Why this matters:** The Helm chart deploys the witness agent that collects anchors from all SDK-instrumented workloads. v0.7.8 adds adapter coverage for IBM watsonx, AWS Bedrock (including Guardrails policy decisions), AWS Strands agent orchestration, and Mistral AI. No chart configuration changes required -- new adapters work automatically with existing witness agent deployments.

## Quick Start

```bash
# Local mode -- anchors emit as structured JSON to stdout
helm install swt3 oci://ghcr.io/tenova-labs/charts/swt3-witness --version 0.7.8

# Cloud mode -- anchors flush to the SWT3 clearing house
helm install swt3 oci://ghcr.io/tenova-labs/charts/swt3-witness --version 0.7.8 \
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
  "version": "0.7.8",
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
docker pull ghcr.io/tenova-labs/swt3-witness:0.7.8
```

## License

Apache-2.0. Copyright 2026 Tenable Nova LLC.

Part of the [SWT3 AI Witness Protocol](https://github.com/tenova-labs/swt3-ai).
