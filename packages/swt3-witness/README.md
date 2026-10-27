# SWT3™ Witness Agent

Cross-silicon hardware attestation for Kubernetes AI infrastructure.

Runs as a **DaemonSet** -- one pod per node. Discovers accelerator hardware
(NVIDIA GPU, Google TPU, AMD MI, AWS Trainium/Inferentia, Intel Gaudi) and
mints AI-HW.1 Witness Anchors on a configurable interval.

> **Protocol Spec:** [swt3.ai/spec](https://swt3.ai/spec) | **Registry:** [swt3.ai/registry](https://swt3.ai/registry) | **Verify:** [swt3.ai/verify](https://swt3.ai/verify)

## What's New in v0.7.9

v0.7.9 is the ecosystem adapter release. Four new provider adapters (Groq, Together AI, DeepSeek, Azure OpenAI) and six witnessing guides bring the total adapter count to 47. Every major commercial inference provider now produces witness anchors in the same format -- one evidence stream regardless of which cloud your team chose.

New guides: [OpenAI GPT](https://sovereign.tenova.io/guides/openai-gpt-compliance-witnessing.html) | [Anthropic Claude](https://sovereign.tenova.io/guides/anthropic-claude-compliance-witnessing.html) | [Google Vertex/Gemini](https://sovereign.tenova.io/guides/google-vertex-gemini-compliance-witnessing.html) | [LangChain/LangGraph](https://sovereign.tenova.io/guides/langchain-langgraph-compliance-witnessing.html) | [DeepSeek](https://sovereign.tenova.io/guides/deepseek-gpai-compliance-witnessing.html) | [Groq](https://sovereign.tenova.io/guides/groq-compliance-witnessing.html)

**Why this matters for Kubernetes:** The witness agent DaemonSet collects anchors from all SDK-instrumented workloads across the cluster. With 47 adapters, pods running Groq for low-latency inference, Azure OpenAI for enterprise workloads, DeepSeek for cost-optimized batch jobs, and Together AI for open-weight models all produce anchors the agent collects, batches, and forwards -- zero provider-specific configuration. The `@tenova/swt3-mcp` MCP server (75 tools, 78 frameworks) can query anchors collected by the witness agent, giving MCP-connected AI assistants real-time visibility into cluster-wide AI governance posture.

v0.7.9 also aligns all MCP discovery metadata (`mcp.json`, `agent-card.json`, `llms.txt`, `server.json`) to report identical version numbers and counts. Agent discovery bots and MCP crawlers see consistent metadata everywhere.

### Updated Coverage

- 293 procedures across 10 namespaces
- 78 regulatory frameworks, 340 compliance guides, 47 adapters, 10 SDK languages

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

**Why this matters for the Witness Agent:** The Kubernetes witness agent collects anchors from workloads across the cluster. With 6 new adapters covering IBM watsonx, AWS Bedrock, AWS Strands, and Mistral, pods running any major cloud AI SDK now produce witness anchors that the agent can collect, batch, and forward without provider-specific configuration. v0.7.8 brings all SDKs back to version lockstep.

## What's New in v0.7.6

Five standards bodies converged on agent governance requirements in Q3-Q4 2026. v0.7.6 adds three procedures (delegation chain integrity, scope boundary attestation, agent interrupt witnessing) and aligns crosswalks to G7 AI-SBOM, DORA, Singapore Agentic MGF, and the upcoming NIST Agent Profile.

**Why this matters for Kubernetes:** Hardware attestation anchors (AI-HW.1) now combine with the new agent interrupt procedure (AI-SAFE.2) to provide infrastructure-to-agent evidence chains that include operational governance events. When a K8s operator kills an AI agent pod, AI-SAFE.2 records the interrupt with trigger source and state preservation status. G7 AI-SBOM crosswalk (50 elements, 7 clusters) maps supply chain transparency requirements relevant to containerized AI infrastructure. DORA crosswalk (20 mappings) brings EU operational resilience evidence to K8s-orchestrated fintech deployments.

### Updated Coverage

- 293 procedures across 10 namespaces
- 78 regulatory frameworks, 340 compliance guides
- [G7 AI-SBOM Crosswalk](https://sovereign.tenova.io/guides/g7-ai-sbom-minimum-elements-crosswalk.html) | [DORA + ECB Crosswalk](https://sovereign.tenova.io/guides/dora-ecb-ai-cyber-crosswalk.html)

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

Part of the [SWT3 AI Witness Protocol](https://swt3.ai/spec).

---
SWT3, swt3-ai, TeNova, Axiom Sovereign Engine, UCT, and Sovereign Score are trademarks of Tenable Nova LLC.
