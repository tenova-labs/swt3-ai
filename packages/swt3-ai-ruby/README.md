Add cryptographic compliance evidence to existing Ruby applications. Three lines of code. Zero external dependencies.

[![Gem Version](https://img.shields.io/gem/v/swt3-ai)](https://rubygems.org/gems/swt3-ai)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)

# swt3-ai

**SWT3 AI Witness SDK for Ruby**: mint, verify, and sign SWT3 witness anchors with cross-language parity. Uses only `openssl` from the standard library. No native extensions, no C bindings, no dependency risk.

Built for platform engineers who need to bolt compliance witnessing onto production Rails apps, Sidekiq workers, Grape APIs, or any Ruby service that touches AI. Your Python team trains the model; your Ruby infrastructure serves it, monitors it, and proves it followed the rules. When a model drifts at 2am, the anchor chain tells you which model version, which pipeline deployed it, and which policy approved it.

EU AI Act GPAI transparency obligations enforced since **August 2, 2026**. High-risk enforcement follows **December 2, 2027**. This SDK gives you the cryptographic primitives for both.

> **Protocol Spec:** [swt3.ai/spec](https://swt3.ai/spec) | **Registry:** [swt3.ai/registry](https://swt3.ai/registry) | **Verify:** [swt3.ai/verify](https://swt3.ai/verify)

## What's New in v0.7.4

NVIDIA shipped OpenShell to 120+ partners. Agent containment is now infrastructure. But containment without evidence is a black box -- an auditor cannot verify that a sandbox policy was enforced last Tuesday at 14:00 UTC by looking at enforcement logs alone. v0.7.4 adds runtime containment attestation (AI-SHELL.1), model distillation provenance (AI-DIST.1), MCP elicitation detection (AI-MCP.6), and incident lifecycle chains. Four governance gaps closed in one release.

**Why this matters for Ruby:** All three new procedure IDs (AI-SHELL.1, AI-DIST.1, AI-MCP.6) verify with the existing `mint_fingerprint` function. AI-SHELL.1 runtime containment attestation works with zero dependency changes -- Ruby API backends orchestrating containerized inference pipelines can attest containment policy enforcement with the same fingerprint output as every other SDK language.

### 3 New Procedures

- **AI-SHELL.1** (Runtime Containment Attestation): Records that a sandboxed runtime enforced its containment policy during a specific observation window. Duck-typed: works with OpenShell, gVisor, Kata, Firecracker, WASM. [NVIDIA OpenShell Crosswalk](https://sovereign.tenova.io/guides/nvidia-openshell-crosswalk.html)
- **AI-DIST.1** (Distillation Provenance): Records teacher-to-student model lineage, compression ratio, and knowledge transfer method.
- **AI-MCP.6** (Elicitation Detection): Records prompt injection attempts via MCP tool responses. OWASP MCP-06.

### Updated Coverage

- 278 procedures across 10 namespaces (was 284)
- 75 MCP tools (was 72)
- 277 compliance guides
- [NVIDIA OpenShell Crosswalk](https://sovereign.tenova.io/guides/nvidia-openshell-crosswalk.html) -- runtime containment evidence for OpenShell, gVisor, Kata, Firecracker
- All new anchor types verify with `Swt3.mint_fingerprint()` -- no library update required for verification

## What's New in v0.7.3

A2A (Google's Agent-to-Agent protocol) has 150+ supporting organizations, all three hyperscalers, and a v1.0 stable specification under Linux Foundation governance. It has zero built-in audit trail. MCP OAuth adoption sits at 8.5% with 30+ CVEs filed in 60 days. v0.7.3 makes SWT3 the evidence layer for both agent communication protocols with dedicated procedures, lifecycle-aware adapters, and a new crosswalk CLI command.

**Why this matters for Ruby:** Ruby API backends and Rails agent orchestrators gain A2A lifecycle attestation with the same factor semantics and fingerprint parity as every other SDK language.

### 4 New Procedures

- **AI-A2A.1** (Task Delegation Lifecycle): Records task state transitions (submitted/working/input_required/completed/failed/canceled/rejected) with delegation depth and latency.
- **AI-A2A.2** (Agent Card Discovery): Records agent discovery via well-known URLs, registries, or referrals, with verified credential count.
- **AI-A2A.3** (Context Chain Linking): Records contextId linkage across multi-agent delegation chains for forensic reconstruction.
- **AI-MCP.5** (OAuth Token Binding): Records 8 OAuth lifecycle events (discovery through revocation) with binding strength and scope governance.

### Updated Coverage

- 284 procedures across 10 namespaces (was 280/9)
- 72 MCP tools (was 68)
- A2A namespace added (10th namespace)
- `swt3 crosswalk <procedure>` CLI command for offline framework mapping lookup
- 269 compliance guides

## What's New in v0.7.2

Two gaps closed in one release: harness-layer governance and zero-code MCP compliance. v0.7.2 adds five new procedures for orchestration, context management, sandboxing, and eval gating -- the decisions AI harnesses make before inference that have no audit trail today. It also ships a Witness Middleware (`withSWT3(transport)`) in the companion MCP package that auto-mints AI-TOOL.1 anchors for every tool call flowing through any MCP server, with zero code changes to tool handlers.

**Why this matters for Ruby:** Rails dashboards and Sidekiq workers are where AI compliance data surfaces for human review. The five harness governance anchors (AI-ORCH.1/2, AI-CTX.1, AI-SAND.1, AI-GATE.1) are structurally identical to inference anchors -- same `mint_fingerprint` verification, same `WitnessPayload` structure. When your Python or TypeScript harness records which agents it delegated to, how much context was truncated, and whether the eval gate passed, your Ruby reporting layer processes those anchors without any gem changes. The Witness Middleware means every MCP server in your stack gains cryptographic attestation by wrapping its transport -- your Ruby dashboard displays the evidence automatically.

### 5 New Procedures

- **AI-ORCH.1** (Orchestration Topology): Records routing pattern (parallel/sequential/hierarchical), agent count, dependency depth.
- **AI-ORCH.2** (Agent Handoff): Records delegator-to-delegate identity link with permission delta direction.
- **AI-CTX.1** (Context Window Management): Records token count before/after eviction and the method used.
- **AI-SAND.1** (Sandbox Enforcement): Records tools declared vs. invoked and violation count.
- **AI-GATE.1** (Eval Gate Decision): Records eval pass/fail counts with auto-computed gate score.

### Updated Coverage

- 280 procedures across 77 namespaces (was 275/77)
- 68 MCP tools (was 63)
- 10 SDK languages with byte-identical output
- 77 framework crosswalks, 265 compliance guides
- ~3,000 tests passing across 10 languages

## What's New in v0.7.1

MCP security is under fire. OWASP published the MCP Top 10 in 2026 -- 30-82% of MCP servers are vulnerable to tool poisoning, insufficient authentication, and shadow server proliferation. v0.7.1 adds three new procedures (AI-MCP.2, AI-MCP.3, AI-MCP.4) that close the remaining OWASP gaps. SWT3 is now the first protocol to cover all 10 OWASP MCP risks with cryptographic evidence. Every new anchor type verifies with the existing `Swt3Ai::Fingerprint.mint_fingerprint` method -- no gem update required.

**Why this matters for Ruby:** Rails dashboards displaying compliance posture and Sidekiq workers processing witness data will encounter the new MCP security anchors (tool integrity, server auth, server discovery) as your Python and TypeScript pipelines adopt them. Same `mint_fingerprint` verification, same `WitnessPayload` structure -- no gem changes.

### 3 New Procedures

- **AI-MCP.2** (Tool Integrity Attestation): Detects tool schema drift between connect and invoke. OWASP MCP-03.
- **AI-MCP.3** (Server Auth Attestation): Records auth method and verification. No auth = FAIL = IA-9 finding. OWASP MCP-07.
- **AI-MCP.4** (Server Discovery Attestation): Shadow server detection via allowlist check. OWASP MCP-09.

## What's New in v0.7.0

AI does not run in a vacuum. It authenticates with service accounts, runs on hardware with supply chains, and consumes enough electricity to reshape power grids. v0.7.0 extends SWT3 down the full AI infrastructure stack with 22 new procedures across three families: credential governance (NHI), hardware supply chains (HBOM/DPP), and energy management (ADR). Every new anchor type verifies with the existing `Swt3Ai::Fingerprint.mint_fingerprint` method -- no gem update required.

**Why this matters for Ruby:** Rails dashboards and Sidekiq workers are where AI data flows through enterprise systems. These new procedure families mean your Ruby monitoring layer can process credential rotation anchors, hardware inventory attestations, and demand response settlements alongside inference anchors -- same verifiable fingerprint structure, same verification call, new evidence categories. When your Python team witnesses service account rotation and your Ruby dashboard displays it, the fingerprint math is identical.

### 22 New Procedures

**NHI (6):** Credential scope, lifecycle, privilege changes, rotation, delegation, revocation. **HBOM/DPP (10):** Hardware inventory, component lifecycle, thermal monitoring, water, PUE, supply chain provenance, battery health, charge cycles, degradation, end-of-life. **ADR (6):** Demand response events, baseline, curtailment, settlement, carbon credits, grid signals.

- 266 procedures across 75 namespaces (was 118/64)
- 59 MCP tools (was 37)
- 10 SDK languages with byte-identical output
- 36 framework crosswalks, 237 compliance guides
- ~2,950 tests passing across 5 languages

## What's New in v0.6.6

Supply chain accountability. Four new procedures, a CI/CD gate action, and OTel GenAI conventions across the ecosystem. Every improvement flows through to Ruby because fingerprints are identical across all 10 languages.

## What's New in v0.6.5

Scale governance. The protocol grew features that matter at GPAI scale, and every improvement flows through to Ruby because fingerprints are identical across all 10 languages.

### Probabilistic Witnessing (Python + TypeScript)

**What it does:** A new `sampling_rate` parameter (0.0-1.0) lets the full-pipeline SDKs witness a statistical sample of inferences instead of every single one. Non-witnessed inferences are counted and summarized in periodic AI-SAMPLE.1 anchors on flush. Per-procedure overrides keep safety-critical procedures at 100% while sampling high-volume inference calls.

**Why it matters for Ruby:** A GPAI provider processing a billion inferences per day cannot witness every single one. When your Python inference pipeline samples at 1% and your Ruby Sidekiq workers process the results, both sides produce anchors with the same fingerprint formula. The AI-SAMPLE.1 summary anchors are verifiable with this gem's `mint_fingerprint` -- same formula, same output. Your Ruby service can independently verify that the sampling was deterministic and reproducible.

### Governance Effectiveness Metadata (Python + TypeScript)

**What it does:** Governance witness methods now accept a `governance_metadata` dictionary recording review duration and participant count. Assessors use this to distinguish substantive governance from governance theater.

**Why it matters for Ruby:** If your Ruby service ingests governance anchors from the Python pipeline, the metadata is in the `ai_context` JSONB field at clearing levels 0-1. Your Rails dashboards and Sidekiq processors can read and display these fields without any gem changes. A 3-minute review by one person produces different metadata than a 90-minute review by five -- and your Ruby reporting layer can surface that difference.

### Go SDK (v0.1.0)

The 10th language in the SWT3 ecosystem. Core primitives: fingerprint minting, HMAC-SHA256 signing, lifecycle chain IDs. Zero dependencies. All 65 test vectors pass. Go is the dominant language for Kubernetes operators, API gateways, and inference orchestrators -- the infrastructure layer that sits between your Ruby application and the model. Same fingerprints, same signing, same audit trail.

### MCP Witness Middleware

`withSWT3(transport)` wraps any MCP transport to auto-witness every tool call. Zero code changes to tool handlers. If your Ruby service talks to MCP-enabled agents, every tool call they make now has a cryptographic anchor that your gem can independently verify.

### Updated Coverage

- 114 procedures across 62 namespaces (AI-SAMPLE.1 added)
- 36 framework crosswalks
- 215 compliance guides at [sovereign.tenova.io/guides](https://sovereign.tenova.io/guides/index.html)
- 2,515 tests passing across 5 languages

### v0.6.4

Version alignment across 10 SDKs. Pre-inference gate and chain reconstruction added in Python and TypeScript. 214 compliance guides.

## What You Get

| Method | What It Does | Use Case |
|--------|-------------|----------|
| `Swt3Ai::Fingerprint.mint_fingerprint` | Canonical SWT3 fingerprint from tenant, procedure, factors, and timestamp | Every inference, tool call, or decision point |
| `Swt3Ai::Signing.sign_payload` | HMAC-SHA256 signing with optional agent identity binding | Non-repudiation for regulated systems |
| `Swt3Ai::Fingerprint.sha256_truncated` | Truncated SHA-256 hash for prompts, responses, and model weights | Hash locally, transmit only the proof |
| `WitnessPayload` / `WitnessReceipt` | Typed structs for witness data | Serialize to JSON for API calls or database storage |
| `REVOCATION_REASONS` | 7 standard reason codes for anchor revocation | Model recall, policy violation, consent withdrawal |

All output is byte-identical to the Python, TypeScript, Swift, Rust, C#, Go, Kotlin, and MCP SDKs. 10 languages, one audit trail. Verified by shared test vectors.

## Quick Start

```bash
gem install swt3-ai
```

Or add to your Gemfile:

```ruby
gem "swt3-ai", "~> 0.6"
```

### Add witnessing to a Rails controller

```ruby
require "swt3_ai"

class InferencesController < ApplicationController
  def create
    result = AiService.call(params[:prompt])

    # Witness the inference (3 lines)
    fp = Swt3Ai::Fingerprint.mint_fingerprint(
      "MY_TENANT", "AI-INF.1",
      1.0, 1.0, 0.0,
      (Time.now.to_f * 1000).to_i
    )
    sig = Swt3Ai::Signing.sign_payload(ENV["SWT3_SIGNING_KEY"], fp, "rails-api")

    render json: { result: result, fingerprint: fp, signature: sig }
  end
end
```

### Add witnessing to a Sidekiq worker

```ruby
class FraudScoringWorker
  include Sidekiq::Job

  def perform(transaction_id)
    score = FraudModel.score(transaction_id)

    fp = Swt3Ai::Fingerprint.mint_fingerprint(
      "MY_TENANT", "AI-FAIR.1",
      score, 0.85, 0.0,
      (Time.now.to_f * 1000).to_i
    )
    WitnessLog.create!(transaction_id: transaction_id, fingerprint: fp)
  end
end
```

### Zero-code Rack middleware

Witness every request that hits an AI endpoint without changing application code. Drop this into `config.ru` or your Rails initializer.

```ruby
# config/initializers/swt3_middleware.rb
class Swt3WitnessMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    status, headers, response = @app.call(env)

    if env["PATH_INFO"].start_with?("/api/v1/ai/")
      fp = Swt3Ai::Fingerprint.mint_fingerprint(
        ENV["SWT3_TENANT"], "AI-TOOL.1",
        1.0, status == 200 ? 1.0 : 0.0, 0.0,
        (Time.now.to_f * 1000).to_i
      )
      Rails.logger.info("[SWT3] #{env['PATH_INFO']} -> #{fp}")
    end

    [status, headers, response]
  end
end

Rails.application.config.middleware.use Swt3WitnessMiddleware
```

Every request matching `/api/v1/ai/*` gets a witness anchor logged. No controller changes. Works with any Rack-compatible framework (Rails, Sinatra, Grape, Hanami, Roda).

### Core primitives

```ruby
require "swt3_ai"

# Hash prompt and response locally (raw text never leaves your machine)
prompt_hash = Swt3Ai::Fingerprint.sha256_truncated("Summarize this contract...", 16)
response_hash = Swt3Ai::Fingerprint.sha256_truncated("The contract states...", 16)

# Mint a fingerprint from the canonical formula
fp = Swt3Ai::Fingerprint.mint_fingerprint("MY_TENANT", "AI-INF.1", 1.0, 1.0, 0.0, 1774800000000)

# Sign for non-repudiation (optional)
sig = Swt3Ai::Signing.sign_payload("swt3_sk_my_key", fp, "fraud-detector-prod")
```

## Verify Any Anchor From Your Terminal

```bash
echo -n "WITNESS:DEMO_TENANT:AI-INF.1:1:1:0:1774800000000" | sha256sum | cut -c1-12
# Produces a 12-character fingerprint. Compare it to the anchor. If it matches, the anchor is real.
```

No SDK needed. Works on any machine, any language.

### What an anchor looks like

A witness anchor is a single deterministic string. Grep it, index it, parse it, write OPA rules against it.

```
SWT3-E-AWS-AI-TOOL1-PASS-1723891200-a4f8c92d0e17
|    |  |   |       |    |          |
|    |  |   |       |    |          +-- SHA-256 fingerprint (12 hex)
|    |  |   |       |    +------------ epoch timestamp
|    |  |   |       +----------------- verdict (PASS / FAIL)
|    |  |   +------------------------- procedure (AI-TOOL.1)
|    |  +----------------------------- cloud provider
|    +-------------------------------- deployment tier (E = Enclave)
+------------------------------------ protocol prefix
```

## CI/CD Integration

SWT3 fits into your existing pipeline as a verification stage. Gate deployments on witness coverage the same way you gate on test coverage.

```yaml
# .github/workflows/deploy.yml
- name: Verify Witness Anchor
  run: |
    # $SWT3_ANCHOR is set by your app's witness output or a CI artifact
    FINGERPRINT=$(echo -n "$SWT3_ANCHOR" | cut -d'-' -f8)
    curl -sf "https://sovereign.tenova.io/api/v1/verify?fingerprint=$FINGERPRINT" \
      | jq -e '.verified == true' || exit 1
    # No API key. Public endpoint. Just math.
```

If you already sign containers with cosign and generate SBOMs with Syft or Trivy, SWT3 covers the gap those tools don't reach: what your AI decided after you deployed it. Your attestation chain extends from source commit to container image to runtime decision.

## Cross-Language Parity

All SWT3 SDKs produce identical fingerprints from the same inputs. A unified audit trail across your entire stack, verified by shared test vectors at build time.

| Language | Package | Registry |
|----------|---------|----------|
| Python | [swt3-ai](https://pypi.org/project/swt3-ai/) | PyPI |
| TypeScript | [@tenova/swt3-ai](https://www.npmjs.com/package/@tenova/swt3-ai) | npm |
| Swift | [swt3-ai](https://github.com/tenova-labs/swt3-ai-swift) | Swift Package Index |
| Rust | [swt3-ai](https://crates.io/crates/swt3-ai) | crates.io |
| C# / .NET | [swt3-ai](https://www.nuget.org/packages/swt3-ai) | NuGet |
| Ruby | swt3-ai (this package) | RubyGems |
| Go | [swt3-ai](https://github.com/tenova-labs/swt3-ai-go) | Go modules |
| MCP Server | [@tenova/swt3-mcp](https://www.npmjs.com/package/@tenova/swt3-mcp) | npm + MCP Registry |
| K8s Witness Agent | [swt3-witness](https://github.com/tenova-labs/swt3-ai/tree/main/packages/swt3-witness) | GHCR + Helm |

### When to use which SDK

| Your Stack | SDK | What You Get |
|-----------|-----|-------------|
| Python ML pipeline | [swt3-ai (PyPI)](https://pypi.org/project/swt3-ai/) | Full witness pipeline: `wrap(client)`, buffer management, clearing engine, 21 adapters (OpenAI, Anthropic, Bedrock, vLLM, Ollama, LiteLLM, LangChain, CrewAI, etc.) |
| TypeScript/Node API | [@tenova/swt3-ai (npm)](https://www.npmjs.com/package/@tenova/swt3-ai) | ES6 Proxy wrapping, streaming support, Vercel AI SDK adapter, OTel export |
| Rails, Sidekiq, Grape, Hanami | **swt3-ai (this gem)** | Fingerprint, signing, and verification primitives. Embed witnessing into controllers, workers, middleware, or rake tasks |
| MCP-enabled agents | [@tenova/swt3-mcp](https://www.npmjs.com/package/@tenova/swt3-mcp) | 37 MCP tools, transport middleware for zero-code witnessing |

Your Python team trains the model and wraps inference with the full pipeline. Your Ruby infrastructure witnesses every downstream decision, API call, and background job that touches the model's output. Same fingerprints, same anchors, same audit trail.

## Regulatory Coverage

The SWT3 AI Witnessing Profile maps to:

- **EU AI Act**: Articles 9, 10, 12, 13, 14, 53, 72
- **NIST AI RMF**: GOVERN, MAP, MEASURE, MANAGE functions
- **ISO 42001**: Annex A AI management controls
- **NIST 800-53**: SI-7 (integrity), AU-2/AU-3 (audit), AC controls
- **SR 11-7**: Model risk management (financial services)

## Privacy

Your prompts and responses **never leave your infrastructure**. The SDK computes SHA-256 hashes locally and transmits only irreversible hashes and numeric factors. At Clearing Level 3, even the model name is hashed. The witness endpoint is a blind registrar: it stores cryptographic proofs, not your data.

## Links

- **Website**: [tenova.io](https://tenova.io)
- **Protocol Spec**: [SWT3 Protocol Specification](https://swt3.ai/spec)
- **Live Demo**: [sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public](https://sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public)

---

*SWT3: Sovereign Witness Traceability. We don't run your models. We witness them.*

SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC. Patent pending. Apache 2.0 licensed.

This project is not affiliated with, endorsed by, or sponsored by any third-party AI provider. All third-party trademarks are the property of their respective owners. Use of these names is for identification and interoperability purposes only.
