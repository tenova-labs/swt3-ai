Add cryptographic compliance evidence to existing Ruby applications. Three lines of code. Zero external dependencies.

[![Gem Version](https://img.shields.io/gem/v/swt3-ai)](https://rubygems.org/gems/swt3-ai)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)

# swt3-ai

**SWT3 AI Witness SDK for Ruby**: mint, verify, and sign SWT3 witness anchors with cross-language parity. Uses only `openssl` from the standard library. No native extensions, no C bindings, no dependency risk.

Built for platform engineers who need to bolt compliance witnessing onto production Rails apps, Sidekiq workers, Grape APIs, or any Ruby service that touches AI. Your Python team trains the model; your Ruby infrastructure serves it, monitors it, and proves it followed the rules. When a model drifts at 2am, the anchor chain tells you which model version, which pipeline deployed it, and which policy approved it.

EU AI Act GPAI transparency obligations enforced since **August 2, 2026**. High-risk enforcement follows **December 2, 2027**. This SDK gives you the cryptographic primitives for both.

## What's New in v0.6.6

Supply chain accountability. Four new procedures, a CI/CD gate action, and OTel GenAI conventions across the ecosystem. Every improvement flows through to Ruby because fingerprints are identical across all 10 languages.

### 4 New Procedures

**AI-PROV.1 (Model Provenance Chain):** Records model lineage -- base model, training pipeline, fine-tuning ancestry. The G7 Hiroshima AI SBOM framework requires provenance documentation. A `parent_model_fingerprint` parameter on model weight/adapter/quantization methods links derivative models to their ancestors. Provenance anchors verify with `mint_fingerprint` like any other anchor.

**AI-DEL.2 (Delegation Boundary):** Records what an agent is NOT permitted to do -- blocked tools, restricted scopes, escalation triggers. EU AI Act Art. 14 requires documented AI system limitations. Where AI-DEL.1 tracks permissions, AI-DEL.2 tracks constraints.

**AI-DENSITY.1 (Anchor Density):** Records the ratio of witnessed events to total events over a time window. Catches the slow coverage drift from 100% to 2% that nobody notices until the audit. A DensityEnforcer class in Python and TypeScript auto-fires density anchors when coverage drops.

**AI-MCP.1 (MCP Security Posture):** Evaluates 8 security properties of an MCP server connection. Records checks passed vs. total -- never which specific checks failed. NSA and CISA flagged 200,000+ vulnerable MCP deployments in 2026. This creates evidence that security was evaluated at connection time without becoming an attack map.

**Why it matters for Ruby:** All four procedures produce anchors with the same fingerprint formula. Your Ruby code can verify any of these new anchor types with the existing `Swt3Ai::Fingerprint.mint_fingerprint` method -- no gem update required for verification. Your Rails dashboards and Sidekiq workers can process provenance and density anchors from the Python pipeline without any changes. When your Ruby monitoring layer ingests anchor data, the new procedure types are just more rows with the same verifiable fingerprint structure.

### GitHub Action

`tenova-labs/swt3-gate-action@v1` evaluates `.swt3-gate.yml` in CI/CD. Fails the build when coverage drops. Works with any language -- the gate checks anchors on the server, not the SDK in your repo. Your Gemfile-driven CI pipeline can enforce compliance gates without installing any additional gems.

### OTel GenAI Conventions (Python + TypeScript)

The OpenTelemetry exporters now emit `gen_ai.system`, `gen_ai.request.model`, and token usage attributes following the OTel GenAI semantic conventions. If your Ruby service consumes OTel spans from the Python or TypeScript witness pipeline, these new attributes appear automatically.

### Updated Coverage

- 118 procedures across 64 namespaces (+AI-PROV.1, AI-DEL.2, AI-DENSITY.1, AI-MCP.1)
- 37 MCP tools (+witness_delegation_boundary, witness_anchor_density, witness_mcp_security, witness_model_provenance)
- 10 SDK languages with byte-identical output
- 36 framework crosswalks, 222 compliance guides
- 2,825 tests passing across 5 languages

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
- **Protocol Spec**: [SWT3-SPEC-v1.0](https://github.com/tenova-labs/swt3-ai)
- **Live Demo**: [sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public](https://sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public)

---

*SWT3: Sovereign Witness Traceability. We don't run your models. We witness them.*

SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC. Patent pending. Apache 2.0 licensed.

This project is not affiliated with, endorsed by, or sponsored by any third-party AI provider. All third-party trademarks are the property of their respective owners. Use of these names is for identification and interoperability purposes only.
