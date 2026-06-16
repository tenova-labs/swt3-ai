Witness your AI. Prove it followed the rules. Cryptographic accountability for every inference, tool call, and resource access.

[![Gem Version](https://img.shields.io/gem/v/swt3-ai)](https://rubygems.org/gems/swt3-ai)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)

# swt3-ai

**SWT3 AI Witness SDK for Ruby**: mint, verify, and sign SWT3 witness anchors with cross-language parity. Zero external dependencies -- uses only `openssl` from the standard library.

GPAI transparency obligations are enforceable now. EU AI Act high-risk enforcement begins **December 2, 2027**. This SDK gives you the cryptographic primitives.

## What You Get

- **`Swt3Ai::Fingerprint.mint_fingerprint`** -- canonical SWT3 fingerprint from tenant, procedure, factors, and timestamp
- **`Swt3Ai::Signing.sign_payload`** -- HMAC-SHA256 signing with optional agent identity binding
- **`Swt3Ai::Fingerprint.sha256_truncated`** -- truncated SHA-256 hashing for prompts, responses, and model weights
- **Types** -- `WitnessPayload`, `WitnessReceipt`, `WitnessConfig` structs and `REVOCATION_REASONS` constants

All output is byte-identical to the Python, TypeScript, Rust, and C# SDKs. Verified by shared test vectors.

## Quick Start

```bash
gem install swt3-ai
```

Mint a fingerprint:

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

## Cross-Language Parity

All SWT3 SDKs produce identical fingerprints from the same inputs. A unified audit trail across your entire stack, verified by shared test vectors at build time.

| Language | Package | Registry |
|----------|---------|----------|
| Python | [swt3-ai](https://pypi.org/project/swt3-ai/) | PyPI |
| TypeScript | [@tenova/swt3-ai](https://www.npmjs.com/package/@tenova/swt3-ai) | npm |
| Rust | [swt3-ai](https://crates.io/crates/swt3-ai) | crates.io |
| C# / .NET | [swt3-ai](https://www.nuget.org/packages/swt3-ai) | NuGet |
| Ruby | swt3-ai (this package) | RubyGems |
| MCP Server | [@tenova/swt3-mcp](https://www.npmjs.com/package/@tenova/swt3-mcp) | npm + MCP Registry |

The Python and TypeScript SDKs include the full witness pipeline: transparent client wrapping, buffer management, clearing engine, adapter support (OpenAI, Anthropic, Bedrock, vLLM, Ollama, LangChain), trust mesh, policy-as-code, and Merkle accumulator. Use them for production AI witnessing. Use this Ruby gem for embedding fingerprint verification into Rails apps, Sidekiq workers, or Ruby-based tooling.

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
