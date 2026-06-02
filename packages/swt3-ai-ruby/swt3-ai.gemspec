Gem::Specification.new do |s|
  s.name        = "swt3-ai"
  s.version     = "0.5.4"
  s.summary     = "SWT3 AI Witness SDK: cryptographic attestation for AI inference. 65 procedures, 41 namespaces, 5 languages, 14 profiles."
  s.description = "Mint, verify, and sign SWT3 witness anchors for AI compliance. " \
                  "EU AI Act, NIST AI RMF, CMMC, SR 11-7. " \
                  "Cross-language parity with Python and TypeScript SDKs. " \
                  "Zero external dependencies."
  s.authors     = ["TeNova Labs"]
  s.email       = ["engineering@tenovaai.com"]
  s.homepage    = "https://tenova.io"
  s.license     = "Apache-2.0"
  s.files       = Dir["lib/**/*.rb"] + ["README.md", "LICENSE"]
  s.metadata    = {
    "source_code_uri" => "https://github.com/tenova-labs/swt3-ai",
    "homepage_uri" => "https://tenova.io",
    "documentation_uri" => "https://sovereign.tenova.io/docs/",
    "changelog_uri" => "https://sovereign.tenova.io/guides/nsa-mcp-security-mapping.html",
    "keywords" => "ai,compliance,witness,swt3,eu-ai-act,nist-ai-rmf,ai-governance,ai-audit,ai-safety,agentic-ai,guardrails,model-governance,cryptographic-attestation,cmmc,sr-11-7"
  }
  s.required_ruby_version = ">= 2.7.0"
end
