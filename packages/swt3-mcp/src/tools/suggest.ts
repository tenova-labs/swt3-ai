/**
 * SWT3 MCP Server: suggest_procedures tool.
 *
 * Advisory-only procedure suggestions based on context keywords.
 * No network call. Never enforced. The agent decides what to witness.
 */

interface SuggestArgs {
  context: string;
  model_id?: string;
  data_classification?: string;
  tools_used?: string[];
}

interface Suggestion {
  procedure: string;
  title: string;
  reason: string;
  priority: number; // 1=highest
}

const KEYWORD_MAP: Array<{
  keywords: string[];
  procedure: string;
  title: string;
  reason: string;
  priority: number;
}> = [
  {
    keywords: ["infer", "generat", "complet", "chat", "prompt", "response", "llm", "model", "gpt", "claude", "llama", "mistral"],
    procedure: "AI-INF.1",
    title: "Inference Provenance",
    reason: "AI model inference detected -- witness the model, prompt hash, and response hash",
    priority: 1,
  },
  {
    keywords: ["guard", "safety", "filter", "modera", "content filter", "refusal", "block", "harm"],
    procedure: "AI-GRD.1",
    title: "Guardrail Attestation",
    reason: "Safety or content filtering context detected -- witness guardrail state",
    priority: 2,
  },
  {
    keywords: ["agent", "identity", "who am i", "multi-agent", "orchestrat", "delegat"],
    procedure: "AI-ID.1",
    title: "Agent Identity",
    reason: "Agent identity or multi-agent context detected -- witness agent_id",
    priority: 3,
  },
  {
    keywords: ["access", "database", "api call", "fetch", "read", "write", "permiss", "authoriz", "pii", "credential"],
    procedure: "AI-ACC.1",
    title: "Access Control Witnessing",
    reason: "Data or resource access detected -- witness the authorization decision",
    priority: 2,
  },
  {
    keywords: ["tool", "function call", "plugin", "action", "execut", "run command", "code interpret"],
    procedure: "AI-TOOL.1",
    title: "Tool Use Witnessing",
    reason: "Tool or function call detected -- witness the tool invocation",
    priority: 2,
  },
  {
    keywords: ["revok", "recall", "retract", "correct", "error", "mistake", "withdraw", "undo"],
    procedure: "AI-REV.1",
    title: "Anchor Revocation",
    reason: "Correction or recall context detected -- consider revoking a prior anchor",
    priority: 3,
  },
  {
    keywords: ["handoff", "transfer", "pass to", "chain", "pipeline", "next agent", "downstream"],
    procedure: "AI-CHAIN.1",
    title: "Chain-of-Custody Handoff",
    reason: "Agent handoff or pipeline transfer detected -- witness custody transfer",
    priority: 3,
  },
  {
    keywords: ["rag", "retriev", "context", "document", "chunk", "vector", "embed", "search result", "knowledge base"],
    procedure: "AI-RAG.1",
    title: "RAG Context Provenance",
    reason: "Retrieval-augmented generation detected -- witness source documents and relevance",
    priority: 2,
  },
  {
    keywords: ["train", "fine-tun", "dataset", "epoch", "checkpoint", "weight", "lora", "adapter", "unsloth"],
    procedure: "AI-DATA.3",
    title: "Training Data Statistics",
    reason: "Training or fine-tuning context detected -- witness dataset properties",
    priority: 3,
  },
  {
    keywords: ["bias", "fairness", "disparity", "protected", "demographic", "equit", "discriminat"],
    procedure: "AI-FAIR.3",
    title: "Bias Assessment",
    reason: "Fairness or bias evaluation detected -- witness assessment results",
    priority: 3,
  },
  {
    keywords: ["model card", "registry", "catalog", "model version", "deploy model", "serve model"],
    procedure: "AI-MDL.1",
    title: "Model Hash Integrity",
    reason: "Model management context detected -- witness model identity and hash",
    priority: 2,
  },
  {
    keywords: ["violat", "policy breach", "forbidden", "prohibited", "restrict", "banned", "illegal"],
    procedure: "AI-VIO.1",
    title: "Policy Violation",
    reason: "Policy violation or prohibited action detected -- witness with severity classification",
    priority: 1,
  },
  {
    keywords: ["skill", "capability", "manifest", "plugin list", "tool list", "function list"],
    procedure: "AI-SKILL.1",
    title: "Skill Manifest",
    reason: "Agent capability or skill registration detected -- witness the manifest",
    priority: 3,
  },
  {
    keywords: ["thermal", "temperature", "cool", "overheat", "power draw", "watt", "energy", "node health", "residential", "edge node"],
    procedure: "AI-ENV.1",
    title: "Environmental Integrity",
    reason: "Hardware environment or node health context detected -- witness thermal and power state",
    priority: 3,
  },
  {
    keywords: ["watermark", "c2pa", "provenance", "label", "mark", "content id", "manifest", "steganograph", "ai-generated"],
    procedure: "AI-MARK.1",
    title: "Content Provenance Marking",
    reason: "Content marking or labelling detected -- witness the provenance metadata",
    priority: 2,
  },
  {
    keywords: ["baseline", "behavior", "envelope", "anomal", "drift detect", "normal behav", "deviation", "behavioral"],
    procedure: "AI-BASE.1",
    title: "Agent Behavioral Baseline",
    reason: "Agent behavior monitoring detected -- witness the baseline comparison",
    priority: 2,
  },
  {
    keywords: ["license", "licens", "openmdw", "spdx", "copyright", "copyleft", "permissive", "proprietary", "open source", "oss"],
    procedure: "AI-LIC.1",
    title: "License Provenance",
    reason: "License or open-source compliance context detected -- witness the license composition",
    priority: 2,
  },
  {
    keywords: ["sbom", "bom", "bill of material", "component", "inventory", "g7", "cisa", "supply chain", "cyclonedx", "spdx"],
    procedure: "AI-SBOM.1",
    title: "AI Bill of Materials",
    reason: "AI component inventory detected -- witness the SBOM snapshot for supply chain transparency",
    priority: 1,
  },
  {
    keywords: ["red team", "adversarial", "attack", "jailbreak", "prompt inject", "pentest", "security test", "vulnerability", "exploit", "owasp"],
    procedure: "AI-REDTEAM.1",
    title: "Adversarial Test Campaign",
    reason: "Red team or adversarial testing detected -- witness the campaign results",
    priority: 2,
  },
  {
    keywords: ["consent", "gdpr", "legal basis", "data subject", "withdrawal", "opt-in", "opt-out", "privacy", "dpia", "lawful"],
    procedure: "AI-CONSENT.1",
    title: "Data Subject Consent",
    reason: "Consent or legal basis context detected -- witness the data subject authorization",
    priority: 2,
  },
  {
    keywords: ["delegation", "multi-agent", "sub-agent", "orchestrat", "spawn", "delegate", "child agent", "parent agent", "permission"],
    procedure: "AI-MULTI.1",
    title: "Multi-Agent Delegation",
    reason: "Agent delegation or multi-agent orchestration detected -- witness the permission envelope",
    priority: 2,
  },
  {
    keywords: ["drift", "data drift", "concept drift", "prediction drift", "distribution shift", "model decay", "degradation"],
    procedure: "AI-DRIFT.1",
    title: "Model Drift Detection",
    reason: "Model or data drift detected -- witness the drift event for continuous risk estimation",
    priority: 2,
  },
  {
    keywords: ["audit", "log integrity", "tamper", "record keeping", "traceability", "log verification"],
    procedure: "AI-AUDIT.1",
    title: "Audit Log Integrity",
    reason: "Audit log verification detected -- witness the integrity check result",
    priority: 2,
  },
  {
    keywords: ["incident", "serious incident", "breach", "safety event", "harm", "malfunction"],
    procedure: "AI-INCIDENT.1",
    title: "Incident Reporting",
    reason: "Incident or safety event detected -- witness the incident report",
    priority: 1,
  },
  {
    keywords: ["performance", "accuracy", "precision", "recall", "f1", "benchmark", "evaluation", "metric"],
    procedure: "AI-PERF.1",
    title: "Performance Metrics",
    reason: "Model performance evaluation detected -- witness the benchmark results",
    priority: 2,
  },
  {
    keywords: ["robust", "perturbation", "noise", "corruption", "edge case", "fault tolerance", "resilience"],
    procedure: "AI-ROBUST.1",
    title: "Robustness Testing",
    reason: "Robustness or perturbation testing detected -- witness the resilience results",
    priority: 2,
  },
  {
    keywords: ["cybersecurity", "security assessment", "nist csf", "iso 27001", "penetration", "vulnerability scan"],
    procedure: "AI-CYBER.1",
    title: "Cybersecurity Attestation",
    reason: "Cybersecurity assessment detected -- witness the security posture",
    priority: 2,
  },
  {
    keywords: ["transparency", "disclosure", "inform", "notify user", "ai usage", "automated processing"],
    procedure: "AI-TRANS.1",
    title: "Transparency Disclosure",
    reason: "AI usage disclosure detected -- witness the transparency notification",
    priority: 2,
  },
  {
    keywords: ["watermark verify", "watermark detect", "c2pa verify", "synthid", "provenance check", "marking survived"],
    procedure: "AI-WATERMARK.1",
    title: "Watermark Verification",
    reason: "Content watermark verification detected -- witness whether marking survived",
    priority: 2,
  },
  {
    keywords: ["dpia", "impact assessment", "data protection impact", "privacy impact", "risk assessment", "gdpr 35"],
    procedure: "AI-DPIA.1",
    title: "Data Protection Impact Assessment",
    reason: "DPIA or privacy impact assessment detected -- witness the assessment results",
    priority: 2,
  },
  {
    keywords: ["automated decision", "algorithmic decision", "gdpr 22", "credit score", "employment decision", "profiling"],
    procedure: "AI-AUTO.1",
    title: "Automated Decision Notification",
    reason: "Automated decision with legal effects detected -- witness the notification",
    priority: 1,
  },
  {
    keywords: ["dual use", "dual-use", "foundation model", "systemic risk", "eo 14110", "high impact"],
    procedure: "AI-DUALUSE.1",
    title: "Dual-Use Model Classification",
    reason: "Dual-use or high-impact model detected -- witness the classification and reporting status",
    priority: 1,
  },
  {
    keywords: ["supply chain", "supplier", "third party", "vendor risk", "dependency risk", "upstream"],
    procedure: "AI-SUPPLY.1",
    title: "Supply Chain Risk",
    reason: "Supply chain or third-party risk assessment detected -- witness the supplier compliance",
    priority: 2,
  },
  {
    keywords: ["post-market", "post market", "monitoring plan", "surveillance", "deployed monitoring", "pmm"],
    procedure: "AI-PMM.1",
    title: "Post-Market Monitoring",
    reason: "Post-market monitoring activity detected -- witness the monitoring attestation",
    priority: 2,
  },
  // --- Additional procedure keyword mappings (full coverage) ---
  {
    keywords: ["latency", "response time", "timeout", "p95", "p99", "slow", "performance budget"],
    procedure: "AI-INF.2",
    title: "Inference Latency",
    reason: "Inference latency or response time context detected -- witness latency threshold compliance",
    priority: 3,
  },
  {
    keywords: ["rate limit", "throttle", "volume", "quota", "requests per", "throughput", "capacity"],
    procedure: "AI-INF.3",
    title: "Inference Volume",
    reason: "Inference volume or rate limiting detected -- witness hourly rate governance",
    priority: 3,
  },
  {
    keywords: ["model version", "version track", "model tag", "model release", "semver", "checkpoint version"],
    procedure: "AI-MDL.2",
    title: "Model Version Tracking",
    reason: "Model versioning context detected -- witness the version identifier",
    priority: 3,
  },
  {
    keywords: ["model drift", "drift score", "drift threshold", "distribution shift", "covariate shift"],
    procedure: "AI-MDL.3",
    title: "Model Drift Scoring",
    reason: "Model drift scoring detected -- witness the drift measurement",
    priority: 3,
  },
  {
    keywords: ["model weight", "weight hash", "safetensors", "gguf", "model file", "model integrity"],
    procedure: "AI-MDL.5",
    title: "Weight File Integrity",
    reason: "Model weight file context detected -- witness the file hash for integrity verification",
    priority: 2,
  },
  {
    keywords: ["adapter", "lora", "qlora", "peft", "adapter stack", "fine-tune adapter"],
    procedure: "AI-MDL.6",
    title: "Adapter Stack Attestation",
    reason: "Adapter or LoRA context detected -- witness the adapter stack configuration",
    priority: 3,
  },
  {
    keywords: ["quantiz", "gptq", "awq", "bnb", "4-bit", "8-bit", "fp16", "int8", "mixed precision"],
    procedure: "AI-MDL.7",
    title: "Quantization Attestation",
    reason: "Model quantization detected -- witness the quantization parameters",
    priority: 3,
  },
  {
    keywords: ["content safety", "output filter", "toxicity", "nsfw", "hate speech", "harmful content"],
    procedure: "AI-GRD.2",
    title: "Content Safety Filter",
    reason: "Content safety filtering detected -- witness the output classification result",
    priority: 2,
  },
  {
    keywords: ["pii", "redact", "mask", "anonymiz", "de-identif", "personal data", "ssn", "email scrub"],
    procedure: "AI-GRD.3",
    title: "PII Redaction",
    reason: "PII redaction or data masking detected -- witness the redaction action",
    priority: 2,
  },
  {
    keywords: ["bias ratio", "disparity", "demographic parity", "equalized odds", "selection rate"],
    procedure: "AI-FAIR.1",
    title: "Bias Disparity Measurement",
    reason: "Bias measurement context detected -- witness the disparity ratio",
    priority: 3,
  },
  {
    keywords: ["calibration", "fairness score", "fairness metric", "brier score", "calibration curve"],
    procedure: "AI-FAIR.2",
    title: "Fairness Calibration",
    reason: "Fairness calibration detected -- witness the calibration score",
    priority: 3,
  },
  {
    keywords: ["training data", "data provenance", "dataset source", "data lineage", "data origin"],
    procedure: "AI-DATA.1",
    title: "Training Data Provenance",
    reason: "Training data provenance context detected -- witness the dataset source and lineage",
    priority: 2,
  },
  {
    keywords: ["data license", "dataset license", "training license", "data rights", "data use agreement"],
    procedure: "AI-DATA.2",
    title: "Training Data License Compliance",
    reason: "Training data licensing detected -- witness the license compliance status",
    priority: 2,
  },
  {
    keywords: ["pii lifecycle", "data retention", "data deletion", "data minimiz", "purpose limitation"],
    procedure: "AI-DATA.4",
    title: "Training Data PII Lifecycle",
    reason: "PII data lifecycle management detected -- witness the retention and deletion compliance",
    priority: 2,
  },
  {
    keywords: ["human review", "human-in-the-loop", "hitl", "manual review", "human oversight", "human check"],
    procedure: "AI-HITL.1",
    title: "Human Review Completion",
    reason: "Human review or oversight context detected -- witness the review completion",
    priority: 2,
  },
  {
    keywords: ["override", "human override", "manual override", "escalat", "human correction", "veto"],
    procedure: "AI-HITL.2",
    title: "Human Override Event",
    reason: "Human override or escalation detected -- witness the override event",
    priority: 2,
  },
  {
    keywords: ["explain", "interpretab", "shap", "lime", "feature importance", "attention", "saliency"],
    procedure: "AI-EXPL.1",
    title: "Explanation Generation",
    reason: "Explainability or interpretation context detected -- witness the explanation output",
    priority: 3,
  },
  {
    keywords: ["confidence", "certainty", "probability", "logprob", "uncertainty", "calibrated score"],
    procedure: "AI-EXPL.2",
    title: "Confidence Scoring",
    reason: "Model confidence or uncertainty context detected -- witness the confidence score",
    priority: 3,
  },
  {
    keywords: ["relevance", "retrieval quality", "context score", "reranker", "chunk relevance"],
    procedure: "AI-RAG.2",
    title: "RAG Context Relevance",
    reason: "Retrieval quality or relevance scoring detected -- witness the relevance assessment",
    priority: 3,
  },
  {
    keywords: ["security scan", "threat detect", "adversarial detect", "input scan", "prompt injection detect"],
    procedure: "AI-SEC.1",
    title: "Adversarial Threat Detection",
    reason: "Security scanning or adversarial detection context -- witness the scan results",
    priority: 2,
  },
  {
    keywords: ["input valid", "sanitiz", "input filter", "payload valid", "schema valid", "input boundar"],
    procedure: "AI-SEC.2",
    title: "Input Validation",
    reason: "Input validation or sanitization detected -- witness the validation result",
    priority: 2,
  },
  {
    keywords: ["memory", "conversation history", "context window", "session state", "memory binding"],
    procedure: "AI-SKILL.2",
    title: "Memory Context Binding",
    reason: "Agent memory or conversation state detected -- witness the memory context",
    priority: 3,
  },
  {
    keywords: ["reward", "rlhf", "preference", "reward model", "alignment", "dpo", "rlaif"],
    procedure: "AI-SKILL.3",
    title: "Reward Model Binding",
    reason: "Reward model or alignment training detected -- witness the reward signal",
    priority: 3,
  },
  {
    keywords: ["gpu", "cuda", "accelerator", "tpu", "npu", "hardware inventory", "device"],
    procedure: "AI-HW.1",
    title: "Hardware Runtime Attestation",
    reason: "GPU or accelerator hardware context detected -- witness the hardware inventory",
    priority: 3,
  },
  {
    keywords: ["tpm", "pcr", "firmware", "secure boot", "measured boot", "root of trust"],
    procedure: "AI-HW.3",
    title: "TPM Platform Attestation",
    reason: "TPM or firmware integrity context detected -- witness the platform attestation",
    priority: 3,
  },
  {
    keywords: ["trust verif", "compliance check", "posture check", "agent trust", "mutual trust"],
    procedure: "AI-TRUST.1",
    title: "Trust Verification",
    reason: "Agent trust or compliance verification detected -- witness the trust check result",
    priority: 3,
  },
  {
    keywords: ["trust handshake", "credential exchange", "trust credential", "compliance credential"],
    procedure: "AI-TRUST.2",
    title: "Trust Credential Presentation",
    reason: "Trust handshake or credential exchange detected -- witness the handshake details",
    priority: 3,
  },
  {
    keywords: ["charter", "system prompt", "constitution", "behavioral contract", "agent policy"],
    procedure: "AI-CHR.1",
    title: "Agent Charter Registration",
    reason: "Agent charter or system prompt context detected -- witness the charter hash",
    priority: 3,
  },
  {
    keywords: ["stop", "interrupt", "kill switch", "emergency stop", "safe state", "shutdown", "circuit breaker"],
    procedure: "AI-SAFE.1",
    title: "Safe State Transition",
    reason: "Stop mechanism or safe state context detected -- witness the safe state attestation",
    priority: 2,
  },
  {
    keywords: ["chain depth", "trust degrad", "chain trust", "hop count", "transitive trust"],
    procedure: "AI-CHAIN.2",
    title: "Chain Trust Degradation",
    reason: "Chain depth or trust degradation context detected -- witness trust decay measurement",
    priority: 3,
  },
  {
    keywords: ["dependency manifest", "package list", "pip freeze", "npm ls", "requirements.txt", "lock file"],
    procedure: "AI-ENV.2",
    title: "Dependency Manifest Attestation",
    reason: "Runtime dependency or package manifest detected -- witness the dependency inventory",
    priority: 3,
  },
  {
    keywords: ["governance", "governance config", "governance layer", "governance policy", "meta-governance", "metagov", "policy stack"],
    procedure: "AI-METAGOV.1",
    title: "Governance Infrastructure Attestation",
    reason: "Governance infrastructure or policy configuration detected -- witness the governance config",
    priority: 2,
  },
  {
    keywords: ["governance layer", "policy layer", "governance registration", "compliance layer", "governance stack"],
    procedure: "AI-METAGOV.2",
    title: "Governance Layer Registration",
    reason: "Governance layer registration detected -- witness the layer binding",
    priority: 3,
  },
  {
    keywords: ["policy downgrade", "config downgrade", "weaken policy", "reduce clearing", "lower security"],
    procedure: "AI-METAGOV.3",
    title: "Policy Downgrade Detection",
    reason: "Policy downgrade or weakening detected -- witness the configuration change",
    priority: 1,
  },
  {
    keywords: ["circular dependency", "governance cycle", "policy loop", "circular governance", "dependency graph"],
    procedure: "AI-METAGOV.4",
    title: "Circular Dependency Check",
    reason: "Governance dependency analysis detected -- witness the cycle detection result",
    priority: 2,
  },
  {
    keywords: ["governance change", "governance authorization", "policy change approval", "governance approval"],
    procedure: "AI-METAGOV.5",
    title: "Governance Authorization",
    reason: "Governance change authorization detected -- witness the approval decision",
    priority: 2,
  },
  {
    keywords: ["emergency override", "break glass", "emergency governance", "governance bypass", "emergency policy"],
    procedure: "AI-METAGOV.6",
    title: "Emergency Override Attestation",
    reason: "Emergency governance override detected -- witness the override event and justification",
    priority: 1,
  },
  {
    keywords: ["governance sync", "federation sync", "policy sync", "governance federation", "cross-tenant governance"],
    procedure: "AI-METAGOV.7",
    title: "Governance Sync Verification",
    reason: "Governance federation or policy sync detected -- witness the sync verification",
    priority: 3,
  },
  {
    keywords: ["attestation purity", "self-referential", "governance integrity", "attestation verification"],
    procedure: "AI-METAGOV.8",
    title: "Attestation Purity Verification",
    reason: "Attestation purity check detected -- verify governance anchors are not self-referential",
    priority: 3,
  },
];

export function handleSuggest(args: SuggestArgs): string {
  const context = [
    args.context,
    args.model_id || "",
    args.data_classification || "",
    ...(args.tools_used || []),
  ].join(" ").toLowerCase();

  const matches: Suggestion[] = [];
  const seen = new Set<string>();

  for (const entry of KEYWORD_MAP) {
    if (seen.has(entry.procedure)) continue;
    const hit = entry.keywords.some((kw) => context.includes(kw));
    if (hit) {
      seen.add(entry.procedure);
      matches.push({
        procedure: entry.procedure,
        title: entry.title,
        reason: entry.reason,
        priority: entry.priority,
      });
    }
  }

  // Always suggest AI-INF.1 if nothing else matched
  if (matches.length === 0) {
    matches.push({
      procedure: "AI-INF.1",
      title: "Inference Provenance",
      reason: "Default recommendation -- witness any AI inference for baseline compliance",
      priority: 1,
    });
  }

  // Data classification boost
  if (args.data_classification) {
    const classification = args.data_classification.toLowerCase();
    if (classification === "sensitive" || classification === "classified") {
      if (!seen.has("AI-ACC.1")) {
        matches.push({
          procedure: "AI-ACC.1",
          title: "Access Control Witnessing",
          reason: `Data classified as ${args.data_classification} -- witness access decisions`,
          priority: 1,
        });
      }
    }
  }

  // Sort by priority
  matches.sort((a, b) => a.priority - b.priority);

  const lines = [
    `Suggested Procedures (${matches.length}):`,
    ``,
  ];

  for (const m of matches) {
    lines.push(`  ${m.procedure} -- ${m.title}`);
    lines.push(`    ${m.reason}`);
    lines.push(``);
  }

  lines.push(`These are advisory only. Use witness_inference or the relevant tool to attest.`);

  return lines.join("\n");
}
