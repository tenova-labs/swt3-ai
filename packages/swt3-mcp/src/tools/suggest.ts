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
    keywords: ["drift", "version", "chang", "updat", "different model", "switch", "migrat"],
    procedure: "AI-DFT.1",
    title: "Model Drift Detection",
    reason: "Model version or behavior change indicated -- witness for drift tracking",
    priority: 2,
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
