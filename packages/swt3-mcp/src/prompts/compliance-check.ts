/**
 * SWT3 MCP Server: compliance-check prompt template.
 *
 * Generates an adaptive prompt that guides the LLM through a compliance
 * witnessing session based on the selected framework and context.
 */

import {
  resolveFramework,
  crosswalkFrameworks as frameworks,
} from "@tenova/swt3-ai";

interface ComplianceCheckArgs {
  framework: string;
  model_id?: string;
  context?: string;
}

// Map procedures to MCP tool names
const PROC_TO_TOOL: Record<string, string> = {
  "AI-INF.1": "witness_inference",
  "AI-ACC.1": "witness_authorization",
  "AI-GRD.1": "witness_guardrail",
  "AI-HITL.1": "witness_human_review",
  "AI-RAG.1": "witness_rag_context",
  "AI-RAG.2": "witness_rag_context",
  "AI-MDL.5": "witness_model_integrity",
  "AI-MDL.6": "witness_adapter_stack",
  "AI-SKILL.1": "attest_skill_manifest",
  "AI-SKILL.2": "attest_memory_context",
  "AI-DEL.1": "witness_delegation_tree",
  "AI-COST.1": "witness_resource_consumption",
  "AI-CHAIN.1": "chain_handoff",
  "AI-VIO.1": "report_violation",
  "AI-TRUST.1": "verify_agent_trust",
};

export function buildComplianceCheckPrompt(args: ComplianceCheckArgs): string {
  const fwId = args.framework.toUpperCase();

  // Resolve framework procedures
  let procList: string[] = [];
  try {
    const mapping = resolveFramework(fwId);
    const seen = new Set<string>();
    for (const procs of Object.values(mapping)) {
      for (const p of procs as string[]) {
        if (!seen.has(p)) {
          seen.add(p);
          procList.push(p);
        }
      }
    }
  } catch {
    // Framework not found -- use core procedures
  }

  if (procList.length === 0) {
    procList = ["AI-INF.1", "AI-GRD.1", "AI-HITL.1", "AI-RAG.1", "AI-ACC.1"];
  }

  // Find which MCP tools cover these procedures
  const toolsNeeded = new Set<string>();
  for (const proc of procList) {
    const tool = PROC_TO_TOOL[proc];
    if (tool) toolsNeeded.add(tool);
  }

  // Always include these
  toolsNeeded.add("witness_inference");

  const fwName = (() => {
    try {
      const allFw = frameworks();
      const meta = allFw[fwId] as { name?: string } | undefined;
      return meta?.name ?? fwId;
    } catch {
      return fwId;
    }
  })();

  const lines: string[] = [];
  lines.push(`You are conducting an AI compliance witnessing session under the ${fwName} framework.`);
  lines.push(``);

  if (args.context) {
    lines.push(`Context: ${args.context}`);
    lines.push(``);
  }

  lines.push(`## Session Setup`);
  lines.push(``);
  lines.push(`1. Call \`start_audit_session\` to begin tracking which procedures are witnessed.`);
  lines.push(``);

  lines.push(`## Applicable Procedures`);
  lines.push(``);
  lines.push(`The ${fwName} framework maps to ${procList.length} SWT3 procedures. Focus on the ones relevant to your current task:`);
  lines.push(``);

  // Group by category
  const categories: Record<string, string[]> = {};
  for (const proc of procList.sort()) {
    const ns = proc.split("-")[1]?.split(".")[0] ?? "OTHER";
    if (!categories[ns]) categories[ns] = [];
    categories[ns].push(proc);
  }

  for (const [ns, procs] of Object.entries(categories)) {
    const procsStr = procs.join(", ");
    lines.push(`- **${ns}**: ${procsStr}`);
  }
  lines.push(``);

  lines.push(`## Available Tools`);
  lines.push(``);
  lines.push(`Use these MCP tools based on what the AI system is doing:`);
  lines.push(``);

  const toolDescriptions: Record<string, string> = {
    witness_inference: "Witness any AI model call (required for all sessions)",
    witness_guardrail: "Witness guardrail activation or presence",
    witness_human_review: "Witness human review of AI output",
    witness_rag_context: "Witness RAG retrieval provenance and relevance",
    witness_authorization: "Witness resource access decisions",
    witness_model_integrity: "Verify model weight integrity",
    witness_adapter_stack: "Attest LoRA/adapter configuration",
    attest_skill_manifest: "Attest loaded skills/tools/plugins",
    attest_memory_context: "Attest persistent memory sources",
    witness_delegation_tree: "Witness permission delegation chains",
    witness_resource_consumption: "Witness token usage and costs",
    chain_handoff: "Witness agent-to-agent handoffs",
    verify_agent_trust: "Verify counterpart agent trust",
    report_violation: "Self-report policy violations",
  };

  for (const tool of Array.from(toolsNeeded).sort()) {
    const desc = toolDescriptions[tool] ?? tool;
    lines.push(`- \`${tool}\`: ${desc}`);
  }
  lines.push(``);

  if (args.model_id) {
    lines.push(`## Model`);
    lines.push(``);
    lines.push(`Use model_id "${args.model_id}" for all witness calls in this session.`);
    lines.push(``);
  }

  lines.push(`## Session Close`);
  lines.push(``);
  lines.push(`When finished, call \`end_audit_session\` to see a gap report showing which procedures were witnessed and which were missed. Then call \`coverage_report\` with framework "${fwId}" to see the coverage percentage.`);
  lines.push(``);
  lines.push(`Prioritize witnessing the procedures most relevant to the current task. Not every procedure needs to be witnessed in every session -- focus on what the AI system is actually doing.`);

  return lines.join("\n");
}
