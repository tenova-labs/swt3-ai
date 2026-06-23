/**
 * SWT3 MCP Server — Server assembly.
 *
 * Creates an MCP Server with tools and resources for the SWT3 AI Witness protocol.
 * Supports three modes: demo (zero config), API key only (auto-resolve tenant),
 * and full config (API key + tenant ID).
 */

import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { McpConfig, McpConfigBundle } from "./config.js";
import { AxiomClient } from "./client.js";
import { initChainDensity, evaluateToolPolicy } from "./tool-policy.js";
import { createSessionState } from "./state.js";
import { handleWitness } from "./tools/witness.js";
import { handleVerify } from "./tools/verify.js";
import { handleProcedures } from "./tools/procedures.js";
import { handlePosture } from "./tools/posture.js";
import { handleSignup } from "./tools/signup.js";
import { handleAuthorize } from "./tools/authorize.js";
import { handleStartAudit, handleEndAudit, trackProcedure } from "./tools/audit.js";
import { handleSuggest } from "./tools/suggest.js";
import { handleStartChain, handleChainHandoff } from "./tools/chain.js";
import { handleReportViolation } from "./tools/violation.js";
import { handleWitnessModelIntegrity, handleWitnessAdapterStack } from "./tools/model.js";
import { handleAttestSkillManifest, handleAttestMemoryContext } from "./tools/skill.js";
import { handleVerifyAgentTrust, handlePresentCredential } from "./tools/trust.js";
import { readRegistry } from "./resources/registry.js";
import { readHealth } from "./resources/health.js";
import { REGISTRY_RESOURCE } from "./resources/registry.js";
import { HEALTH_RESOURCE } from "./resources/health.js";
import { verifyAnchorChain } from "./chain-verifier.js";
import { loadDensityPolicy } from "./density-policy.js";
import { startRedisReader, stopRedisReader, getReaderState } from "./redis-reader.js";
import { mintFingerprint, timestampMs, signPayload } from "./fingerprint.js";

// Chain density + tool policy functions imported from ./tool-policy.js

export function createServer(config: McpConfig, bundle?: McpConfigBundle): McpServer {
  const client = new AxiomClient(config);
  const sessionState = createSessionState(
    bundle?.trustMesh?.trustedTenants,
    bundle?.trustMesh?.deniedAgents,
  );
  const densityPolicy = bundle?.densityPolicy ?? loadDensityPolicy();
  const mcpPolicy = bundle?.mcpPolicy ?? null;
  const chainDensity = mcpPolicy ? initChainDensity(mcpPolicy) : null;

  // Start Redis reader if chain verification is enabled
  if (config.chainVerify) {
    startRedisReader({ redisUrl: config.redisUrl, streamName: config.redisStream })
      .then((ok) => {
        sessionState.redisReader = getReaderState();
        if (!ok) {
          // Redis unavailable -- will fall back to ledger queries
        }
      })
      .catch(() => { /* graceful: ledger fallback */ });
  }

  /**
   * Chain verification gate. Returns null if chain is valid (or gate disabled).
   * Returns denial message string if chain verification fails.
   */
  async function chainGate(args: Record<string, unknown>): Promise<string | null> {
    if (!config.chainVerify || config.demo) return null;

    const agentId = (args.agent_id as string) || config.agentId;
    const cycleId = (args.cycle_id as string) || sessionState.activeChain?.cycleId;

    // No identity context -- cannot verify, deny
    if (!agentId && !cycleId) {
      return "Chain verification failed: no agent_id or cycle_id provided. " +
        "Set SWT3_AGENT_ID or pass agent_id/cycle_id to enable chain verification.";
    }

    const result = await verifyAnchorChain(
      agentId, cycleId, config, client, densityPolicy,
      args.input_tokens as number | undefined,
    );

    if (result.valid) return null;

    // Mint AI-TRUST.1 FAIL anchor for the denial
    const [ts, epoch] = timestampMs();
    const fp = mintFingerprint(config.tenantId, "AI-TRUST.1", 1, 0, 0, ts);
    if (!config.demo) {
      client.postWitness({
        procedure_id: "AI-TRUST.1",
        factor_a: 1, factor_b: 0, factor_c: 0,
        clearing_level: config.clearingLevel,
        anchor_fingerprint: fp,
        anchor_epoch: epoch,
        fingerprint_timestamp_ms: ts,
        ai_model_id: "chain-gate",
        witness_source: "mcp",
        ...(agentId ? { agent_id: agentId } : {}),
        ...(cycleId ? { cycle_id: cycleId } : {}),
        ...(config.signingKey ? { payload_signature: signPayload(config.signingKey, fp, agentId) } : {}),
      }).catch(() => { /* fire-and-forget */ });
    }

    const violations = result.policyViolations.map((v) => `  - ${v.message}`).join("\n");
    return [
      `Chain Verification DENIED`,
      `Reason: ${result.reason || "unknown"}`,
      `Anchors found: ${result.anchorCount} (source: ${result.source})`,
      ...(result.gaps.length > 0 ? [`Gaps: ${result.gaps.length} (max gap: ${Math.max(...result.gaps.map((g) => g.gapSeconds))}s)`] : []),
      ...(result.revoked.length > 0 ? [`Revoked anchors: ${result.revoked.join(", ")}`] : []),
      ...(violations ? [`Policy violations:\n${violations}`] : []),
      ``,
      `To pass chain verification, ensure your agent has recent SWT3 anchors`,
      `linked by agent_id or cycle_id with no gaps exceeding ${config.maxChainGapSeconds}s.`,
    ].join("\n");
  }

  function toolPolicyGate(toolName: string): "witness" | "exempt" | "block" | null {
    const sessionTrust = sessionState.verifiedTrustLevel
      ?? (sessionState.activeAuditSession ? 2 : (config.signingKey ? 1 : 0));
    return evaluateToolPolicy(toolName, mcpPolicy, chainDensity, sessionTrust);
  }

  type McpToolResult = { content: Array<{ type: "text"; text: string }>; isError?: boolean };
  type McpToolHandler = (args: Record<string, unknown>) => Promise<McpToolResult>;

  /**
   * Auto-mint an AI-TOOL.1 anchor for a tool call.
   * Called after successful execution when toolPolicyGate returns "witness".
   */
  async function autoWitnessTool(toolName: string, args: Record<string, unknown>, startMs: number): Promise<void> {
    const elapsedMs = Date.now() - startMs;
    const [ts, epoch] = timestampMs();
    const inputHash = mintFingerprint(config.tenantId, toolName, 1, 0, 0, ts).slice(0, 8);
    const fp = mintFingerprint(config.tenantId, "AI-TOOL.1", 1, elapsedMs, 1, ts);

    const payload = {
      procedure_id: "AI-TOOL.1",
      factor_a: 1,
      factor_b: elapsedMs,
      factor_c: 1,
      clearing_level: config.clearingLevel,
      anchor_fingerprint: fp,
      anchor_epoch: epoch,
      fingerprint_timestamp_ms: ts,
      ai_model_id: toolName,
      ai_context: { tool_name: toolName, latency_ms: elapsedMs, provider: "mcp" },
    };

    if (!config.demo) {
      try {
        await client.postWitness(payload);
      } catch { /* best-effort */ }
    }
    trackProcedure(sessionState, "AI-TOOL.1");
  }

  /**
   * Wrap an MCP tool handler with policy enforcement.
   *
   * Before execution: checks toolPolicyGate.
   *   - "block" => returns denial without executing
   *   - "exempt" / null => executes without auto-witnessing
   *   - "witness" => executes, then auto-mints AI-TOOL.1 anchor
   */
  function withPolicyEnforcement(toolName: string, handler: McpToolHandler): McpToolHandler {
    return async (args: Record<string, unknown>): Promise<McpToolResult> => {
      const gate = toolPolicyGate(toolName);

      if (gate === "block") {
        const reason = mcpPolicy?.blockOnFailure !== false
          ? `Tool "${toolName}" blocked by MCP tool policy.`
          : `Tool "${toolName}" would be blocked by policy (log-only mode).`;
        if (mcpPolicy?.blockOnFailure !== false) {
          return {
            content: [{ type: "text" as const, text: reason }],
            isError: true,
          };
        }
        // Log-only: fall through to execute
      }

      const startMs = Date.now();
      const result = await handler(args);

      if (gate === "witness" && !result.isError) {
        await autoWitnessTool(toolName, args, startMs);
      }

      return result;
    };
  }

  const server = new McpServer({
    name: "swt3-mcp",
    version: "0.1.0",
  });

  // --- Tools ---

  server.registerTool("witness_inference", {
    description:
      "Mint a cryptographic SWT3 witness anchor for an AI inference. " +
      "Records model identity, prompt/response hashes, and latency as " +
      "compliance evidence. Raw text is hashed locally and never sent to the server." +
      (config.demo ? " Currently in DEMO mode — anchors are minted locally. Use the signup tool to persist them." : ""),
    inputSchema: {
      model_id: z.string().describe("AI model identifier (e.g., gpt-4o, claude-sonnet-4)"),
      prompt: z.string().optional().describe("Raw prompt text (hashed locally, never sent to server)"),
      prompt_hash: z.string().optional().describe("Pre-computed SHA-256 hash of prompt (16 hex chars)"),
      response: z.string().optional().describe("Raw response text (hashed locally, never sent to server)"),
      response_hash: z.string().optional().describe("Pre-computed SHA-256 hash of response (16 hex chars)"),
      latency_ms: z.number().optional().describe("Inference latency in milliseconds"),
      input_tokens: z.number().optional().describe("Number of input tokens"),
      output_tokens: z.number().optional().describe("Number of output tokens"),
      clearing_level: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]).optional()
        .describe("Data clearing level (0=analytics, 1=standard, 2=sensitive, 3=classified)"),
      procedure: z.string().optional().describe("UCT procedure ID (default: AI-INF.1)"),
      provider: z.string().optional().describe("AI provider name (openai, anthropic, bedrock, etc.)"),
      agent_id: z.string().optional().describe("Agent identity for this inference (AI-ID.1)"),
      cycle_id: z.string().optional().describe("Multi-agent chain link identifier"),
      jurisdiction: z.string().optional().describe("ISO 3166-1 jurisdiction code (e.g., 'DE', 'US-VA')"),
      legal_basis: z.string().optional().describe("GDPR legal basis (e.g., 'consent', 'legitimate_interest', 'contract')"),
      purpose_class: z.string().optional().describe("Processing purpose classification (e.g., 'clinical_decision_support')"),
    },
    annotations: { readOnlyHint: false },
  }, async (args) => {
    try {
      const text = await handleWitness(args, config, client);
      trackProcedure(sessionState, (args as Record<string, unknown>).procedure as string || "AI-INF.1");
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  server.registerTool("verify_anchor", {
    description:
      "Verify the cryptographic integrity of an SWT3 witness anchor. " +
      "Checks that the anchor's fingerprint matches the recomputed value " +
      "from the original factors, proving the evidence has not been tampered with.",
    inputSchema: {
      token: z.string().describe("SWT3 anchor token (e.g., SWT3-E-VULTR-AI-AIINF1-PASS-1700000000-96b7d56c0245)"),
    },
    annotations: { readOnlyHint: true },
  }, async (args) => {
    try {
      const text = await handleVerify(args, config, client);
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  server.registerTool("list_procedures", {
    description:
      "List available UCT (Universal Control Taxonomy) procedures from the SWT3 registry. " +
      "Each procedure maps to a specific compliance control (e.g., AI-INF.1 for inference provenance). " +
      "Optionally filter by namespace (AI, ACC, AUD, CFG, NET, etc.).",
    inputSchema: {
      namespace: z.string().optional().describe("Filter by UCT namespace prefix (e.g., 'AI' for AI procedures)"),
    },
    annotations: { readOnlyHint: true },
  }, async (args) => {
    try {
      const text = await handleProcedures(args, config, client);
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  server.registerTool("check_posture", {
    description:
      "Check the current AI witness compliance posture for your tenant. " +
      "Returns model activity summary, pass/fail counts, and overall compliance status." +
      (config.demo ? " Requires a live account — use the signup tool first." : ""),
    annotations: { readOnlyHint: true },
  }, async () => {
    if (config.demo) {
      return {
        content: [{ type: "text" as const, text: "Posture requires a live account. Use the signup tool to create a free account." }],
        isError: true,
      };
    }
    try {
      const text = await handlePosture({}, config, client);
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  server.registerTool("signup", {
    description:
      "Get a signup link to create a free SWT3 account. " +
      "Opens in your browser — no credentials pass through the AI. " +
      "After signup, copy your API key into the MCP config to activate live mode.",
    inputSchema: {
      framework: z.string().optional().describe("Primary compliance framework (default: NIST-800-53). Options: NIST-800-53, CMMC-v2.0, AI-RMF, EU-AI-ACT, SR-11-7, NIST-800-171"),
    },
    annotations: { readOnlyHint: true },
  }, async (args) => {
    try {
      const text = await handleSignup(args, config);
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  server.registerTool("witness_authorization", {
    description:
      "Witness an authorization decision as an AI-ACC.1 anchor. " +
      "Records whether a resource access was granted or denied. " +
      "FAIL anchors trigger alerts but never block execution." +
      (config.demo ? " Currently in DEMO mode — anchors are minted locally. Use the signup tool to persist them." : ""),
    inputSchema: {
      resource: z.string().describe("Resource being accessed (e.g., 'prod-database', 'user-pii-store')"),
      scope: z.string().optional().describe("Authorization scope (e.g., 'read-only', 'write', 'admin')"),
      granted: z.boolean().describe("Whether access was granted (true) or denied (false)"),
      agent_id: z.string().optional().describe("Agent identity requesting access (AI-ID.1)"),
      cycle_id: z.string().optional().describe("Multi-agent chain link identifier"),
      clearing_level: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]).optional()
        .describe("Data clearing level (0=analytics, 1=standard, 2=sensitive, 3=classified)"),
    },
    annotations: { readOnlyHint: false },
  }, async (args) => {
    try {
      const denial = await chainGate(args as Record<string, unknown>);
      if (denial) return { content: [{ type: "text" as const, text: denial }], isError: true };
      const text = await handleAuthorize(args as { resource: string; scope?: string; granted: boolean; agent_id?: string; cycle_id?: string; clearing_level?: 0 | 1 | 2 | 3 }, config, client);
      trackProcedure(sessionState, "AI-ACC.1");
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  // --- Compliance Discovery Tools ---

  server.registerTool("start_audit_session", {
    description:
      "Begin passive compliance tracking for this conversation. " +
      "Records which procedures are witnessed. Call end_audit_session for a gap report. " +
      "Purely observational -- never blocks execution.",
    annotations: { readOnlyHint: true },
  }, async () => {
    try {
      const text = handleStartAudit(sessionState);
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  server.registerTool("end_audit_session", {
    description:
      "End the audit session and produce a compliance gap report. " +
      "Shows which AI procedures were witnessed and which were missed.",
    inputSchema: {
      session_id: z.string().optional().describe("Session ID (uses active session if omitted)"),
    },
    annotations: { readOnlyHint: true },
  }, async (args) => {
    try {
      const text = await handleEndAudit(args, sessionState, client);
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  server.registerTool("suggest_procedures", {
    description:
      "Get advisory suggestions for which SWT3 procedures to witness based on context. " +
      "Returns a ranked list of applicable procedures. Advisory only -- never enforced. " +
      "No network call required.",
    inputSchema: {
      context: z.string().describe("What the agent is doing (e.g., 'calling GPT-4o to summarize a contract')"),
      model_id: z.string().optional().describe("AI model being used"),
      data_classification: z.string().optional().describe("Data sensitivity (public, internal, sensitive, classified)"),
      tools_used: z.array(z.string()).optional().describe("Tools or functions being called"),
    },
    annotations: { readOnlyHint: true },
  }, async (args) => {
    try {
      const text = handleSuggest(args as { context: string; model_id?: string; data_classification?: string; tools_used?: string[] });
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  // --- Multi-Agent Chain Tools ---

  server.registerTool("start_chain", {
    description:
      "Generate a cycle_id for a multi-agent chain. " +
      "Pass the returned cycle_id to subsequent witness calls to link all anchors in the chain. " +
      "Metadata only -- never blocks execution.",
    inputSchema: {
      description: z.string().optional().describe("Chain description (e.g., 'contract review pipeline')"),
    },
    annotations: { readOnlyHint: true },
  }, async (args) => {
    try {
      const text = handleStartChain(args as { description?: string }, sessionState);
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  server.registerTool("chain_handoff", {
    description:
      "Witness a handoff between agents in a multi-agent chain. " +
      "Mints an AI-CHAIN.1 anchor recording custody transfer. " +
      "Evidence only -- never blocks execution." +
      (config.demo ? " Currently in DEMO mode -- anchors are minted locally." : ""),
    inputSchema: {
      cycle_id: z.string().describe("Chain cycle_id from start_chain"),
      from_agent: z.string().describe("Agent handing off (e.g., 'summarizer-agent')"),
      to_agent: z.string().describe("Agent receiving handoff (e.g., 'reviewer-agent')"),
      context: z.string().optional().describe("What is being handed off"),
      clearing_level: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]).optional()
        .describe("Data clearing level (0=analytics, 1=standard, 2=sensitive, 3=classified)"),
    },
    annotations: { readOnlyHint: false },
  }, async (args) => {
    try {
      const text = await handleChainHandoff(
        args as { cycle_id: string; from_agent: string; to_agent: string; context?: string; clearing_level?: 0 | 1 | 2 | 3 },
        config, client,
      );
      trackProcedure(sessionState, "AI-CHAIN.1");
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  // --- Self-Attestation Tools ---

  server.registerTool("report_violation", {
    description:
      "Voluntarily self-report a policy violation. " +
      "Mints a FAIL anchor as evidence. Never blocks execution. " +
      "FAIL anchors trigger downstream alerts via the existing pipeline." +
      (config.demo ? " Currently in DEMO mode -- anchors are minted locally." : ""),
    inputSchema: {
      violation_type: z.string().describe("Type of violation (e.g., 'unauthorized_model', 'data_leak', 'jurisdiction_mismatch')"),
      description: z.string().describe("Description of what happened"),
      severity: z.string().optional().describe("Severity level (low, medium, high, critical). Default: medium"),
      agent_id: z.string().optional().describe("Agent identity reporting the violation"),
      cycle_id: z.string().optional().describe("Multi-agent chain link identifier"),
      clearing_level: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]).optional()
        .describe("Data clearing level (0=analytics, 1=standard, 2=sensitive, 3=classified)"),
    },
    annotations: { readOnlyHint: false },
  }, async (args) => {
    try {
      const text = await handleReportViolation(
        args as { violation_type: string; description: string; severity?: string; agent_id?: string; cycle_id?: string; clearing_level?: 0 | 1 | 2 | 3 },
        config, client,
      );
      trackProcedure(sessionState, "AI-VIO.1");
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  // --- Model Weight & Adapter Tools ---

  server.registerTool("witness_model_integrity", {
    description:
      "Witness model weight file integrity (AI-MDL.5). " +
      "Verifies the SHA-256 hash of model weights against an expected value. " +
      "Evidence only -- never blocks execution." +
      (config.demo ? " Currently in DEMO mode -- anchors are minted locally." : ""),
    inputSchema: {
      model_id: z.string().describe("Model identifier (e.g., 'llama-3.1-70b-instruct')"),
      weight_hash: z.string().describe("SHA-256 hash of the model weight file"),
      expected_hash: z.string().optional().describe("Expected hash for verification. Omit to attest without verification."),
      format: z.string().optional().describe("Weight file format (safetensors, gguf, bin, pt)"),
      file_size_bytes: z.number().optional().describe("Weight file size in bytes"),
      agent_id: z.string().optional().describe("Agent identity"),
      cycle_id: z.string().optional().describe("Multi-agent chain link identifier"),
      clearing_level: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]).optional()
        .describe("Data clearing level (0=analytics, 1=standard, 2=sensitive, 3=classified)"),
    },
    annotations: { readOnlyHint: false },
  }, async (args) => {
    try {
      const denial = await chainGate(args as Record<string, unknown>);
      if (denial) return { content: [{ type: "text" as const, text: denial }], isError: true };
      const text = await handleWitnessModelIntegrity(
        args as any, config, client,
      );
      trackProcedure(sessionState, "AI-MDL.5");
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  server.registerTool("witness_adapter_stack", {
    description:
      "Witness active LoRA/QLoRA/PEFT adapter stack (AI-MDL.6). " +
      "Records which adapters are loaded on top of a base model. " +
      "Evidence only -- never blocks execution." +
      (config.demo ? " Currently in DEMO mode -- anchors are minted locally." : ""),
    inputSchema: {
      base_model: z.string().describe("Base model identifier (e.g., 'llama-3.1-70b')"),
      adapters: z.array(z.object({
        name: z.string().describe("Adapter name"),
        hash: z.string().describe("SHA-256 hash of adapter weights"),
        base_model: z.string().optional().describe("Base model this adapter was trained on"),
      })).describe("List of active adapters"),
      agent_id: z.string().optional().describe("Agent identity"),
      cycle_id: z.string().optional().describe("Multi-agent chain link identifier"),
      clearing_level: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]).optional()
        .describe("Data clearing level"),
    },
    annotations: { readOnlyHint: false },
  }, async (args) => {
    try {
      const denial = await chainGate(args as Record<string, unknown>);
      if (denial) return { content: [{ type: "text" as const, text: denial }], isError: true };
      const text = await handleWitnessAdapterStack(
        args as any, config, client,
      );
      trackProcedure(sessionState, "AI-MDL.6");
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  // --- Skill & Memory Attestation Tools ---

  server.registerTool("attest_skill_manifest", {
    description:
      "Attest the active skill/tool/plugin manifest (AI-SKILL.1). " +
      "Records which capabilities are loaded. " +
      "Evidence only -- never blocks execution." +
      (config.demo ? " Currently in DEMO mode -- anchors are minted locally." : ""),
    inputSchema: {
      skills: z.array(z.object({
        name: z.string().describe("Skill name"),
        version: z.string().optional().describe("Skill version"),
        hash: z.string().optional().describe("SHA-256 hash of skill definition"),
      })).describe("List of active skills/tools/plugins"),
      expected_manifest_hash: z.string().optional().describe("Expected manifest hash for verification"),
      agent_id: z.string().optional().describe("Agent identity"),
      cycle_id: z.string().optional().describe("Multi-agent chain link identifier"),
      clearing_level: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]).optional()
        .describe("Data clearing level"),
    },
    annotations: { readOnlyHint: false },
  }, async (args) => {
    try {
      const denial = await chainGate(args as Record<string, unknown>);
      if (denial) return { content: [{ type: "text" as const, text: denial }], isError: true };
      const text = await handleAttestSkillManifest(
        args as any, config, client,
      );
      trackProcedure(sessionState, "AI-SKILL.1");
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  server.registerTool("attest_memory_context", {
    description:
      "Attest persistent memory sources influencing decisions (AI-SKILL.2). " +
      "Records which memory stores (vector DBs, conversation history, etc.) are active. " +
      "Evidence only -- never blocks execution." +
      (config.demo ? " Currently in DEMO mode -- anchors are minted locally." : ""),
    inputSchema: {
      memory_sources: z.array(z.object({
        type: z.string().describe("Memory source type (vector_store, conversation, scratchpad, knowledge_base)"),
        id: z.string().optional().describe("Source identifier"),
        hash: z.string().optional().describe("SHA-256 hash of memory contents"),
      })).describe("List of active memory sources"),
      agent_id: z.string().optional().describe("Agent identity"),
      cycle_id: z.string().optional().describe("Multi-agent chain link identifier"),
      clearing_level: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]).optional()
        .describe("Data clearing level"),
    },
    annotations: { readOnlyHint: false },
  }, async (args) => {
    try {
      const denial = await chainGate(args as Record<string, unknown>);
      if (denial) return { content: [{ type: "text" as const, text: denial }], isError: true };
      const text = await handleAttestMemoryContext(
        args as any, config, client,
      );
      trackProcedure(sessionState, "AI-SKILL.2");
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  server.registerTool("verify_agent_trust", {
    description:
      "Verify a counterpart agent's compliance posture before exchanging data or calling their tools (AI-TRUST.1). " +
      "Checks: deny list, tenant trust, anchor freshness, signing status. " +
      "Returns trust level (denied/basic/verified/attested/sovereign). " +
      "Both PASS and FAIL produce cryptographic evidence anchors." +
      (config.demo ? " Currently in DEMO mode -- anchors are minted locally." : ""),
    inputSchema: {
      counterpart_agent_id: z.string().describe("Agent ID of the counterpart to verify"),
      counterpart_tenant_id: z.string().describe("Tenant ID of the counterpart agent"),
      anchor_fingerprint: z.string().describe("Counterpart's latest SWT3 anchor fingerprint (12 hex chars)"),
      anchor_timestamp_ms: z.number().optional().describe("When the counterpart's anchor was minted (ms since epoch)"),
      is_signed: z.boolean().optional().describe("Whether the counterpart's anchor carries a payload signature"),
      procedures: z.array(z.string()).optional().describe("UCT procedures the counterpart has witnessed"),
      clearing_level: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]).optional()
        .describe("Counterpart's clearing level"),
      has_hardware_attestation: z.boolean().optional().describe("Counterpart has AI-HW.1 hardware attestation"),
      has_guardrails: z.boolean().optional().describe("Counterpart has active guardrails"),
      agent_id: z.string().optional().describe("This agent's identity"),
      cycle_id: z.string().optional().describe("Multi-agent chain link identifier"),
    },
    annotations: { readOnlyHint: false },
  }, async (args) => {
    try {
      const text = await handleVerifyAgentTrust(
        args as any, config, client, sessionState,
      );
      trackProcedure(sessionState, "AI-TRUST.1");
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  server.registerTool("present_trust_credential", {
    description:
      "Get this agent's trust credential for presentation to another agent. " +
      "Returns agent_id, tenant_id, anchor fingerprint, and trust metadata. " +
      "Pass these fields to another agent's verify_agent_trust tool " +
      "to establish mutual compliance trust before exchanging data.",
    inputSchema: {
      agent_id: z.string().optional().describe("Override agent identity for this credential"),
    },
    annotations: { readOnlyHint: true },
  }, async (args) => {
    try {
      const text = handlePresentCredential(args as any, config);
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  // --- Agent Lifecycle Tools (PPA #23) ---

  server.registerTool("witness_resource_consumption", {
    description:
      "Witness resource consumption for an AI operation (AI-COST.1). " +
      "Records token usage, API call counts, and estimated cost as compliance evidence. " +
      "Evidence layer only -- values are self-reported, not verified.",
    inputSchema: {
      token_count: z.number().describe("Total tokens consumed (input + output)"),
      api_calls: z.number().describe("Number of API calls made"),
      estimated_cost: z.string().describe("Estimated cost as string (e.g. '0.0042')"),
      budget_threshold: z.string().optional().describe("Budget limit as string"),
      cost_anomaly: z.boolean().optional().describe("Whether this consumption is anomalous"),
      resource_attribution_id: z.string().optional().describe("Cost attribution identifier"),
      consumption_window_seconds: z.number().optional().describe("Time window for this consumption"),
      model_id: z.string().optional().describe("Model identifier"),
    },
  }, async (args) => {
    try {
      const fa = args.token_count as number;
      const fb = args.api_calls as number;
      const fc = parseFloat(args.estimated_cost as string) || 0;
      const [ts, epoch] = timestampMs();
      const fp = mintFingerprint(config.tenantId, "AI-COST.1", fa, fb, fc, ts);
      const payload: Record<string, unknown> = {
        procedure_id: "AI-COST.1", factor_a: fa, factor_b: fb, factor_c: fc,
        clearing_level: config.clearingLevel,
        anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
        witness_source: "mcp",
        ...(config.agentId ? { agent_id: config.agentId } : {}),
        ...(config.signingKey ? { payload_signature: signPayload(config.signingKey, fp, config.agentId) } : {}),
      };
      if (!config.demo) await client.postWitness(payload);
      const text = `Witnessed resource consumption: ${fa} tokens, ${fb} API calls, $${args.estimated_cost}\nAnchor: ${fp}${config.demo ? " (demo mode -- not persisted)" : ""}`;
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return { content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }], isError: true };
    }
  });

  server.registerTool("witness_delegation", {
    description:
      "Witness a delegation tree node (AI-DEL.1). " +
      "Records authority delegation structure between agents: scope, depth, TTL, " +
      "and whether cascade revocation and sub-delegation are permitted.",
    inputSchema: {
      scope_hash: z.string().describe("SHA-256 of the permission/scope manifest"),
      delegation_depth: z.number().describe("Hops from original human authorization"),
      ttl_seconds: z.number().describe("Seconds until delegation expires (0 = unbounded)"),
      parent_agent_id: z.string().describe("Delegating agent identifier"),
      child_agent_id: z.string().describe("Receiving agent identifier"),
      delegated_capabilities: z.array(z.string()).optional().describe("Delegated capability names"),
      cascade_revocation: z.boolean().optional().describe("Whether revoking parent revokes children"),
      sub_delegation_allowed: z.boolean().optional().describe("Whether child can further delegate"),
    },
  }, async (args) => {
    try {
      const { sha256Hex } = await import("./fingerprint.js");
      const fa = args.scope_hash ? (parseInt(sha256Hex(args.scope_hash as string, 8), 16) >>> 0) : 0;
      const fb = args.delegation_depth as number;
      const fc = args.ttl_seconds as number;
      const [ts, epoch] = timestampMs();
      const fp = mintFingerprint(config.tenantId, "AI-DEL.1", fa, fb, fc, ts);
      const payload: Record<string, unknown> = {
        procedure_id: "AI-DEL.1", factor_a: fa, factor_b: fb, factor_c: fc,
        clearing_level: config.clearingLevel,
        anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
        witness_source: "mcp",
        ...(config.agentId ? { agent_id: config.agentId } : {}),
        ...(config.signingKey ? { payload_signature: signPayload(config.signingKey, fp, config.agentId) } : {}),
      };
      if (!config.demo) await client.postWitness(payload);
      const text = `Witnessed delegation: ${args.parent_agent_id} -> ${args.child_agent_id}, depth=${fb}, TTL=${fc}s\nAnchor: ${fp}${config.demo ? " (demo mode -- not persisted)" : ""}`;
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return { content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }], isError: true };
    }
  });

  server.registerTool("witness_capability_attestation", {
    description:
      "Witness an agent's capability manifest (AI-CAP.1). " +
      "Records declared vs observed capabilities with drift detection " +
      "and autonomy level binding.",
    inputSchema: {
      manifest_hash: z.string().describe("SHA-256 of the capability manifest"),
      capability_count: z.number().describe("Number of declared capabilities"),
      autonomy_level: z.number().describe("Agent autonomy level (0-3)"),
      declared_capabilities: z.array(z.string()).optional().describe("Capabilities the agent claims"),
      observed_capabilities: z.array(z.string()).optional().describe("Capabilities actually exercised"),
      drift_detected: z.boolean().optional().describe("Whether declared/observed diverge"),
      hitl_required: z.boolean().optional().describe("Whether human-in-the-loop is required"),
    },
  }, async (args) => {
    try {
      const { sha256Hex } = await import("./fingerprint.js");
      const fa = args.manifest_hash ? (parseInt(sha256Hex(args.manifest_hash as string, 8), 16) >>> 0) : 0;
      const fb = args.capability_count as number;
      const fc = args.autonomy_level as number;
      const [ts, epoch] = timestampMs();
      const fp = mintFingerprint(config.tenantId, "AI-CAP.1", fa, fb, fc, ts);
      const payload: Record<string, unknown> = {
        procedure_id: "AI-CAP.1", factor_a: fa, factor_b: fb, factor_c: fc,
        clearing_level: config.clearingLevel,
        anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
        witness_source: "mcp",
        ...(config.agentId ? { agent_id: config.agentId } : {}),
        ...(config.signingKey ? { payload_signature: signPayload(config.signingKey, fp, config.agentId) } : {}),
      };
      if (!config.demo) await client.postWitness(payload);
      const text = `Witnessed capability attestation: ${fb} capabilities, autonomy level ${fc}${args.drift_detected ? ", DRIFT DETECTED" : ""}\nAnchor: ${fp}${config.demo ? " (demo mode -- not persisted)" : ""}`;
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return { content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }], isError: true };
    }
  });

  server.registerTool("witness_autonomy_transition", {
    description:
      "Witness an agent autonomy level transition (AI-AUTO.3). " +
      "Records when an agent's autonomy level changes (promotion or demotion). " +
      "Levels 0-3 parallel clearing levels.",
    inputSchema: {
      from_level: z.number().describe("Previous autonomy level (0-3)"),
      to_level: z.number().describe("New autonomy level (0-3)"),
      trigger_type: z.string().describe("What caused the transition (e.g. risk, policy, manual, scheduled)"),
      justification: z.string().optional().describe("Human-readable reason for the transition"),
      risk_score: z.number().optional().describe("Risk score that triggered the transition"),
      hitl_checkpoint: z.boolean().optional().describe("Whether a HITL checkpoint was required"),
    },
  }, async (args) => {
    try {
      const { sha256Hex } = await import("./fingerprint.js");
      const fa = args.from_level as number;
      const fb = args.to_level as number;
      const trigger = (args.trigger_type as string).toLowerCase();
      const fc = parseInt(sha256Hex(trigger, 4), 16) % 65536;
      const [ts, epoch] = timestampMs();
      const fp = mintFingerprint(config.tenantId, "AI-AUTO.3", fa, fb, fc, ts);
      const payload: Record<string, unknown> = {
        procedure_id: "AI-AUTO.3", factor_a: fa, factor_b: fb, factor_c: fc,
        clearing_level: config.clearingLevel,
        anchor_fingerprint: fp, anchor_epoch: epoch, fingerprint_timestamp_ms: ts,
        witness_source: "mcp",
        ...(config.agentId ? { agent_id: config.agentId } : {}),
        ...(config.signingKey ? { payload_signature: signPayload(config.signingKey, fp, config.agentId) } : {}),
      };
      if (!config.demo) await client.postWitness(payload);
      const direction = fb > fa ? "promotion" : fb < fa ? "demotion" : "lateral";
      const text = `Witnessed autonomy ${direction}: level ${fa} -> ${fb} (trigger: ${trigger})\nAnchor: ${fp}${config.demo ? " (demo mode -- not persisted)" : ""}`;
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return { content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }], isError: true };
    }
  });

  // --- Resources ---

  server.registerResource(
    REGISTRY_RESOURCE.name,
    REGISTRY_RESOURCE.uri,
    { mimeType: REGISTRY_RESOURCE.mimeType, description: REGISTRY_RESOURCE.description },
    async () => ({
      contents: [
        {
          uri: REGISTRY_RESOURCE.uri,
          mimeType: REGISTRY_RESOURCE.mimeType,
          text: await readRegistry(client),
        },
      ],
    }),
  );

  server.registerResource(
    HEALTH_RESOURCE.name,
    HEALTH_RESOURCE.uri,
    { mimeType: HEALTH_RESOURCE.mimeType, description: HEALTH_RESOURCE.description },
    async () => ({
      contents: [
        {
          uri: HEALTH_RESOURCE.uri,
          mimeType: HEALTH_RESOURCE.mimeType,
          text: await readHealth(client),
        },
      ],
    }),
  );

  // Graceful shutdown hook for Redis reader
  process.on("SIGTERM", () => { stopRedisReader(); });
  process.on("SIGINT", () => { stopRedisReader(); });

  return server;
}
