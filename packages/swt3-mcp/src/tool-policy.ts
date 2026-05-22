/**
 * SWT3 MCP Server -- Tool Policy Enforcement.
 *
 * Evaluates MCP tool policy rules (witnessed, exempt, blocked)
 * and chain density checks (velocity, depth, allowlist, blocklist).
 *
 * Patent pending.
 */

import type { McpToolPolicy } from "./config.js";

/**
 * Match a tool name against a glob pattern list.
 * Supports * (any chars) and ? (single char).
 */
export function matchesToolPattern(toolName: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    const regex = new RegExp(
      "^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, ".*")
        .replace(/\?/g, ".") + "$",
    );
    if (regex.test(toolName)) return true;
  }
  return false;
}

export interface ChainDensityState {
  velocityWindow: number[];
  velocityLimit: number;
  velocityWindowMs: number;
  chainDepth: number;
  maxChainDepth: number;
  lastToolName: string | null;
  blockPatterns: RegExp[];
  allowPatterns: RegExp[] | null;
  failSecure: boolean;
}

export function initChainDensity(policy: McpToolPolicy): ChainDensityState | null {
  if (!policy.maxVelocity && policy.maxChainDepth === undefined &&
      !policy.toolAllowlist?.length && !policy.toolBlocklist?.length) {
    return null;
  }
  let velocityLimit = 0, velocityWindowMs = 0;
  if (policy.maxVelocity) {
    const parts = policy.maxVelocity.split("/");
    velocityLimit = parseInt(parts[0], 10);
    velocityWindowMs = parseInt(parts[1].replace("s", ""), 10) * 1000;
  }
  const toRegex = (p: string) => new RegExp(
    "^" + p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$",
  );
  return {
    velocityWindow: [],
    velocityLimit,
    velocityWindowMs,
    chainDepth: 0,
    maxChainDepth: policy.maxChainDepth ?? Infinity,
    lastToolName: null,
    blockPatterns: (policy.toolBlocklist ?? []).map(toRegex),
    allowPatterns: policy.toolAllowlist?.length ? policy.toolAllowlist.map(toRegex) : null,
    failSecure: policy.failSecure ?? true,
  };
}

export function checkChainDensity(state: ChainDensityState, toolName: string): string | null {
  const now = Date.now();
  // Blocklist
  for (const p of state.blockPatterns) {
    if (p.test(toolName)) return `Tool "${toolName}" is on the blocklist`;
  }
  // Allowlist
  if (state.allowPatterns && !state.allowPatterns.some((p) => p.test(toolName))) {
    return `Tool "${toolName}" is not on the allowlist`;
  }
  // Velocity
  if (state.velocityLimit > 0) {
    const cutoff = now - state.velocityWindowMs;
    while (state.velocityWindow.length > 0 && state.velocityWindow[0] <= cutoff) {
      state.velocityWindow.shift();
    }
    if (state.velocityWindow.length >= state.velocityLimit) {
      if (state.failSecure) return `Rate limit exceeded: ${state.velocityLimit} calls per ${state.velocityWindowMs / 1000}s`;
    }
    state.velocityWindow.push(now);
  }
  // Depth
  if (state.maxChainDepth < Infinity) {
    if (toolName !== state.lastToolName && state.lastToolName !== null) state.chainDepth = 0;
    state.chainDepth++;
    state.lastToolName = toolName;
    if (state.chainDepth > state.maxChainDepth) {
      if (state.failSecure) return `Chain depth ${state.chainDepth} exceeds max ${state.maxChainDepth}`;
    }
  }
  return null;
}

export type PolicyGateResult = "witness" | "exempt" | "block" | null;

/**
 * Evaluate the MCP tool policy gate for a given tool name.
 *
 * Returns:
 *   - "witness": tool must be auto-witnessed
 *   - "exempt": tool is explicitly exempt from witnessing
 *   - "block": tool blocked by trust level or chain density
 *   - null: no policy configured
 */
export function evaluateToolPolicy(
  toolName: string,
  mcpPolicy: McpToolPolicy | null,
  chainDensity: ChainDensityState | null,
  sessionTrustLevel?: number,
): PolicyGateResult {
  if (!mcpPolicy) return null;

  // Exempt tools always pass through unwatched
  if (mcpPolicy.exemptTools.length > 0 && matchesToolPattern(toolName, mcpPolicy.exemptTools)) {
    return "exempt";
  }

  // Check if tool matches witnessed patterns
  const isWitnessed = mcpPolicy.witnessedTools.length === 0
    || matchesToolPattern(toolName, mcpPolicy.witnessedTools);

  if (!isWitnessed) return "exempt";

  // Trust level gate
  if (mcpPolicy.requireTrustLevel > 0) {
    const trust = sessionTrustLevel ?? 0;
    if (trust < mcpPolicy.requireTrustLevel) {
      return "block";
    }
  }

  // Chain density enforcement
  if (chainDensity) {
    const violation = checkChainDensity(chainDensity, toolName);
    if (violation) return "block";
  }

  return mcpPolicy.autoWitness ? "witness" : "exempt";
}
