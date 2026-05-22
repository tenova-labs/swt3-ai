/**
 * SWT3 MCP Server: session state.
 *
 * Ephemeral in-memory state for audit sessions and chain tracking.
 * Lost on restart by design -- sessions are conversation-scoped.
 */

import type { RedisReaderState } from "./redis-reader.js";

export interface SessionState {
  activeAuditSession: {
    sessionId: string;
    startedAt: number;
    proceduresWitnessed: string[];
  } | null;
  activeChain: {
    cycleId: string;
    description: string;
    startedAt: number;
  } | null;
  /** Tenant IDs trusted for this session (env + runtime additions). */
  trustedTenants: Set<string>;
  /** Agent IDs denied for this session. */
  deniedAgents: Set<string>;
  /** Last verified trust level from verify_agent_trust (null if no verification performed). */
  verifiedTrustLevel: number | null;
  /** Redis reader state (null if not configured or unavailable). */
  redisReader: RedisReaderState | null;
}

export function createSessionState(
  yamlTrustedTenants?: string[],
  yamlDeniedAgents?: string[],
): SessionState {
  // Seed trusted tenants from env var (comma-separated) + YAML
  const envTrusted = process.env.SWT3_TRUSTED_TENANTS?.split(",").map((s) => s.trim()).filter(Boolean) ?? [];
  const allTrusted = [...envTrusted, ...(yamlTrustedTenants ?? [])];

  return {
    activeAuditSession: null,
    activeChain: null,
    trustedTenants: new Set(allTrusted),
    deniedAgents: new Set(yamlDeniedAgents ?? []),
    verifiedTrustLevel: null,
    redisReader: null,
  };
}
