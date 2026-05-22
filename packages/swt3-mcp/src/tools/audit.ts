/**
 * SWT3 MCP Server: audit session tools.
 *
 * Passive compliance tracking for a conversation. Records which procedures
 * were witnessed and produces a gap report at session end.
 *
 * Never blocks execution. Purely observational.
 */

import { randomUUID } from "node:crypto";
import type { AxiomClient } from "../client.js";
import type { SessionState } from "../state.js";

export function handleStartAudit(state: SessionState): string {
  // Idempotent: return existing session if already active
  if (state.activeAuditSession) {
    return [
      `Audit session already active.`,
      `Session ID: ${state.activeAuditSession.sessionId}`,
      `Started: ${new Date(state.activeAuditSession.startedAt).toISOString()}`,
      `Procedures witnessed so far: ${state.activeAuditSession.proceduresWitnessed.length}`,
    ].join("\n");
  }

  const sessionId = randomUUID();
  state.activeAuditSession = {
    sessionId,
    startedAt: Date.now(),
    proceduresWitnessed: [],
  };

  return [
    `Audit session started.`,
    `Session ID: ${sessionId}`,
    ``,
    `All witness_inference and witness_authorization calls will be tracked.`,
    `Call end_audit_session when done to see a compliance gap report.`,
  ].join("\n");
}

export async function handleEndAudit(
  _args: { session_id?: string },
  state: SessionState,
  client: AxiomClient,
): Promise<string> {
  if (!state.activeAuditSession) {
    return "No audit session is active. Call start_audit_session first.";
  }

  const session = state.activeAuditSession;
  const durationMs = Date.now() - session.startedAt;
  const durationSec = Math.round(durationMs / 1000);
  const witnessed = [...new Set(session.proceduresWitnessed)];

  // Fetch AI procedures from registry for gap analysis
  let allAiProcedures: string[] = [];
  try {
    const registry = await client.fetchRegistry();
    const procedures = (registry as any)?.procedures ?? registry;
    if (Array.isArray(procedures)) {
      allAiProcedures = procedures
        .map((p: any) => p.procedure_id || p.id || "")
        .filter((id: string) => id.startsWith("AI-"));
    }
  } catch {
    // Registry unavailable -- report what we have
  }

  const gaps = allAiProcedures.filter((p) => !witnessed.includes(p));
  const coverage = allAiProcedures.length > 0
    ? Math.round((witnessed.filter(w => allAiProcedures.includes(w)).length / allAiProcedures.length) * 100)
    : 0;

  // Clear session
  state.activeAuditSession = null;

  const lines = [
    `Audit Session Complete`,
    `Session ID: ${session.sessionId}`,
    `Duration: ${durationSec}s`,
    ``,
    `Procedures Witnessed (${witnessed.length}):`,
  ];

  if (witnessed.length > 0) {
    for (const p of witnessed.sort()) {
      lines.push(`  [x] ${p}`);
    }
  } else {
    lines.push(`  (none)`);
  }

  if (allAiProcedures.length > 0) {
    lines.push(``);
    lines.push(`AI Procedures Not Witnessed (${gaps.length}):`);
    if (gaps.length > 0) {
      for (const p of gaps.sort()) {
        lines.push(`  [ ] ${p}`);
      }
    } else {
      lines.push(`  (full coverage)`);
    }
    lines.push(``);
    lines.push(`AI Procedure Coverage: ${coverage}%`);
  }

  return lines.join("\n");
}

/**
 * Track a procedure in the active audit session (if any).
 * Called from server.ts after witness/authorize tool calls.
 */
export function trackProcedure(state: SessionState, procedureId: string): void {
  if (state.activeAuditSession) {
    state.activeAuditSession.proceduresWitnessed.push(procedureId);
  }
}
