/**
 * SWT3 MCP Server -- crosswalk tools.
 *
 * Offline regulatory crosswalk resolution using the bundled crosswalks.json
 * from @tenova/swt3-ai. Zero network calls.
 */

import {
  resolve,
  resolveFramework,
  crosswalkFrameworks as frameworks,
  crosswalkProcedures as procedures,
  crosswalkVersion,
} from "@tenova/swt3-ai";
import type { SessionState } from "../state.js";

interface ResolveArgs {
  procedure_id?: string;
  framework_id?: string;
}

interface CoverageArgs {
  framework: string;
}

/**
 * Resolve crosswalk mappings for a procedure or framework.
 * If procedure_id is given, returns all framework controls it satisfies.
 * If framework_id is given, returns all requirement-to-procedure mappings.
 * If neither is given, returns a summary of all available frameworks.
 */
export function handleResolveCrosswalk(args: ResolveArgs): string {
  if (args.procedure_id) {
    const mappings = resolve(args.procedure_id);
    const keys = Object.keys(mappings);
    if (keys.length === 0) {
      return `No crosswalk mappings found for procedure "${args.procedure_id}".`;
    }
    const lines = keys.map((fw) => `  ${fw}: ${mappings[fw]}`);
    return `Crosswalk for ${args.procedure_id} (${keys.length} frameworks):\n${lines.join("\n")}\n\nData version: ${crosswalkVersion()}`;
  }

  if (args.framework_id) {
    const mappings = resolveFramework(args.framework_id);
    const keys = Object.keys(mappings);
    if (keys.length === 0) {
      return `No crosswalk mappings found for framework "${args.framework_id}". Use resolve_crosswalk with no arguments to see available frameworks.`;
    }
    const lines = keys.map((req) => {
      const procs = mappings[req];
      return `  ${req}: ${procs.join(", ")}`;
    });
    return `Framework ${args.framework_id} (${keys.length} requirements mapped):\n${lines.join("\n")}\n\nData version: ${crosswalkVersion()}`;
  }

  // No args: list available frameworks
  const fws = frameworks();
  const lines = Object.entries(fws).map(([id, meta]) => {
    const parts = [`  ${id}: ${meta.name}`];
    if (meta.procedure_count) parts[0] += ` (${meta.procedure_count} procedures)`;
    if (meta.enforcement_date) parts.push(`    Enforcement: ${meta.enforcement_date}`);
    return parts.join("\n");
  });
  return `Available frameworks (${Object.keys(fws).length}):\n${lines.join("\n")}\n\nData version: ${crosswalkVersion()}`;
}

/**
 * Report framework coverage for procedures witnessed in the current session.
 * Uses the audit session's proceduresWitnessed list to compute coverage.
 */
export function handleCoverageReport(
  args: CoverageArgs,
  sessionState: SessionState,
): string {
  const fw = args.framework;
  const fwMeta = frameworks()[fw];
  if (!fwMeta) {
    const available = Object.keys(frameworks()).join(", ");
    return `Unknown framework "${fw}". Available: ${available}`;
  }

  // Get all procedures that map to this framework
  const allProcs = procedures();
  const requiredProcedures: string[] = [];
  for (const [procId, meta] of Object.entries(allProcs)) {
    if (meta.frameworks[fw]) {
      requiredProcedures.push(procId);
    }
  }

  if (requiredProcedures.length === 0) {
    return `Framework "${fw}" has no mapped procedures in the crosswalk data.`;
  }

  // Compare against session
  const witnessed = new Set(
    sessionState.activeAuditSession?.proceduresWitnessed ?? [],
  );
  const covered = requiredProcedures.filter((p) => witnessed.has(p));
  const remaining = requiredProcedures.filter((p) => !witnessed.has(p));
  const score = Math.round((covered.length / requiredProcedures.length) * 100);

  const lines: string[] = [
    `Framework Coverage: ${fw} (${fwMeta.name})`,
    `${"─".repeat(50)}`,
    `Score: ${score}% (${covered.length}/${requiredProcedures.length} procedures)`,
    ``,
  ];

  if (covered.length > 0) {
    lines.push(`Covered (${covered.length}):`);
    for (const p of covered.sort()) {
      const req = allProcs[p]?.frameworks[fw] || "";
      lines.push(`  [x] ${p} -> ${req}`);
    }
    lines.push(``);
  }

  if (remaining.length > 0) {
    lines.push(`Remaining (${remaining.length}):`);
    for (const p of remaining.sort()) {
      const req = allProcs[p]?.frameworks[fw] || "";
      lines.push(`  [ ] ${p} -> ${req}`);
    }
  }

  if (!sessionState.activeAuditSession) {
    lines.push(``);
    lines.push(`Note: No active audit session. Use start_audit_session first to track witnessed procedures.`);
  }

  return lines.join("\n");
}
