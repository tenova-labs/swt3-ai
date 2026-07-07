/**
 * SWT3 MCP Server — list_procedures tool.
 *
 * Lists available UCT procedures from the registry with optional
 * namespace filtering. Registry is fetched from the endpoint and
 * cached in memory (1 hour TTL).
 */

import type { AxiomClient } from "../client.js";
import type { McpConfig } from "../config.js";

interface ProceduresArgs {
  namespace?: string;
  framework?: string;
}

interface RegistryEntry {
  procedure_id: string;
  title?: string;
  parent_control?: string;
  category?: string;
  factors?: {
    factor_a?: { label?: string; description?: string };
    factor_b?: { label?: string; description?: string };
    factor_c?: { label?: string; description?: string };
  };
  frameworks?: Record<string, string>;
}

let registryCache: Record<string, RegistryEntry> | null = null;
let cacheTimestamp = 0;
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

async function getRegistry(client: AxiomClient): Promise<Record<string, RegistryEntry>> {
  const now = Date.now();
  if (registryCache && now - cacheTimestamp < CACHE_TTL_MS) {
    return registryCache;
  }

  const raw = await client.fetchRegistry();
  registryCache = raw as unknown as Record<string, RegistryEntry>;
  cacheTimestamp = now;
  return registryCache;
}

export async function handleProcedures(
  args: ProceduresArgs,
  _config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const registry = await getRegistry(client);
  const entries = Object.values(registry);

  let filtered = entries;
  if (args.namespace) {
    filtered = filtered.filter((e) =>
      e.procedure_id?.toUpperCase().startsWith(args.namespace!.toUpperCase()),
    );
  }
  if (args.framework) {
    const fw = args.framework.toUpperCase();
    filtered = filtered.filter((e) => {
      if (!e.frameworks) return false;
      return Object.keys(e.frameworks).some((k) => k.toUpperCase().includes(fw));
    });
  }

  if (filtered.length === 0) {
    const filters = [args.namespace && `namespace '${args.namespace}'`, args.framework && `framework '${args.framework}'`].filter(Boolean).join(" and ");
    return `No procedures found for ${filters || "registry"}.`;
  }

  const lines = filtered.map((e) => {
    const parts = [`${e.procedure_id}: ${e.title || "Untitled"}`];
    if (e.factors) {
      const fa = e.factors.factor_a;
      const fb = e.factors.factor_b;
      const fc = e.factors.factor_c;
      if (fa?.label) parts.push(`  Factor A: ${fa.label}${fa.description ? ` — ${fa.description}` : ""}`);
      if (fb?.label) parts.push(`  Factor B: ${fb.label}${fb.description ? ` — ${fb.description}` : ""}`);
      if (fc?.label) parts.push(`  Factor C: ${fc.label}${fc.description ? ` — ${fc.description}` : ""}`);
    }
    if (args.framework && e.frameworks) {
      const fwEntries = Object.entries(e.frameworks).filter(([k]) => k.toUpperCase().includes(args.framework!.toUpperCase()));
      for (const [k, v] of fwEntries) {
        parts.push(`  ${k}: ${v}`);
      }
    }
    return parts.join("\n");
  });

  const filters = [args.namespace && `namespace ${args.namespace.toUpperCase()}`, args.framework && `framework ${args.framework}`].filter(Boolean);
  const header = filters.length
    ? `UCT Procedures (${filters.join(", ")}): ${filtered.length} found`
    : `UCT Procedures: ${filtered.length} total`;

  return `${header}\n${"─".repeat(50)}\n${lines.join("\n\n")}`;
}
