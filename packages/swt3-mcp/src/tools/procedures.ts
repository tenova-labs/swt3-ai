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

  const filtered = args.namespace
    ? entries.filter((e) =>
        e.procedure_id?.toUpperCase().startsWith(args.namespace!.toUpperCase()),
      )
    : entries;

  if (filtered.length === 0) {
    return args.namespace
      ? `No procedures found for namespace '${args.namespace}'.`
      : "No procedures found in registry.";
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
    return parts.join("\n");
  });

  const header = args.namespace
    ? `UCT Procedures (${args.namespace.toUpperCase()}): ${filtered.length} found`
    : `UCT Procedures: ${filtered.length} total`;

  return `${header}\n${"─".repeat(50)}\n${lines.join("\n\n")}`;
}
