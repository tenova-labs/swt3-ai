/**
 * SWT3 MCP Server — swt3://registry/procedures resource.
 *
 * Read-only resource providing the full UCT procedure catalog.
 */

import type { AxiomClient } from "../client.js";

let registryCache: string | null = null;
let cacheTimestamp = 0;
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

export const REGISTRY_RESOURCE = {
  uri: "swt3://registry/procedures",
  name: "UCT Procedure Registry",
  description:
    "Full catalog of Universal Control Taxonomy (UCT) procedures. " +
    "Each procedure defines a compliance control with factor schemas, " +
    "evaluation logic, and framework mappings.",
  mimeType: "application/json",
};

export async function readRegistry(client: AxiomClient): Promise<string> {
  const now = Date.now();
  if (registryCache && now - cacheTimestamp < CACHE_TTL_MS) {
    return registryCache;
  }

  const registry = await client.fetchRegistry();
  registryCache = JSON.stringify(registry, null, 2);
  cacheTimestamp = now;
  return registryCache;
}
