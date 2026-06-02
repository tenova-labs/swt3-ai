/**
 * SWT3 MCP Server — swt3://health resource.
 *
 * Read-only resource providing service health status.
 */

import type { AxiomClient } from "../client.js";

export const HEALTH_RESOURCE = {
  uri: "swt3://health",
  name: "Service Health",
  description:
    "Current health status of the SWT3 witness endpoint including " +
    "uptime, database connectivity, and service version.",
  mimeType: "application/json",
};

export async function readHealth(client: AxiomClient): Promise<string> {
  const health = await client.getHealth();
  return JSON.stringify(health, null, 2);
}
