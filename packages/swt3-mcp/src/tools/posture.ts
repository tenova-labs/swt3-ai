/**
 * SWT3 MCP Server — check_posture tool.
 *
 * Returns the current AI witness posture for the tenant.
 */

import type { AxiomClient } from "../client.js";
import type { McpConfig } from "../config.js";

export async function handlePosture(
  _args: Record<string, never>,
  _config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  const posture = await client.getPosture();
  return JSON.stringify(posture, null, 2);
}
