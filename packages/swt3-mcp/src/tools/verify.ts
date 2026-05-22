/**
 * SWT3 MCP Server — verify_anchor tool.
 *
 * Verifies the cryptographic integrity of an existing SWT3 anchor.
 */

import type { AxiomClient } from "../client.js";
import type { McpConfig } from "../config.js";

interface VerifyArgs {
  token: string;
}

export async function handleVerify(
  args: VerifyArgs,
  _config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  if (!args.token.startsWith("SWT3-")) {
    return "Error: Token must start with 'SWT3-'";
  }

  const result = await client.verifyAnchor(args.token);

  const lines = [
    `Verified: ${result.verified ? "YES" : "NO"}`,
    `Status: ${result.status}`,
  ];

  if (result.claimed_fingerprint) {
    lines.push(`Claimed Fingerprint: ${result.claimed_fingerprint}`);
  }
  if (result.recomputed_fingerprint) {
    lines.push(`Recomputed Fingerprint: ${result.recomputed_fingerprint}`);
  }
  if (result.inputs) {
    lines.push(`Inputs: ${JSON.stringify(result.inputs, null, 2)}`);
  }

  return lines.join("\n");
}
