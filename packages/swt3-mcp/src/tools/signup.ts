/**
 * SWT3 MCP Server: signup tool.
 *
 * Directs the developer to the signup page without passing credentials
 * through the LLM context. Returns a URL. The developer completes
 * signup in their browser and copies the API key back.
 */

import type { McpConfig } from "../config.js";

export async function handleSignup(
  args: { framework?: string },
  config: McpConfig,
): Promise<string> {
  const framework = args.framework || "NIST-800-53";
  const signupUrl = `${config.endpoint}/signup?ref=mcp&framework=${encodeURIComponent(framework)}`;

  return [
    `Open this link to create your free account:`,
    ``,
    `  ${signupUrl}`,
    ``,
    `After signup, you'll see your API key (shown once, copy it).`,
    `Then add it to your MCP config:`,
    ``,
    `  "env": {`,
    `    "SWT3_API_KEY": "axm_open_..."`,
    `  }`,
    ``,
    `Restart your MCP client and the server switches to live mode automatically.`,
    ``,
    `SDKs available in 5 languages:`,
    `  Python:     pip install swt3-ai`,
    `  TypeScript: npm install @tenova/swt3-ai`,
    `  Rust:       cargo add swt3-ai`,
    `  C#:         dotnet add package swt3-ai`,
    `  Ruby:       gem install swt3-ai`,
  ].join("\n");
}
