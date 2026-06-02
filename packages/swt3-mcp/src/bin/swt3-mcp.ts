#!/usr/bin/env node
/**
 * SWT3 MCP Server — CLI entry point.
 *
 * Zero-config start:
 *   npx @tenova/swt3-mcp
 *
 * With API key (tenant auto-resolved):
 *   SWT3_API_KEY=axm_live_... npx @tenova/swt3-mcp
 *
 * Full config:
 *   SWT3_API_KEY=axm_live_... SWT3_TENANT_ID=MY_ENCLAVE npx @tenova/swt3-mcp
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "../config.js";
import { createServer } from "../server.js";

try {
  const bundle = loadConfig();
  const config = bundle.config;
  const server = createServer(config, bundle);
  const transport = new StdioServerTransport();

  if (config.demo) {
    process.stderr.write(
      "swt3-mcp: running in demo mode (local-only anchors)\n" +
      "swt3-mcp: use the signup tool to create a free account\n",
    );
  }

  await server.connect(transport);
} catch (err) {
  process.stderr.write(`swt3-mcp: ${(err as Error).message}\n`);
  process.exit(1);
}
