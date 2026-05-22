/**
 * @tenova/swt3-mcp — MCP Server for SWT3 AI Witness Protocol
 *
 * Provides tools for witnessing AI inferences, verifying anchors,
 * and browsing the UCT procedure registry via the Model Context Protocol.
 *
 * Usage (programmatic):
 *   import { createServer, loadConfig } from "@tenova/swt3-mcp";
 *   const server = createServer(loadConfig());
 *
 * Usage (CLI):
 *   SWT3_API_KEY=axm_live_... SWT3_TENANT_ID=MY_ENCLAVE npx @tenova/swt3-mcp
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

export { createServer } from "./server.js";
export { loadConfig } from "./config.js";
export type { McpConfig } from "./config.js";
