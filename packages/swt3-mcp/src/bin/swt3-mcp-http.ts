#!/usr/bin/env node
/**
 * SWT3 MCP Server -- Streamable HTTP entry point.
 *
 * Serves the full SWT3 MCP server over HTTP for remote MCP clients
 * (Meta Muse, Claude Desktop, custom integrations).
 *
 * Stateless mode: each POST creates a fresh server+transport pair.
 * No session state to hijack. No in-memory state between requests.
 *
 * Zero-config start (demo mode):
 *   npx @tenova/swt3-mcp-http
 *
 * With API key:
 *   SWT3_API_KEY=axm_live_... npx @tenova/swt3-mcp-http
 *
 * Custom port:
 *   SWT3_MCP_PORT=3200 npx @tenova/swt3-mcp-http
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { createServer as createHttpServer } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { loadConfig } from "../config.js";
import { createServer } from "../server.js";

const PORT = parseInt(process.env.SWT3_MCP_PORT || "3100", 10);
const HOST = "127.0.0.1";

const bundle = loadConfig();
const mcpConfig = bundle.config;

if (mcpConfig.demo) {
  process.stderr.write(
    "swt3-mcp-http: running in demo mode (local-only anchors)\n" +
    "swt3-mcp-http: set SWT3_API_KEY to connect to the ledger\n",
  );
}

const httpServer = createHttpServer(async (req, res) => {
  // CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, GET, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, mcp-session-id",
      "Access-Control-Max-Age": "86400",
    });
    res.end();
    return;
  }

  // Health check
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", transport: "streamable-http", tools: 68 }));
    return;
  }

  // MCP endpoint: POST /mcp
  if (req.method === "POST" && (req.url === "/mcp" || req.url === "/")) {
    // Set CORS headers on all MCP responses
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Expose-Headers", "mcp-session-id");

    const server = createServer(mcpConfig, bundle);

    try {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined, // stateless
      });

      await server.connect(transport);

      // Parse body
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
      }
      const body = JSON.parse(Buffer.concat(chunks).toString("utf-8"));

      await transport.handleRequest(req, res, body);

      res.on("close", () => {
        transport.close().catch(() => {});
        server.close().catch(() => {});
      });
    } catch (err) {
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        }));
      }
      server.close().catch(() => {});
    }
    return;
  }

  // GET /mcp and DELETE /mcp -- method not allowed (stateless mode)
  if ((req.method === "GET" || req.method === "DELETE") && (req.url === "/mcp" || req.url === "/")) {
    res.writeHead(405, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Method not allowed." },
      id: null,
    }));
    return;
  }

  // 404 for everything else
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});

httpServer.listen(PORT, HOST, () => {
  process.stderr.write(
    `swt3-mcp-http: listening on http://${HOST}:${PORT}/mcp\n` +
    `swt3-mcp-http: health check at http://${HOST}:${PORT}/health\n`,
  );
});

// Graceful shutdown
function shutdown() {
  process.stderr.write("swt3-mcp-http: shutting down...\n");
  httpServer.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
