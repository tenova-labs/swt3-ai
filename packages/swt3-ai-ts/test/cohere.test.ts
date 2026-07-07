/**
 * Tests for the Cohere adapter (wrapCohere).
 */
import { describe, it, expect, vi } from "vitest";
import { wrapCohere } from "../src/adapters/cohere.js";
import { Witness } from "../src/witness.js";

function w() {
  return new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "TEST", clearingLevel: 1, disableFlush: true });
}

function mockCohereResponse() {
  return {
    message: { content: [{ text: "Hello!" }] },
    model: "command-r-plus",
    usage: { tokens: { input_tokens: 10, output_tokens: 5 } },
    meta: { model: "command-r-plus-08-2024" },
  };
}

describe("wrapCohere", () => {
  it("returns a proxy object", () => {
    const client = { chat: vi.fn() };
    const proxied = wrapCohere(client, w());
    expect(proxied).toBeDefined();
  });

  it("passes through non-wrapped attributes", () => {
    const client = { chat: vi.fn(), someAttr: "test" } as any;
    const proxied = wrapCohere(client, w()) as any;
    expect(proxied.someAttr).toBe("test");
  });

  it("intercepts chat() and returns response", async () => {
    const resp = mockCohereResponse();
    const client = { chat: vi.fn().mockResolvedValue(resp) };
    const proxied = wrapCohere(client, w());
    const result = await proxied.chat({ model: "command-r-plus", messages: [] });
    expect(result).toBe(resp);
    expect(client.chat).toHaveBeenCalledOnce();
  });
});
