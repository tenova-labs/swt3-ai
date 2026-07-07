/**
 * Tests for the Qdrant RAG witness adapter (wrapQdrant).
 */
import { describe, it, expect, vi } from "vitest";
import { wrapQdrant } from "../src/adapters/qdrant.js";
import { Witness } from "../src/witness.js";

function w() {
  return new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "TEST", clearingLevel: 1, disableFlush: true });
}

describe("wrapQdrant", () => {
  it("returns a proxy object", () => {
    const client = { search: vi.fn() };
    const proxied = wrapQdrant(client, w());
    expect(proxied).toBeDefined();
  });

  it("passes through non-wrapped attributes", () => {
    const client = { search: vi.fn(), collection: "docs" } as any;
    const proxied = wrapQdrant(client, w()) as any;
    expect(proxied.collection).toBe("docs");
  });

  it("intercepts search() and returns results", () => {
    const mockResults = [
      { id: 1, score: 0.95, payload: { text: "result 1" } },
      { id: 2, score: 0.85, payload: { text: "result 2" } },
    ];
    const client = { search: vi.fn().mockReturnValue(mockResults) };
    const proxied = wrapQdrant(client, w());
    const results = proxied.search({ collectionName: "docs", queryVector: [0.1, 0.2], limit: 5 });
    expect(results).toBe(mockResults);
    expect(client.search).toHaveBeenCalledOnce();
  });
});
