import { describe, it, expect, beforeEach } from "vitest";
import { queryAnchors, getReaderState } from "../src/redis-reader.js";

describe("redis-reader", () => {
  describe("queryAnchors (when reader not running)", () => {
    it("returns empty array when reader not started", () => {
      const result = queryAnchors("agent-1");
      expect(result).toEqual([]);
    });

    it("returns empty for cycle_id query when not running", () => {
      const result = queryAnchors(undefined, "cycle-abc");
      expect(result).toEqual([]);
    });

    it("returns empty for combined query when not running", () => {
      const result = queryAnchors("agent-1", "cycle-abc");
      expect(result).toEqual([]);
    });
  });

  describe("getReaderState (when not running)", () => {
    it("returns null when reader not started", () => {
      expect(getReaderState()).toBeNull();
    });
  });
});
