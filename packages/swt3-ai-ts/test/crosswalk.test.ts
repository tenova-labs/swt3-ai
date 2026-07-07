import { describe, it, expect } from "vitest";
import {
  resolve,
  resolveFramework,
  frameworks,
  procedures,
  crosswalkVersion,
} from "../src/crosswalk.js";

describe("resolve", () => {
  it("resolves a known procedure", () => {
    const result = resolve("AI-FAIR.1");
    expect(typeof result).toBe("object");
    expect(Object.keys(result).length).toBeGreaterThan(0);
    expect(result["EU-AI-ACT"]).toBeDefined();
  });

  it("returns empty dict for unknown procedure", () => {
    expect(resolve("FAKE-PROC.99")).toEqual({});
  });

  it("returns a copy (mutation-safe)", () => {
    const r1 = resolve("AI-FAIR.1");
    (r1 as any)["INJECTED"] = "bad";
    const r2 = resolve("AI-FAIR.1");
    expect(r2).not.toHaveProperty("INJECTED");
  });

  it("all values are strings", () => {
    const result = resolve("AI-FAIR.1");
    for (const [fw, ref] of Object.entries(result)) {
      expect(typeof fw).toBe("string");
      expect(typeof ref).toBe("string");
    }
  });

  it("resolves multiple procedures", () => {
    for (const proc of ["AI-INF.1", "AI-GOV.1", "AI-TRANS.1"]) {
      const result = resolve(proc);
      expect(Object.keys(result).length).toBeGreaterThan(0);
    }
  });
});

describe("resolveFramework", () => {
  it("resolves a known framework", () => {
    const result = resolveFramework("EU-AI-ACT");
    expect(typeof result).toBe("object");
    expect(Object.keys(result).length).toBeGreaterThan(0);
  });

  it("returns empty dict for unknown framework", () => {
    expect(resolveFramework("FAKE-FRAMEWORK")).toEqual({});
  });

  it("values are arrays of strings", () => {
    const result = resolveFramework("EU-AI-ACT");
    for (const [, procs] of Object.entries(result)) {
      expect(Array.isArray(procs)).toBe(true);
      for (const p of procs) {
        expect(typeof p).toBe("string");
      }
    }
  });

  it("returns a copy (mutation-safe)", () => {
    const r1 = resolveFramework("EU-AI-ACT");
    const firstKey = Object.keys(r1)[0];
    r1[firstKey].push("INJECTED");
    const r2 = resolveFramework("EU-AI-ACT");
    expect(r2[firstKey]).not.toContain("INJECTED");
  });
});

describe("metadata", () => {
  it("frameworks returns all known", () => {
    const result = frameworks();
    expect(Object.keys(result).length).toBeGreaterThan(10);
  });

  it("procedures returns all known", () => {
    const result = procedures();
    expect(Object.keys(result).length).toBeGreaterThan(50);
  });

  it("crosswalkVersion is ISO timestamp", () => {
    const v = crosswalkVersion();
    expect(typeof v).toBe("string");
    expect(v).toContain("T");
  });
});
