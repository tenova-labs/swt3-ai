import { describe, it, expect } from "vitest";
import { parseGateDict, parseMaxAge, validateProcedures, allProcedures, findGateFile, generateGateYaml, listFrameworks } from "../src/gate.js";
import type { GateConfig } from "../src/gate.js";

const COMPLETE_CONFIG = {
  version: "1.0",
  name: "Test Gate",
  strict: false,
  metadata: {
    generated_at: "2026-07-24T14:00:00Z",
    crosswalk_version: "1.0.0",
    baseline_hash: "e4f5a6b7c8d9",
  },
  models: {
    "credit-v3": { risk: "high" },
    "chatbot-v1": { risk: "low" },
  },
  defaults: {
    gates: [
      { procedure: "AI-LOG.1", required: true, description: "Logging" },
    ],
  },
  frameworks: {
    "eu-ai-act": {
      risk_class: "high-risk",
      crosswalk_hash: "a3b7c9d2e1f4",
      gates: [
        {
          group: "Article 10: Data Governance",
          procedures: [
            {
              procedure: "AI-FAIR.1",
              max_age: "7d",
              required: true,
              ref: "Art. 10(2)(f)",
              critical: true,
              description: "Bias testing",
              hint: "witness.witness_bias_detection()",
            },
          ],
        },
        {
          group: "Article 14: Human Oversight",
          procedures: [
            { procedure: "AI-HITL.1", max_age: "24h", required: true, ref: "Art. 14", critical: true },
          ],
        },
      ],
    },
    "sr-11-7": {
      gates: [
        {
          group: "Model Validation",
          procedures: [
            { procedure: "AI-FAIR.1", max_age: "30d", required: true },
          ],
        },
      ],
    },
  },
};

describe("parseGateDict", () => {
  it("parses complete config", () => {
    const cfg = parseGateDict(COMPLETE_CONFIG);
    expect(cfg.version).toBe("1.0");
    expect(cfg.name).toBe("Test Gate");
    expect(cfg.strict).toBe(false);
    expect(Object.keys(cfg.models)).toHaveLength(2);
    expect(cfg.models["credit-v3"].risk).toBe("high");
    expect(cfg.defaults?.gates).toHaveLength(1);
    expect(cfg.defaults?.gates[0].procedure).toBe("AI-LOG.1");
    expect(Object.keys(cfg.frameworks)).toHaveLength(2);
  });

  it("parses minimal config", () => {
    const cfg = parseGateDict({ version: "1.0" });
    expect(cfg.version).toBe("1.0");
    expect(cfg.name).toBeUndefined();
    expect(cfg.strict).toBe(false);
    expect(Object.keys(cfg.models)).toHaveLength(0);
    expect(cfg.defaults).toBeUndefined();
    expect(Object.keys(cfg.frameworks)).toHaveLength(0);
    expect(cfg.warnings).toHaveLength(0);
  });

  it("rejects missing version", () => {
    expect(() => parseGateDict({ name: "no version" })).toThrow("version");
  });

  it("parses strict flag", () => {
    const cfg = parseGateDict({ version: "1.0", strict: true });
    expect(cfg.strict).toBe(true);
  });

  it("passes through metadata", () => {
    const cfg = parseGateDict(COMPLETE_CONFIG);
    expect(cfg.metadata?.crosswalk_version).toBe("1.0.0");
    expect(cfg.metadata?.baseline_hash).toBe("e4f5a6b7c8d9");
  });
});

describe("framework parsing", () => {
  it("parses grouped gates", () => {
    const cfg = parseGateDict(COMPLETE_CONFIG);
    const eu = cfg.frameworks["eu-ai-act"];
    expect(eu.riskClass).toBe("high-risk");
    expect(eu.crosswalkHash).toBe("a3b7c9d2e1f4");
    expect(eu.gates).toHaveLength(2);
    expect(eu.gates[0].group).toBe("Article 10: Data Governance");
    expect(eu.gates[0].procedures[0].procedure).toBe("AI-FAIR.1");
    expect(eu.gates[0].procedures[0].critical).toBe(true);
  });

  it("wraps flat gates in unnamed group", () => {
    const cfg = parseGateDict({
      version: "1.0",
      frameworks: {
        "test-fw": {
          gates: [
            { procedure: "AI-INF.1", required: true },
            { procedure: "AI-GRD.1", required: false },
          ],
        },
      },
    });
    const fw = cfg.frameworks["test-fw"];
    expect(fw.gates).toHaveLength(1);
    expect(fw.gates[0].group).toBe("");
    expect(fw.gates[0].procedures).toHaveLength(2);
  });

  it("warns on empty framework", () => {
    const cfg = parseGateDict({
      version: "1.0",
      frameworks: { "empty-fw": {} },
    });
    expect(cfg.warnings.some(w => w.includes("empty-fw") && w.includes("no gates"))).toBe(true);
  });

  it("parses multi-framework", () => {
    const cfg = parseGateDict(COMPLETE_CONFIG);
    expect(cfg.frameworks["sr-11-7"].gates[0].procedures[0].maxAge).toBe("30d");
  });
});

describe("procedure parsing", () => {
  it("parses all fields", () => {
    const cfg = parseGateDict(COMPLETE_CONFIG);
    const fair = cfg.frameworks["eu-ai-act"].gates[0].procedures[0];
    expect(fair.procedure).toBe("AI-FAIR.1");
    expect(fair.required).toBe(true);
    expect(fair.maxAge).toBe("7d");
    expect(fair.maxAgeSeconds).toBe(604800);
    expect(fair.ref).toBe("Art. 10(2)(f)");
    expect(fair.critical).toBe(true);
    expect(fair.description).toBe("Bias testing");
    expect(fair.hint).toBe("witness.witness_bias_detection()");
  });

  it("parses must_not_exist", () => {
    const cfg = parseGateDict({
      version: "1.0",
      frameworks: {
        test: { gates: [{ procedure: "AI-REV.1", must_not_exist: true }] },
      },
    });
    expect(cfg.frameworks.test.gates[0].procedures[0].mustNotExist).toBe(true);
  });

  it("skips entries without procedure field", () => {
    const cfg = parseGateDict({
      version: "1.0",
      frameworks: {
        test: {
          gates: [
            { required: true },
            { procedure: "AI-INF.1", required: true },
          ],
        },
      },
    });
    expect(cfg.frameworks.test.gates[0].procedures).toHaveLength(1);
    expect(cfg.frameworks.test.gates[0].procedures[0].procedure).toBe("AI-INF.1");
  });
});

describe("parseMaxAge", () => {
  it("parses days", () => {
    expect(parseMaxAge("7d")).toBe(604800);
    expect(parseMaxAge("1d")).toBe(86400);
    expect(parseMaxAge("30d")).toBe(2592000);
    expect(parseMaxAge("90d")).toBe(7776000);
  });

  it("parses hours", () => {
    expect(parseMaxAge("24h")).toBe(86400);
    expect(parseMaxAge("1h")).toBe(3600);
  });

  it("parses minutes", () => {
    expect(parseMaxAge("30m")).toBe(1800);
  });

  it("is case insensitive", () => {
    expect(parseMaxAge("7D")).toBe(604800);
    expect(parseMaxAge("24H")).toBe(86400);
  });

  it("handles whitespace", () => {
    expect(parseMaxAge(" 7d ")).toBe(604800);
  });

  it("rejects invalid format", () => {
    expect(() => parseMaxAge("7 days")).toThrow("Invalid max_age");
  });

  it("rejects invalid unit", () => {
    expect(() => parseMaxAge("7w")).toThrow("Invalid max_age");
  });
});

describe("unknown fields", () => {
  it("warns on unknown top-level keys", () => {
    const cfg = parseGateDict({
      version: "1.0",
      unknown_field: "value",
      another_unknown: 42,
    });
    expect(cfg.warnings).toHaveLength(2);
    expect(cfg.warnings.some(w => w.includes("unknown_field"))).toBe(true);
  });

  it("no warnings for valid keys", () => {
    const cfg = parseGateDict(COMPLETE_CONFIG);
    expect(cfg.warnings).toHaveLength(0);
  });
});

describe("validateProcedures", () => {
  it("no warnings for known procedures", () => {
    const cfg = parseGateDict(COMPLETE_CONFIG);
    const known = new Set(["AI-LOG.1", "AI-FAIR.1", "AI-HITL.1"]);
    expect(validateProcedures(cfg, known)).toHaveLength(0);
  });

  it("warns on unknown procedure", () => {
    const cfg = parseGateDict(COMPLETE_CONFIG);
    const known = new Set(["AI-LOG.1"]);
    const warnings = validateProcedures(cfg, known);
    expect(warnings.length).toBeGreaterThan(0);
    expect(warnings.some(w => w.includes("AI-FAIR.1"))).toBe(true);
  });
});

describe("allProcedures", () => {
  it("extracts all with context", () => {
    const cfg = parseGateDict(COMPLETE_CONFIG);
    const procs = allProcedures(cfg);
    const ids = procs.map(([, p]) => p.procedure);
    expect(ids).toContain("AI-LOG.1");
    expect(ids).toContain("AI-FAIR.1");
    expect(ids).toContain("AI-HITL.1");
    const contexts = new Set(procs.map(([fw]) => fw));
    expect(contexts).toContain("defaults");
    expect(contexts).toContain("eu-ai-act");
    expect(contexts).toContain("sr-11-7");
  });
});

describe("findGateFile", () => {
  it("returns null for nonexistent path", () => {
    expect(findGateFile("/nonexistent/gate.yml")).toBeNull();
  });
});

// ── Gate Init Generator Tests ──

describe("generateGateYaml", () => {
  it("generates valid EU-AI-ACT YAML", async () => {
    const yaml = await import("yaml");
    const output = await generateGateYaml("EU-AI-ACT");
    const raw = yaml.parse(output);
    const cfg = parseGateDict(raw);
    expect(cfg.version).toBe("1.0");
    expect(cfg.name).toContain("EU");
    expect(cfg.frameworks["eu-ai-act"]).toBeDefined();
    expect(cfg.frameworks["eu-ai-act"].riskClass).toBe("high-risk");
    let total = 0;
    for (const g of cfg.frameworks["eu-ai-act"].gates) total += g.procedures.length;
    expect(total).toBeGreaterThanOrEqual(50);
  });

  it("generates valid SR-11-7 YAML", async () => {
    const yaml = await import("yaml");
    const output = await generateGateYaml("SR-11-7");
    const raw = yaml.parse(output);
    const cfg = parseGateDict(raw);
    expect(cfg.frameworks["sr-11-7"]).toBeDefined();
    expect(cfg.frameworks["sr-11-7"].riskClass).toBe("model-risk");
    let total = 0;
    for (const g of cfg.frameworks["sr-11-7"].gates) total += g.procedures.length;
    expect(total).toBeGreaterThanOrEqual(15);
  });

  it("accepts custom name", async () => {
    const yaml = await import("yaml");
    const output = await generateGateYaml("SR-11-7", { name: "ACME Corp" });
    const raw = yaml.parse(output);
    const cfg = parseGateDict(raw);
    expect(cfg.name).toBe("ACME Corp");
  });

  it("sets strict mode", async () => {
    const yaml = await import("yaml");
    const output = await generateGateYaml("SR-11-7", { strict: true });
    const raw = yaml.parse(output);
    const cfg = parseGateDict(raw);
    expect(cfg.strict).toBe(true);
  });

  it("rejects unknown framework", async () => {
    await expect(generateGateYaml("NONEXISTENT")).rejects.toThrow("Unknown framework");
  });

  it("organizes procedures into named groups", async () => {
    const yaml = await import("yaml");
    const output = await generateGateYaml("EU-AI-ACT");
    const raw = yaml.parse(output);
    const cfg = parseGateDict(raw);
    const eu = cfg.frameworks["eu-ai-act"];
    expect(eu.gates.length).toBeGreaterThan(5);
    const hasArticleGroup = eu.gates.some(g => g.group.includes("Article"));
    expect(hasArticleGroup).toBe(true);
  });

  it("includes refs on procedures", async () => {
    const yaml = await import("yaml");
    const output = await generateGateYaml("EU-AI-ACT");
    const raw = yaml.parse(output);
    const cfg = parseGateDict(raw);
    for (const group of cfg.frameworks["eu-ai-act"].gates) {
      for (const proc of group.procedures) {
        expect(proc.ref).toBeDefined();
      }
    }
  });

  it("includes SDK hints", async () => {
    const yaml = await import("yaml");
    const output = await generateGateYaml("EU-AI-ACT");
    const raw = yaml.parse(output);
    const cfg = parseGateDict(raw);
    let hints = 0;
    for (const group of cfg.frameworks["eu-ai-act"].gates) {
      for (const proc of group.procedures) {
        if (proc.hint) hints++;
      }
    }
    expect(hints).toBeGreaterThan(20);
  });

  it("includes defaults", async () => {
    const yaml = await import("yaml");
    const output = await generateGateYaml("SR-11-7");
    const raw = yaml.parse(output);
    const cfg = parseGateDict(raw);
    expect(cfg.defaults).toBeDefined();
    const procs = cfg.defaults!.gates.map(g => g.procedure);
    expect(procs).toContain("AI-LOG.1");
    expect(procs).toContain("AI-AUDIT.1");
  });

  it("marks critical procedures", async () => {
    const yaml = await import("yaml");
    const output = await generateGateYaml("EU-AI-ACT");
    const raw = yaml.parse(output);
    const cfg = parseGateDict(raw);
    const criticalProcs = new Set<string>();
    for (const group of cfg.frameworks["eu-ai-act"].gates) {
      for (const proc of group.procedures) {
        if (proc.critical) criticalProcs.add(proc.procedure);
      }
    }
    expect(criticalProcs.has("AI-FAIR.1")).toBe(true);
    expect(criticalProcs.has("AI-HITL.1")).toBe(true);
    expect(criticalProcs.has("AI-GRD.1")).toBe(true);
  });

  it("includes metadata", async () => {
    const yaml = await import("yaml");
    const output = await generateGateYaml("EU-AI-ACT");
    const raw = yaml.parse(output);
    const cfg = parseGateDict(raw);
    expect(cfg.metadata).toBeDefined();
    expect(cfg.metadata!.generated_at).toBeDefined();
    expect(cfg.metadata!.crosswalk_version).toBeDefined();
    expect(cfg.metadata!.framework).toBe("EU-AI-ACT");
  });
});

describe("listFrameworks", () => {
  it("returns frameworks with counts", async () => {
    const fws = await listFrameworks();
    expect(fws.length).toBeGreaterThanOrEqual(10);
    const ids = fws.map(f => f.id);
    expect(ids).toContain("EU-AI-ACT");
    expect(ids).toContain("SR-11-7");
    expect(ids).toContain("NIST-AI-RMF");
  });

  it("all have positive procedure counts", async () => {
    const fws = await listFrameworks();
    for (const fw of fws) {
      expect(fw.procedures).toBeGreaterThan(0);
      expect(fw.name).toBeTruthy();
    }
  });
});
