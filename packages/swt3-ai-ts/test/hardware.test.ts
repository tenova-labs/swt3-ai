/**
 * SWT3 AI Witness SDK -- AI-HW.1 Hardware Witnessing Tests.
 *
 * All tests run without GPUs. nvidia-smi is mocked via vi.mock.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Witness } from "../src/witness.js";
import { detectTopology, topologyCode } from "../src/hardware.js";
import type { GpuInfo, HardwareSnapshot } from "../src/hardware.js";

beforeEach(() => {
  vi.spyOn(console, "info").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

function mkWitness(overrides: Record<string, unknown> = {}): Witness {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    flushInterval: 999999,
    ...overrides,
  } as any);
}

function mkGpu(name: string, memoryMb = 81920): GpuInfo {
  return { name, memoryMb, busIdHash: "bushash", uuidHash: "uidhash" };
}

function mkSnapshot(gpuCount: number, name = "NVIDIA H100 80GB HBM3"): HardwareSnapshot {
  const gpus = Array.from({ length: gpuCount }, () => mkGpu(name));
  return {
    gpus,
    driverVersion: "550.54.15",
    cudaVersion: "12.4",
    topology: detectTopology(gpus),
    interconnect: "nvswitch",
    totalMemoryMb: gpuCount * 81920,
    hostnameHash: "hosthash",
  };
}

// ── Topology Detection ──────────────────────────────────────────────

describe("detectTopology", () => {
  it("zero GPUs -> unknown", () => {
    expect(detectTopology([])).toBe("unknown");
  });

  it("1 GPU -> single", () => {
    expect(detectTopology([mkGpu("RTX 4090")])).toBe("single");
  });

  it("8x H100 -> DGX-H100", () => {
    const gpus = Array.from({ length: 8 }, () => mkGpu("NVIDIA H100 80GB HBM3"));
    expect(detectTopology(gpus)).toBe("DGX-H100");
  });

  it("8x A100 -> DGX-A100", () => {
    const gpus = Array.from({ length: 8 }, () => mkGpu("NVIDIA A100 80GB"));
    expect(detectTopology(gpus)).toBe("DGX-A100");
  });

  it("8x H200 -> DGX-H200", () => {
    const gpus = Array.from({ length: 8 }, () => mkGpu("NVIDIA H200"));
    expect(detectTopology(gpus)).toBe("DGX-H200");
  });

  it("8x B200 -> DGX-B200", () => {
    const gpus = Array.from({ length: 8 }, () => mkGpu("NVIDIA B200 Blackwell"));
    expect(detectTopology(gpus)).toBe("DGX-B200");
  });

  it("8x L40S -> HGX", () => {
    const gpus = Array.from({ length: 8 }, () => mkGpu("NVIDIA L40S"));
    expect(detectTopology(gpus)).toBe("HGX");
  });

  it("72 GPUs -> NVL72", () => {
    const gpus = Array.from({ length: 72 }, () => mkGpu("NVIDIA B200"));
    expect(detectTopology(gpus)).toBe("NVL72");
  });

  it("36 GPUs -> NVL36", () => {
    const gpus = Array.from({ length: 36 }, () => mkGpu("NVIDIA B200"));
    expect(detectTopology(gpus)).toBe("NVL36");
  });

  it("4 GPUs -> multi-gpu", () => {
    const gpus = Array.from({ length: 4 }, () => mkGpu("RTX A6000"));
    expect(detectTopology(gpus)).toBe("multi-gpu");
  });

  it("16 GPUs -> multi-node", () => {
    const gpus = Array.from({ length: 16 }, () => mkGpu("NVIDIA H100"));
    expect(detectTopology(gpus)).toBe("multi-node");
  });
});

describe("topologyCode", () => {
  it("maps known topologies", () => {
    expect(topologyCode("single")).toBe(0);
    expect(topologyCode("DGX-H100")).toBe(1);
    expect(topologyCode("NVL72")).toBe(2);
    expect(topologyCode("unknown")).toBe(3);
  });

  it("unknown string -> 3", () => {
    expect(topologyCode("something_new")).toBe(3);
  });
});

// ── witnessHardware() ───────────────────────────────────────────────

describe("witnessHardware", () => {
  it("basic 8xH100 payload", () => {
    const w = mkWitness();
    const snap = mkSnapshot(8);
    const p = w.witnessHardware({ snapshot: snap });
    expect(p.procedure_id).toBe("AI-HW.1");
    expect(p.factor_a).toBe(8);
    expect(p.factor_b).toBe(1);
    expect(p.factor_c).toBe(1); // DGX-H100 = multi-GPU same node
  });

  it("NVL72 topology code", () => {
    const w = mkWitness();
    const snap = mkSnapshot(72, "NVIDIA B200");
    const p = w.witnessHardware({ snapshot: snap });
    expect(p.factor_a).toBe(72);
    expect(p.factor_c).toBe(2); // NVL72 = multi-node
  });

  it("no GPUs graceful", () => {
    const w = mkWitness();
    const snap: HardwareSnapshot = {
      gpus: [], driverVersion: "", cudaVersion: "",
      topology: "unknown", interconnect: "unknown",
      totalMemoryMb: 0, hostnameHash: "h",
    };
    const p = w.witnessHardware({ snapshot: snap });
    expect(p.factor_a).toBe(0);
    expect(p.factor_b).toBe(0);
    expect(p.factor_c).toBe(3); // unknown
  });

  it("expected topology match", () => {
    const w = mkWitness();
    const snap = mkSnapshot(8);
    const p = w.witnessHardware({ snapshot: snap, expectedTopology: "DGX-H100" });
    expect(p.factor_b).toBe(1);
  });

  it("expected topology mismatch", () => {
    const w = mkWitness();
    const snap = mkSnapshot(8);
    const p = w.witnessHardware({ snapshot: snap, expectedTopology: "NVL72" });
    expect(p.factor_b).toBe(0);
  });

  it("clearing level 0 has full context", () => {
    const w = mkWitness({ clearingLevel: 0 });
    const snap = mkSnapshot(8);
    const p = w.witnessHardware({ snapshot: snap });
    expect(p.ai_context).toBeDefined();
    expect(p.ai_context!.topology).toBe("DGX-H100");
    expect(p.ai_context!.gpu_count).toBe(8);
    expect(p.ai_context!.provider).toBe("nvidia-hw");
    expect((p.ai_context!.gpus as any[]).length).toBe(8);
  });

  it("clearing level 1 has context", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const snap = mkSnapshot(8);
    const p = w.witnessHardware({ snapshot: snap });
    expect(p.ai_context).toBeDefined();
  });

  it("clearing level 2 strips context", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const snap = mkSnapshot(8);
    const p = w.witnessHardware({ snapshot: snap });
    expect(p.ai_context).toBeUndefined();
  });

  it("clearing level 3 strips context", () => {
    const w = mkWitness({ clearingLevel: 3 });
    const snap = mkSnapshot(8);
    const p = w.witnessHardware({ snapshot: snap });
    expect(p.ai_context).toBeUndefined();
  });

  it("payload enqueued", () => {
    const w = mkWitness();
    const snap = mkSnapshot(1, "RTX 4090");
    w.witnessHardware({ snapshot: snap });
    expect(w.pending).toBeGreaterThan(0);
  });

  it("agent_id survives", () => {
    const w = mkWitness({ agentId: "hw-agent" });
    const snap = mkSnapshot(8);
    const p = w.witnessHardware({ snapshot: snap });
    expect(p.agent_id).toBe("hw-agent");
  });

  it("CJT fields survive", () => {
    const w = mkWitness({ jurisdiction: "DE", legalBasis: "GDPR-6.1.a", purposeClass: "analytics" });
    const snap = mkSnapshot(8);
    const p = w.witnessHardware({ snapshot: snap });
    expect(p.jurisdiction).toBe("DE");
    expect(p.legal_basis).toBe("GDPR-6.1.a");
    expect(p.purpose_class).toBe("analytics");
  });

  it("single GPU topology code 0", () => {
    const w = mkWitness();
    const snap = mkSnapshot(1, "RTX 4090");
    const p = w.witnessHardware({ snapshot: snap });
    expect(p.factor_c).toBe(0);
  });

  it("context includes expected_topology when set", () => {
    const w = mkWitness({ clearingLevel: 0 });
    const snap = mkSnapshot(8);
    const p = w.witnessHardware({ snapshot: snap, expectedTopology: "DGX-H100" });
    expect(p.ai_context!.expected_topology).toBe("DGX-H100");
  });
});
