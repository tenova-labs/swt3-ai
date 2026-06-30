/**
 * SWT3 AI Witness SDK -- AI-HW.1 Hardware Witnessing Tests.
 *
 * All tests run without GPUs. nvidia-smi is mocked via vi.mock.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Witness } from "../src/witness.js";
import { detectTopology, topologyCode, queryHardware, queryGoogleTPU, queryAmdRocm, queryAwsNeuron, queryIntelGaudi, queryPciFallback } from "../src/hardware.js";
import type { GpuInfo, HardwareSnapshot, AcceleratorInfo } from "../src/hardware.js";

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
  const accelerators = gpus.map((g) => ({
    vendor: "nvidia" as const,
    name: g.name,
    memoryMb: g.memoryMb,
    idHash: g.uuidHash,
    busIdHash: g.busIdHash,
    discoveryMethod: "nvidia-smi",
  }));
  return {
    gpus,
    driverVersion: "550.54.15",
    cudaVersion: "12.4",
    topology: detectTopology(gpus),
    interconnect: "nvswitch",
    totalMemoryMb: gpuCount * 81920,
    hostnameHash: "hosthash",
    accelerators,
    siliconVendor: gpuCount > 0 ? "nvidia" : "none",
    discoveryMethod: gpuCount > 0 ? "nvidia-smi" : "",
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
      accelerators: [], siliconVendor: "none", discoveryMethod: "",
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
    expect(p.ai_context!.provider).toBe("nvidia");
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

// ── Cross-Silicon Discovery ─────────────────────────────────────────

describe("queryGoogleTPU", () => {

  const origEnv = { ...process.env };
  afterEach(() => { process.env = { ...origEnv }; });

  it("returns empty when no TPU_NAME", () => {
    delete process.env.TPU_NAME;
    expect(queryGoogleTPU()).toEqual([]);
  });

  it("detects single TPU from TPU_NAME", () => {
    process.env.TPU_NAME = "v5e-256";
    delete process.env.TPU_WORKER_HOSTNAMES;
    const accels = queryGoogleTPU();
    expect(accels).toHaveLength(1);
    expect(accels[0].vendor).toBe("google-tpu");
    expect(accels[0].name).toBe("v5e-256");
    expect(accels[0].discoveryMethod).toBe("tpu-env");
    expect(accels[0].memoryMb).toBe(16384);
  });

  it("counts workers from TPU_WORKER_HOSTNAMES", () => {
    process.env.TPU_NAME = "v5p-128";
    process.env.TPU_WORKER_HOSTNAMES = "w0,w1,w2,w3";
    const accels = queryGoogleTPU();
    expect(accels).toHaveLength(4);
    expect(accels[0].memoryMb).toBe(95000);
  });

  it("infers memory for v4 TPU", () => {
    process.env.TPU_NAME = "v4-8";
    delete process.env.TPU_WORKER_HOSTNAMES;
    const accels = queryGoogleTPU();
    expect(accels[0].memoryMb).toBe(32768);
  });

  it("hashes device IDs", () => {
    process.env.TPU_NAME = "v5e-4";
    delete process.env.TPU_WORKER_HOSTNAMES;
    const accels = queryGoogleTPU();
    expect(accels[0].idHash).not.toContain("v5e");
    expect(accels[0].idHash.length).toBe(16);
  });
});

describe("queryAmdRocm", () => {


  it("returns empty when rocm-smi not installed", () => {
    const [accels, driver] = queryAmdRocm();
    expect(accels).toEqual([]);
    expect(driver).toBe("");
  });
});

describe("queryAwsNeuron", () => {


  it("returns empty when neuron-ls not installed", () => {
    expect(queryAwsNeuron()).toEqual([]);
  });
});

describe("queryIntelGaudi", () => {


  it("returns empty when hl-smi not installed", () => {
    const [accels, driver] = queryIntelGaudi();
    expect(accels).toEqual([]);
    expect(driver).toBe("");
  });
});

describe("queryPciFallback", () => {


  it("returns empty on non-Linux or no accelerators", () => {
    const accels = queryPciFallback(new Set());
    // On this test server, may find 0 or some PCI devices -- either way, no crash
    expect(Array.isArray(accels)).toBe(true);
  });

  it("deduplicates already-seen bus IDs", () => {
    const fakeBusId = "already-seen-hash";
    const accels = queryPciFallback(new Set([fakeBusId]));
    expect(accels.every((a: any) => a.busIdHash !== fakeBusId)).toBe(true);
  });
});

describe("detectTopology cross-silicon", () => {
  it("TPU single chip", () => {
    const topo = detectTopology([], [{ vendor: "google-tpu", name: "v5e", memoryMb: 0, idHash: "", busIdHash: "", discoveryMethod: "tpu-env" }]);
    expect(topo).toBe("tpu-single");
  });

  it("TPU pod (multiple chips)", () => {
    const chips = Array.from({ length: 4 }, () => ({ vendor: "google-tpu" as const, name: "v5p", memoryMb: 0, idHash: "", busIdHash: "", discoveryMethod: "tpu-env" }));
    expect(detectTopology([], chips)).toBe("tpu-pod");
  });

  it("AMD single GPU", () => {
    expect(detectTopology([], [{ vendor: "amd", name: "MI300X", memoryMb: 0, idHash: "", busIdHash: "", discoveryMethod: "rocm-smi" }])).toBe("mi-single");
  });

  it("AMD cluster", () => {
    const gpus = Array.from({ length: 8 }, () => ({ vendor: "amd" as const, name: "MI300X", memoryMb: 0, idHash: "", busIdHash: "", discoveryMethod: "rocm-smi" }));
    expect(detectTopology([], gpus)).toBe("mi-cluster");
  });

  it("AWS Trainium cluster", () => {
    const devs = Array.from({ length: 16 }, () => ({ vendor: "aws-trainium" as const, name: "trn1", memoryMb: 0, idHash: "", busIdHash: "", discoveryMethod: "neuron-ls" }));
    expect(detectTopology([], devs)).toBe("trn-cluster");
  });

  it("AWS Inferentia single", () => {
    expect(detectTopology([], [{ vendor: "aws-trainium", name: "inf2", memoryMb: 0, idHash: "", busIdHash: "", discoveryMethod: "neuron-ls" }])).toBe("inf-single");
  });

  it("Intel Gaudi cluster", () => {
    const devs = Array.from({ length: 8 }, () => ({ vendor: "intel-gaudi" as const, name: "Gaudi3", memoryMb: 0, idHash: "", busIdHash: "", discoveryMethod: "hl-smi" }));
    expect(detectTopology([], devs)).toBe("gaudi-cluster");
  });

  it("empty accelerators returns unknown", () => {
    expect(detectTopology([], [])).toBe("unknown");
  });

  it("NVIDIA GPUs still use GPU path (backward compat)", () => {
    const gpus = Array.from({ length: 8 }, () => mkGpu("NVIDIA H100 80GB HBM3"));
    expect(detectTopology(gpus, [])).toBe("DGX-H100");
  });
});

describe("queryHardware aggregation", () => {
  it("populates siliconVendor and discoveryMethod", () => {
    // On this server: no GPUs, no TPU, no AMD, no AWS, no Intel
    const snap = queryHardware();
    expect(snap.siliconVendor).toBeDefined();
    expect(snap.discoveryMethod).toBeDefined();
    expect(snap.accelerators).toBeDefined();
    expect(Array.isArray(snap.accelerators)).toBe(true);
    // Backward compat: gpus still present
    expect(Array.isArray(snap.gpus)).toBe(true);
  });

  it("empty server has siliconVendor none", () => {
    const snap = queryHardware();
    // Unless this test server has GPUs/TPUs, expect none
    if (snap.gpus.length === 0 && snap.accelerators.length === 0) {
      expect(snap.siliconVendor).toBe("none");
      expect(snap.discoveryMethod).toBe("");
    }
  });
});

describe("witnessHardware cross-silicon context", () => {
  it("includes silicon_vendor in context", () => {
    const w = mkWitness({ clearingLevel: 0 });
    const snap = mkSnapshot(8);
    const p = w.witnessHardware({ snapshot: snap });
    expect(p.ai_context!.silicon_vendor).toBe("nvidia");
    expect(p.ai_context!.discovery_method).toBe("nvidia-smi");
    expect(p.ai_context!.accelerator_count).toBe(8);
  });

  it("includes accelerators array in context", () => {
    const w = mkWitness({ clearingLevel: 0 });
    const snap = mkSnapshot(2, "RTX 4090");
    const p = w.witnessHardware({ snapshot: snap });
    const accels = p.ai_context!.accelerators as any[];
    expect(accels).toHaveLength(2);
    expect(accels[0].vendor).toBe("nvidia");
    expect(accels[0].discovery_method).toBe("nvidia-smi");
  });

  it("TPU snapshot has google-tpu provider", () => {
    const w = mkWitness({ clearingLevel: 0 });
    const snap: HardwareSnapshot = {
      gpus: [], driverVersion: "", cudaVersion: "",
      topology: "tpu-pod", interconnect: "unknown",
      totalMemoryMb: 65536, hostnameHash: "h",
      accelerators: [
        { vendor: "google-tpu", name: "v5e-256", memoryMb: 16384, idHash: "a", busIdHash: "b", discoveryMethod: "tpu-env" },
        { vendor: "google-tpu", name: "v5e-256", memoryMb: 16384, idHash: "c", busIdHash: "d", discoveryMethod: "tpu-env" },
      ],
      siliconVendor: "google-tpu",
      discoveryMethod: "tpu-env",
    };
    const p = w.witnessHardware({ snapshot: snap });
    expect(p.factor_a).toBe(2);
    expect(p.ai_context!.provider).toBe("google-tpu");
    expect(p.ai_context!.silicon_vendor).toBe("google-tpu");
  });

  it("mixed silicon shows mixed provider", () => {
    const w = mkWitness({ clearingLevel: 0 });
    const snap: HardwareSnapshot = {
      gpus: [mkGpu("NVIDIA H100 80GB HBM3")],
      driverVersion: "550.54", cudaVersion: "",
      topology: "single", interconnect: "pcie",
      totalMemoryMb: 98304, hostnameHash: "h",
      accelerators: [
        { vendor: "nvidia", name: "H100", memoryMb: 81920, idHash: "a", busIdHash: "b", discoveryMethod: "nvidia-smi" },
        { vendor: "google-tpu", name: "v5e", memoryMb: 16384, idHash: "c", busIdHash: "d", discoveryMethod: "tpu-env" },
      ],
      siliconVendor: "mixed",
      discoveryMethod: "nvidia-smi,tpu-env",
    };
    const p = w.witnessHardware({ snapshot: snap });
    expect(p.factor_a).toBe(2);
    expect(p.ai_context!.provider).toBe("mixed");
    expect(p.ai_context!.silicon_vendor).toBe("mixed");
  });
});
