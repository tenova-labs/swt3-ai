/**
 * SWT3 AI Witness SDK -- Hardware Discovery (AI-HW.1, AI-HW.3).
 *
 * Out-of-band hardware inventory snapshots. Records what accelerator
 * hardware and TPM state were present when the service started.
 * Does NOT sit in the inference path.
 *
 * Accelerator data sources (AI-HW.1), tried in order:
 *   1. nvidia-smi subprocess (NVIDIA GPU)
 *   2. TPU_NAME environment variable (Google TPU on GCE)
 *   3. rocm-smi subprocess (AMD MI series)
 *   4. neuron-ls subprocess (AWS Trainium/Inferentia)
 *   5. hl-smi subprocess (Intel Gaudi)
 *   6. PCI device class fallback (generic)
 *
 * TPM data source (AI-HW.3):
 *   - tpm2-tools subprocess (tpm2_pcrread, tpm2_getcap)
 *
 * Security: All hardware identifiers (GPU UUIDs, bus IDs, hostnames,
 * PCR digests, endorsement keys) are SHA-256 hashed at discovery time.
 * Raw values never leave this module.
 */

import { execSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { hostname } from "node:os";
import { sha256Truncated } from "./fingerprint.js";

export interface GpuInfo {
  name: string;
  memoryMb: number;
  busIdHash: string;   // SHA-256 truncated, never cleartext
  uuidHash: string;    // SHA-256 truncated, never cleartext
}

export interface AcceleratorInfo {
  name: string;        // e.g., "NVIDIA H100 80GB HBM3", "TPU v5p", "AMD Instinct MI300X"
  memoryMb: number;
  busIdHash: string;   // SHA-256 truncated, never cleartext
  uuidHash: string;    // SHA-256 truncated, never cleartext
  vendor: string;      // nvidia, google, amd, aws, intel, unknown
  family: string;      // H100, TPU-v5p, MI300X, Trainium2, Gaudi3
  discoveryMethod: string; // pynvml, nvidia-smi, jax, rocm-smi, neuron-ls, hl-smi, pci
}

export const SILICON_VENDORS = new Set(["nvidia", "google", "amd", "aws", "intel"]);

export const VENDOR_CODES: Record<string, number> = {
  nvidia: 0,
  google: 1,
  amd: 2,
  aws: 3,
  intel: 4,
  mixed: 5,
  unknown: 6,
};

export interface HardwareSnapshot {
  gpus: GpuInfo[];
  driverVersion: string;
  cudaVersion: string;
  topology: string;    // NVL72, DGX-H100, DGX-A100, HGX, multi-gpu, single, unknown
  interconnect: string; // nvswitch, nvlink, pcie, unknown
  totalMemoryMb: number;
  hostnameHash: string; // SHA-256 truncated, never cleartext
  siliconVendor?: string;      // nvidia, google, amd, aws, intel, mixed, ""
  accelerators?: AcceleratorInfo[];
  discoveryMethod?: string;    // which discovery path succeeded
}

/** Topology codes for factor_c. */
export const TOPOLOGY_CODES: Record<string, number> = {
  single: 0,
  "multi-gpu": 1,
  HGX: 1,
  "DGX-A100": 1,
  "DGX-H100": 1,
  "DGX-H200": 1,
  "DGX-B200": 1,
  NVL36: 2,
  NVL72: 2,
  "multi-node": 2,
  unknown: 3,
};

/**
 * Query accelerator hardware and return a pre-hashed snapshot.
 * Tries all silicon vendors: NVIDIA, Google TPU, AMD, AWS, Intel, PCI fallback.
 * Returns empty snapshot if no accelerators are detectable.
 */
export function queryHardware(): HardwareSnapshot {
  return queryAccelerators();
}

/**
 * Infer cluster topology from GPU count and model names.
 */
export function detectTopology(gpus: GpuInfo[]): string {
  const count = gpus.length;
  if (count === 0) return "unknown";
  if (count === 1) return "single";

  const nameStr = gpus.map((g) => g.name.toUpperCase()).join(" ");

  if (count === 72) return "NVL72";
  if (count === 36) return "NVL36";
  if (count === 8) {
    if (nameStr.includes("B200") || nameStr.includes("BLACKWELL")) return "DGX-B200";
    if (nameStr.includes("H200")) return "DGX-H200";
    if (nameStr.includes("H100")) return "DGX-H100";
    if (nameStr.includes("A100")) return "DGX-A100";
    return "HGX";
  }
  if ([2, 3, 4, 6].includes(count)) return "multi-gpu";
  return "multi-node";
}

/**
 * Detect GPU interconnect type from nvidia-smi topology matrix.
 */
export function detectInterconnect(): string {
  try {
    const raw = execSync("nvidia-smi topo -m", {
      timeout: 5_000,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });

    // Parse only GPU data rows (start with "GPU" + digit), skip header/legend
    const connections: string[] = [];
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (/^GPU\d/.test(trimmed)) {
        const parts = trimmed.split(/\s+/).slice(1).filter((p) => p !== "X");
        connections.push(...parts.map((p) => p.toUpperCase()));
      }
    }

    if (connections.length === 0) return "unknown";
    const joined = connections.join(" ");
    if (joined.includes("SYS")) return "nvswitch";
    if (connections.some((c) => /^NV\d/.test(c))) return "nvlink";
    if (joined.includes("PIX") || joined.includes("PHB") || joined.includes("PXB")) return "pcie";
    return "unknown";
  } catch {
    return "unknown";
  }
}

/**
 * Convert topology string to factor_c integer code.
 */
export function topologyCode(topology: string): number {
  return TOPOLOGY_CODES[topology] ?? 3;
}

/**
 * Query GPUs via nvidia-smi subprocess. Returns [gpus, driverVersion].
 */
export function queryNvidiaSmi(): [GpuInfo[], string] {
  try {
    const output = execSync(
      "nvidia-smi --query-gpu=name,memory.total,pci.bus_id,uuid,driver_version --format=csv,noheader,nounits",
      { timeout: 5_000, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
    );

    const gpus: GpuInfo[] = [];
    let driver = "";

    for (const line of output.trim().split("\n")) {
      if (!line.trim()) continue;
      const parts = line.split(",").map((p) => p.trim());
      if (parts.length < 5) continue;

      const [name, memStr, busId, uuid, drv] = parts;
      if (!driver) driver = drv;

      gpus.push({
        name,
        memoryMb: Math.round(parseFloat(memStr)) || 0,
        busIdHash: sha256Truncated(busId),
        uuidHash: sha256Truncated(uuid),
      });
    }

    return [gpus, driver];
  } catch {
    return [[], ""];
  }
}

// ── Vendor Family Parsing ───────────────────────────────────────────────

const NVIDIA_FAMILIES = new Set([
  "A100", "A800", "H100", "H200", "H800", "B100", "B200",
  "L4", "L40", "L40S", "A10", "A10G", "A30", "A40",
  "T4", "V100", "P100", "RTX",
]);

function parseNvidiaFamily(name: string): string {
  for (const token of name.toUpperCase().split(/\s+/)) {
    if (NVIDIA_FAMILIES.has(token)) return token;
  }
  return "GPU";
}

// ── Google TPU Discovery (Node.js) ──────────────────────────────────────

/**
 * Detect Google TPU via environment variables set by GCE TPU VMs.
 * JAX is Python-only; in Node.js we detect TPU presence via standard
 * Google Cloud TPU environment variables (TPU_NAME, TPU_WORKER_HOSTNAMES).
 */
function queryTpuEnv(): [AcceleratorInfo[], string] {
  const tpuName = process.env.TPU_NAME;
  if (!tpuName) return [[], ""];

  const workers = (process.env.TPU_WORKER_HOSTNAMES ?? "").split(",").filter(Boolean);
  const chipCount = Math.max(workers.length, 1);
  const accels: AcceleratorInfo[] = [];

  for (let i = 0; i < chipCount; i++) {
    const workerId = workers[i] ?? `tpu-${i}`;
    accels.push({
      name: tpuName,
      memoryMb: 0,
      busIdHash: sha256Truncated(`tpu-${workerId}`),
      uuidHash: sha256Truncated(`tpu-${workerId}-${i}`),
      vendor: "google",
      family: tpuName.replace(/\s+/g, "-"),
      discoveryMethod: "tpu-env",
    });
  }
  return [accels, "tpu-env"];
}

// ── PCI Vendor IDs ──────────────────────────────────────────────────────

const PCI_VENDORS: Record<string, string> = {
  "10de": "nvidia",
  "1002": "amd",
  "8086": "intel",
};

// ── AMD ROCm Discovery ─────────────────────────────────────────────────

function queryRocmSmi(): [AcceleratorInfo[], string] {
  try {
    const output = execSync(
      "rocm-smi --showproductname --showmeminfo vram --showbus --showuniqueid --csv",
      { timeout: 5_000, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
    );
    const lines = output.trim().split("\n");
    if (lines.length < 2) return [[], ""];

    const accels: AcceleratorInfo[] = [];
    for (const line of lines.slice(1)) {
      if (!line.trim()) continue;
      const parts = line.split(",").map((p) => p.trim());
      if (parts.length < 4) continue;
      const name = parts[0] || "AMD GPU";
      const memoryMb = Math.round(parseFloat(parts[1] || "0")) || 0;
      const busId = parts[2] || `amd-${accels.length}`;
      const uniqueId = parts[3] || `amd-uid-${accels.length}`;
      const upper = name.toUpperCase();
      const family = upper.includes("MI300X") ? "MI300X"
        : upper.includes("MI325X") ? "MI325X"
        : upper.includes("MI300") ? "MI300"
        : upper.includes("MI250") ? "MI250" : "MI";

      accels.push({
        name, memoryMb,
        busIdHash: sha256Truncated(busId),
        uuidHash: sha256Truncated(uniqueId),
        vendor: "amd", family, discoveryMethod: "rocm-smi",
      });
    }
    return [accels, "rocm-smi"];
  } catch {
    return [[], ""];
  }
}

// ── AWS Trainium/Inferentia Discovery ───────────────────────────────────

function queryNeuronLs(): [AcceleratorInfo[], string] {
  try {
    const output = execSync("neuron-ls --json-output", {
      timeout: 5_000, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"],
    });
    const data = JSON.parse(output);
    const devices: Array<Record<string, unknown>> = Array.isArray(data)
      ? data
      : (data.neuron_devices ?? []);
    if (devices.length === 0) return [[], ""];

    const accels: AcceleratorInfo[] = [];
    for (const dev of devices) {
      const devId = (dev.neuron_device ?? accels.length) as number;
      const ncCount = (dev.nc_count ?? 1) as number;
      const mem = (dev.memory_size ?? 0) as number;
      const devType = String(dev.device_type ?? "").toLowerCase();
      let family: string;
      if (devType.includes("trainium2") || devType.includes("trn2")) family = "Trainium2";
      else if (devType.includes("trainium") || devType.includes("trn1")) family = "Trainium";
      else if (devType.includes("inferentia") || devType.includes("inf")) family = "Inferentia";
      else family = ncCount >= 16 ? "Trainium" : "Neuron";

      accels.push({
        name: `AWS ${family}`, memoryMb: mem,
        busIdHash: sha256Truncated(`neuron-${devId}`),
        uuidHash: sha256Truncated(`neuron-${devId}-${ncCount}`),
        vendor: "aws", family, discoveryMethod: "neuron-ls",
      });
    }
    return [accels, "neuron-ls"];
  } catch {
    return [[], ""];
  }
}

// ── Intel Gaudi Discovery ───────────────────────────────────────────────

function queryHlSmi(): [AcceleratorInfo[], string] {
  try {
    const output = execSync(
      "hl-smi -Q name,memory.total,bus_id,serial -f csv,noheader",
      { timeout: 5_000, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
    );
    const accels: AcceleratorInfo[] = [];
    for (const line of output.trim().split("\n")) {
      if (!line.trim()) continue;
      const parts = line.split(",").map((p) => p.trim());
      if (parts.length < 3) continue;
      const name = parts[0] || "Intel Gaudi";
      const memoryMb = Math.round(parseFloat(parts[1] || "0")) || 0;
      const busId = parts[2] || `gaudi-${accels.length}`;
      const serial = parts[3] || `gaudi-sn-${accels.length}`;
      const upper = name.toUpperCase();
      const family = upper.includes("GAUDI3") ? "Gaudi3"
        : upper.includes("GAUDI2") ? "Gaudi2" : "Gaudi";

      accels.push({
        name, memoryMb,
        busIdHash: sha256Truncated(busId),
        uuidHash: sha256Truncated(serial),
        vendor: "intel", family, discoveryMethod: "hl-smi",
      });
    }
    return [accels, "hl-smi"];
  } catch {
    return [[], ""];
  }
}

// ── PCI Device Class Fallback ───────────────────────────────────────────

function queryPciFallback(): [AcceleratorInfo[], string] {
  const pciBase = "/sys/bus/pci/devices";
  try {
    const entries = readdirSync(pciBase);
    const accels: AcceleratorInfo[] = [];

    for (const entry of entries.sort()) {
      const classPath = `${pciBase}/${entry}/class`;
      const vendorPath = `${pciBase}/${entry}/vendor`;
      let pciClass: string;
      let pciVendor: string;
      try {
        pciClass = readFileSync(classPath, "utf-8").trim().toLowerCase();
        pciVendor = readFileSync(vendorPath, "utf-8").trim().toLowerCase().replace("0x", "");
      } catch {
        continue;
      }

      // 0x030200 = 3D controller, 0x120000 = processing accelerator
      if (!pciClass.startsWith("0x0302") && !pciClass.startsWith("0x1200")) continue;

      const vendor = PCI_VENDORS[pciVendor.slice(0, 4)] ?? "unknown";
      accels.push({
        name: `PCI ${vendor} accelerator`,
        memoryMb: 0,
        busIdHash: sha256Truncated(entry),
        uuidHash: sha256Truncated(`pci-${entry}`),
        vendor, family: "unknown", discoveryMethod: "pci",
      });
    }
    return [accels, accels.length > 0 ? "pci" : ""];
  } catch {
    return [[], ""];
  }
}

// ── Unified Accelerator Discovery ───────────────────────────────────────

/**
 * Query all accelerator types across silicon vendors.
 * Tries each discovery path in priority order. Returns a unified
 * HardwareSnapshot with siliconVendor populated.
 */
export function queryAccelerators(): HardwareSnapshot {
  const hn = sha256Truncated(hostname());

  // 1. NVIDIA (existing path)
  const [gpus, driverVersion] = queryNvidiaSmi();
  if (gpus.length > 0) {
    const topology = detectTopology(gpus);
    const interconnect = gpus.length > 0 ? detectInterconnect() : "unknown";
    const totalMemoryMb = gpus.reduce((s, g) => s + g.memoryMb, 0);
    const accelerators: AcceleratorInfo[] = gpus.map((g) => ({
      name: g.name, memoryMb: g.memoryMb,
      busIdHash: g.busIdHash, uuidHash: g.uuidHash,
      vendor: "nvidia", family: parseNvidiaFamily(g.name),
      discoveryMethod: "nvidia-smi",
    }));
    return {
      gpus, driverVersion, cudaVersion: "",
      topology, interconnect, totalMemoryMb, hostnameHash: hn,
      siliconVendor: "nvidia", accelerators, discoveryMethod: "nvidia-smi",
    };
  }

  // 2. Google TPU (env var detection -- JAX is Python-only)
  const [tpuAccels, tpuMethod] = queryTpuEnv();
  if (tpuAccels.length > 0) {
    const count = tpuAccels.length;
    const totalMemoryMb = tpuAccels.reduce((s, a) => s + a.memoryMb, 0);
    const topology = count === 1 ? "single" : count <= 8 ? "multi-gpu" : "multi-node";
    return {
      gpus: [], driverVersion: "", cudaVersion: "",
      topology, interconnect: "unknown", totalMemoryMb, hostnameHash: hn,
      siliconVendor: "google", accelerators: tpuAccels, discoveryMethod: tpuMethod,
    };
  }

  // 3-6: Non-NVIDIA, non-TPU discovery paths
  const paths: Array<[() => [AcceleratorInfo[], string], string]> = [
    [queryRocmSmi, "amd"],
    [queryNeuronLs, "aws"],
    [queryHlSmi, "intel"],
    [queryPciFallback, "pci"],
  ];

  for (const [queryFn] of paths) {
    const [accels, method] = queryFn();
    if (accels.length > 0) {
      const vendors = new Set(accels.map((a) => a.vendor));
      const vendor = vendors.size === 1 ? [...vendors][0] : vendors.size > 1 ? "mixed" : "unknown";
      const totalMemoryMb = accels.reduce((s, a) => s + a.memoryMb, 0);
      const count = accels.length;
      const topology = count === 1 ? "single" : count <= 8 ? "multi-gpu" : "multi-node";
      return {
        gpus: [], driverVersion: "", cudaVersion: "",
        topology, interconnect: "unknown", totalMemoryMb, hostnameHash: hn,
        siliconVendor: vendor, accelerators: accels, discoveryMethod: method,
      };
    }
  }

  // Nothing found
  return {
    gpus: [], driverVersion: "", cudaVersion: "",
    topology: "unknown", interconnect: "unknown",
    totalMemoryMb: 0, hostnameHash: hn,
    siliconVendor: "", accelerators: [], discoveryMethod: "",
  };
}

// ── TPM 2.0 Attestation (AI-HW.3) ──────────────────────────────────────

export interface PcrRegister {
  index: number;
  bank: string;        // "sha256"
  digestHash: string;  // SHA-256 of the raw PCR value, never cleartext
}

export interface TPMSnapshot {
  available: boolean;
  manufacturer: string;       // SHA-256 hashed, never cleartext
  firmwareVersion: string;    // SHA-256 hashed, never cleartext
  pcrs: PcrRegister[];
  endorsementKeyHash: string; // SHA-256 of the EK public key, never cleartext
  hostnameHash: string;       // SHA-256 truncated, never cleartext
}

const EMPTY_TPM: TPMSnapshot = {
  available: false,
  manufacturer: "",
  firmwareVersion: "",
  pcrs: [],
  endorsementKeyHash: "",
  hostnameHash: "",
};

/**
 * Query TPM 2.0 PCR registers and return a pre-hashed snapshot.
 * Returns empty snapshot if no TPM device or tpm2-tools not installed.
 */
export function queryTPM(): TPMSnapshot {
  const pcrs = queryTPMPcrs();
  if (pcrs.length === 0) return { ...EMPTY_TPM, hostnameHash: sha256Truncated(hostname()) };

  const props = queryTPMProperties();

  return {
    available: true,
    manufacturer: props.manufacturer,
    firmwareVersion: props.firmwareVersion,
    pcrs,
    endorsementKeyHash: props.endorsementKeyHash,
    hostnameHash: sha256Truncated(hostname()),
  };
}

/**
 * Read TPM PCR registers via tpm2_pcrread. Returns hashed digests.
 *
 * Output format:
 *   sha256:
 *     0 : 0x<64-hex-chars>
 *     7 : 0x<64-hex-chars>
 */
export function queryTPMPcrs(): PcrRegister[] {
  try {
    const output = execSync("tpm2_pcrread sha256:0,1,2,3,4,5,6,7", {
      timeout: 5_000,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    return parseTPMPcrOutput(output);
  } catch {
    return [];
  }
}

/**
 * Parse tpm2_pcrread output into pre-hashed PcrRegister array.
 */
export function parseTPMPcrOutput(output: string): PcrRegister[] {
  const pcrs: PcrRegister[] = [];
  let currentBank = "";

  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    // Bank header: "sha256:" or "sha1:"
    const bankMatch = trimmed.match(/^(\w+):$/);
    if (bankMatch) {
      currentBank = bankMatch[1];
      continue;
    }
    // PCR line: "  0 : 0x3d458c..."
    const pcrMatch = trimmed.match(/^(\d+)\s*:\s*0x([0-9a-fA-F]+)$/);
    if (pcrMatch && currentBank) {
      pcrs.push({
        index: parseInt(pcrMatch[1], 10),
        bank: currentBank,
        digestHash: sha256Truncated(pcrMatch[2]),
      });
    }
  }

  return pcrs;
}

/**
 * Query TPM manufacturer and firmware via tpm2_getcap.
 * Returns hashed values. Falls back to empty strings on failure.
 */
export function queryTPMProperties(): {
  manufacturer: string;
  firmwareVersion: string;
  endorsementKeyHash: string;
} {
  const result = { manufacturer: "", firmwareVersion: "", endorsementKeyHash: "" };

  try {
    const output = execSync("tpm2_getcap properties-fixed", {
      timeout: 5_000,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    for (const line of output.split("\n")) {
      const kv = line.trim();
      if (kv.startsWith("TPM2_PT_MANUFACTURER:")) {
        result.manufacturer = sha256Truncated(kv.split(":").slice(1).join(":").trim());
      } else if (kv.startsWith("TPM2_PT_FIRMWARE_VERSION_1:")) {
        result.firmwareVersion = sha256Truncated(kv.split(":").slice(1).join(":").trim());
      }
    }
  } catch { /* unavailable */ }

  // Endorsement key: separate command
  try {
    const ekOutput = execSync("tpm2_readpublic -c 0x81010001 -o /dev/null 2>&1 || tpm2_createek -c /dev/null -G rsa -u /dev/stdout 2>/dev/null | head -c 512", {
      timeout: 5_000,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    if (ekOutput.trim()) {
      result.endorsementKeyHash = sha256Truncated(ekOutput.trim());
    }
  } catch { /* unavailable */ }

  return result;
}

/** SHA-256 hash of the all-zeros PCR value (uninitialized register). */
export const ZERO_PCR_HASH = sha256Truncated("0".repeat(64));
