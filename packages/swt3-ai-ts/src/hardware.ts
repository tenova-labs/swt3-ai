/**
 * SWT3 AI Witness SDK -- Hardware Discovery (AI-HW.1, AI-HW.3).
 *
 * Out-of-band hardware inventory snapshots. Records what accelerator
 * hardware and TPM state were present when the service started.
 * Does NOT sit in the inference path.
 *
 * Discovery paths (priority order):
 *   1. NVIDIA GPU -- nvidia-smi subprocess
 *   2. Google TPU -- TPU_NAME / TPU_WORKER_HOSTNAMES env vars
 *   3. AMD GPU -- rocm-smi subprocess
 *   4. AWS Trainium/Inferentia -- neuron-ls subprocess
 *   5. Intel Gaudi -- hl-smi subprocess
 *   6. PCI fallback -- /sys/bus/pci/devices sysfs (Linux only)
 *   7. TPM 2.0 -- tpm2-tools subprocess (AI-HW.3, separate procedure)
 *
 * Security: All hardware identifiers (GPU UUIDs, bus IDs, hostnames,
 * PCR digests, endorsement keys, serial numbers) are SHA-256 hashed
 * at discovery time. Raw values never leave this module.
 */

import { execSync } from "node:child_process";
import { hostname, platform } from "node:os";
import { readdirSync, readFileSync } from "node:fs";
import { sha256Truncated } from "./fingerprint.js";

// ── Types ───────────────────────────────────────────────────────────

export type SiliconVendor = "nvidia" | "google-tpu" | "amd" | "aws-trainium" | "intel-gaudi" | "pci-generic" | "mixed" | "none";

export interface AcceleratorInfo {
  vendor: SiliconVendor;
  name: string;
  memoryMb: number;
  idHash: string;          // SHA-256 truncated device identifier
  busIdHash: string;       // SHA-256 truncated bus/slot ID
  discoveryMethod: string; // nvidia-smi, tpu-env, rocm-smi, neuron-ls, hl-smi, pci-sysfs
}

export interface GpuInfo {
  name: string;
  memoryMb: number;
  busIdHash: string;   // SHA-256 truncated, never cleartext
  uuidHash: string;    // SHA-256 truncated, never cleartext
}

export interface HardwareSnapshot {
  gpus: GpuInfo[];
  driverVersion: string;
  cudaVersion: string;
  topology: string;
  interconnect: string;
  totalMemoryMb: number;
  hostnameHash: string;
  accelerators: AcceleratorInfo[];
  siliconVendor: SiliconVendor;
  discoveryMethod: string; // comma-separated methods that returned results
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
  "tpu-single": 0,
  "tpu-pod": 2,
  "mi-single": 0,
  "mi-cluster": 1,
  "trn-single": 0,
  "trn-cluster": 1,
  "inf-single": 0,
  "gaudi-single": 0,
  "gaudi-cluster": 1,
  unknown: 3,
};

/** PCI vendor ID to SiliconVendor mapping. */
const PCI_VENDOR_MAP: Record<string, SiliconVendor> = {
  "0x10de": "nvidia",
  "0x1002": "amd",
  "0x8086": "intel-gaudi",
  "0x1d0f": "aws-trainium",  // Annapurna Labs
  "0x1ae0": "google-tpu",
};

// ── Cross-Silicon Discovery ──────────────────────────────────────────

/** Google TPU: reads TPU_NAME and TPU_WORKER_HOSTNAMES env vars. */
export function queryGoogleTPU(): AcceleratorInfo[] {
  const tpuName = process.env.TPU_NAME;
  if (!tpuName) return [];

  const workers = process.env.TPU_WORKER_HOSTNAMES;
  const chipCount = workers ? workers.split(",").length : 1;

  // Infer memory from TPU generation
  const upper = tpuName.toUpperCase();
  let memMb = 0;
  if (upper.includes("V6E") || upper.includes("TRILLIUM")) memMb = 32_768;
  else if (upper.includes("V5P")) memMb = 95_000;
  else if (upper.includes("V5E") || upper.includes("V5LITEPOD")) memMb = 16_384;
  else if (upper.includes("V4")) memMb = 32_768;

  const accels: AcceleratorInfo[] = [];
  for (let i = 0; i < chipCount; i++) {
    accels.push({
      vendor: "google-tpu",
      name: tpuName,
      memoryMb: memMb,
      idHash: sha256Truncated(`${tpuName}-chip-${i}`),
      busIdHash: sha256Truncated(`tpu-${tpuName}-${i}`),
      discoveryMethod: "tpu-env",
    });
  }
  return accels;
}

/** AMD GPU: queries rocm-smi for MI-series accelerators. */
export function queryAmdRocm(): [AcceleratorInfo[], string] {
  try {
    const output = execSync(
      "rocm-smi --showproductname --showmeminfo vram --showbus --csv",
      { timeout: 5_000, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
    );
    const accels: AcceleratorInfo[] = [];
    let driver = "";
    for (const line of output.trim().split("\n").slice(1)) {
      if (!line.trim()) continue;
      const parts = line.split(",").map((p) => p.trim());
      if (parts.length < 4) continue;
      const [devId, name, memStr, busId] = parts;
      accels.push({
        vendor: "amd",
        name: name || `AMD-${devId}`,
        memoryMb: Math.round(parseFloat(memStr) / 1_048_576) || 0, // bytes to MB
        idHash: sha256Truncated(devId),
        busIdHash: sha256Truncated(busId),
        discoveryMethod: "rocm-smi",
      });
    }
    try {
      driver = execSync("rocm-smi --showdriverversion --csv", {
        timeout: 5_000, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"],
      }).trim().split("\n").pop()?.trim() ?? "";
    } catch { /* optional */ }
    return [accels, driver];
  } catch {
    return [[], ""];
  }
}

/** AWS Trainium/Inferentia: queries neuron-ls for Neuron devices. */
export function queryAwsNeuron(): AcceleratorInfo[] {
  try {
    const output = execSync("neuron-ls --json-output", {
      timeout: 5_000, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"],
    });
    const devices = JSON.parse(output);
    if (!Array.isArray(devices)) return [];
    return devices.map((d: Record<string, unknown>, i: number) => ({
      vendor: "aws-trainium" as SiliconVendor,
      name: String(d.model_name ?? d.model ?? `neuron-${i}`),
      memoryMb: Number(d.memory_size ?? 0),
      idHash: sha256Truncated(String(d.neuron_device ?? d.device_id ?? i)),
      busIdHash: sha256Truncated(String(d.pci_bdf ?? d.connected_to ?? `neuron-bus-${i}`)),
      discoveryMethod: "neuron-ls",
    }));
  } catch {
    return [];
  }
}

/** Intel Gaudi: queries hl-smi for Habana accelerators. */
export function queryIntelGaudi(): [AcceleratorInfo[], string] {
  try {
    const output = execSync(
      "hl-smi -Q name,memory.total,bus_id,serial -f csv,noheader,nounits",
      { timeout: 5_000, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
    );
    const accels: AcceleratorInfo[] = [];
    for (const line of output.trim().split("\n")) {
      if (!line.trim()) continue;
      const parts = line.split(",").map((p) => p.trim());
      if (parts.length < 4) continue;
      const [name, memStr, busId, serial] = parts;
      accels.push({
        vendor: "intel-gaudi",
        name,
        memoryMb: Math.round(parseFloat(memStr)) || 0,
        idHash: sha256Truncated(serial),
        busIdHash: sha256Truncated(busId),
        discoveryMethod: "hl-smi",
      });
    }
    let driver = "";
    try {
      driver = execSync("hl-smi -Q driver_version -f csv,noheader", {
        timeout: 5_000, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"],
      }).trim();
    } catch { /* optional */ }
    return [accels, driver];
  } catch {
    return [[], ""];
  }
}

/** PCI fallback: scans /sys/bus/pci/devices for accelerator class codes. Linux only. */
export function queryPciFallback(seenBusIds: Set<string> = new Set()): AcceleratorInfo[] {
  if (platform() !== "linux") return [];
  const accels: AcceleratorInfo[] = [];
  try {
    const devDir = "/sys/bus/pci/devices";
    const entries = readdirSync(devDir);
    for (const entry of entries) {
      try {
        const classCode = readFileSync(`${devDir}/${entry}/class`, "utf-8").trim();
        // 0x0302xx = 3D controller, 0x1200xx = processing accelerator
        if (!classCode.startsWith("0x0302") && !classCode.startsWith("0x1200")) continue;
        const busHash = sha256Truncated(entry);
        if (seenBusIds.has(busHash)) continue;
        const vendorId = readFileSync(`${devDir}/${entry}/vendor`, "utf-8").trim();
        const deviceId = readFileSync(`${devDir}/${entry}/device`, "utf-8").trim();
        const vendor = PCI_VENDOR_MAP[vendorId] ?? "pci-generic";
        accels.push({
          vendor,
          name: `PCI-${vendorId}-${deviceId}`,
          memoryMb: 0,
          idHash: sha256Truncated(`${vendorId}:${deviceId}:${entry}`),
          busIdHash: busHash,
          discoveryMethod: "pci-sysfs",
        });
      } catch { /* individual device read failure, skip */ }
    }
  } catch { /* /sys not accessible */ }
  return accels;
}

// ── Main Discovery ──────────────────────────────────────────────────

/**
 * Query all accelerator hardware and return a pre-hashed snapshot.
 * Tries all 6 discovery paths. Returns empty snapshot if nothing found.
 */
export function queryHardware(): HardwareSnapshot {
  // 1. NVIDIA (existing path)
  const [gpus, driverVersion] = queryNvidiaSmi();
  const nvidiaAccels: AcceleratorInfo[] = gpus.map((g) => ({
    vendor: "nvidia" as SiliconVendor,
    name: g.name,
    memoryMb: g.memoryMb,
    idHash: g.uuidHash,
    busIdHash: g.busIdHash,
    discoveryMethod: "nvidia-smi",
  }));

  // 2-5. Non-NVIDIA discovery
  const tpuAccels = queryGoogleTPU();
  const [amdAccels] = queryAmdRocm();
  const neuronAccels = queryAwsNeuron();
  const [gaudiAccels] = queryIntelGaudi();

  // 6. PCI fallback (skip already-discovered bus IDs)
  const seenBusIds = new Set<string>();
  for (const a of [...nvidiaAccels, ...tpuAccels, ...amdAccels, ...neuronAccels, ...gaudiAccels]) {
    seenBusIds.add(a.busIdHash);
  }
  const pciAccels = queryPciFallback(seenBusIds);

  // Aggregate
  const accelerators = [...nvidiaAccels, ...tpuAccels, ...amdAccels, ...neuronAccels, ...gaudiAccels, ...pciAccels];

  // Determine silicon vendor
  const vendors = new Set(accelerators.map((a) => a.vendor));
  let siliconVendor: SiliconVendor = "none";
  if (vendors.size === 1) siliconVendor = [...vendors][0];
  else if (vendors.size > 1) siliconVendor = "mixed";

  // Build discovery method string
  const methods = new Set(accelerators.map((a) => a.discoveryMethod));
  const discoveryMethod = [...methods].join(",");

  // Topology + interconnect
  const topology = detectTopology(gpus, accelerators);
  const interconnect = gpus.length > 0 ? detectInterconnect() : "unknown";
  const totalMemoryMb = accelerators.reduce((sum, a) => sum + a.memoryMb, 0);
  const hostnameHash = sha256Truncated(hostname());

  return {
    gpus,
    driverVersion,
    cudaVersion: "",
    topology,
    interconnect,
    totalMemoryMb,
    hostnameHash,
    accelerators,
    siliconVendor,
    discoveryMethod,
  };
}

/**
 * Infer cluster topology from GPU count, model names, and accelerators.
 */
export function detectTopology(gpus: GpuInfo[], accelerators?: AcceleratorInfo[]): string {
  // NVIDIA path (existing logic, unchanged)
  if (gpus.length > 0) {
    const count = gpus.length;
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

  // Non-NVIDIA path: infer from accelerators
  if (!accelerators || accelerators.length === 0) return "unknown";
  const count = accelerators.length;
  const vendor = accelerators[0].vendor;

  if (vendor === "google-tpu") return count > 1 ? "tpu-pod" : "tpu-single";
  if (vendor === "amd") return count > 1 ? "mi-cluster" : "mi-single";
  if (vendor === "aws-trainium") {
    const name = accelerators[0].name.toLowerCase();
    if (name.includes("inf")) return count > 1 ? "inf-single" : "inf-single"; // Inferentia doesn't cluster the same way
    return count > 1 ? "trn-cluster" : "trn-single";
  }
  if (vendor === "intel-gaudi") return count > 1 ? "gaudi-cluster" : "gaudi-single";

  return count > 1 ? "multi-gpu" : "single";
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
