/**
 * SWT3 AI Witness SDK -- Hardware Discovery (AI-HW.1, AI-HW.3).
 *
 * Out-of-band hardware inventory snapshots. Records what GPU hardware
 * and TPM state were present when the service started.
 * Does NOT sit in the inference path.
 *
 * Data sources:
 *   - nvidia-smi subprocess for GPU discovery (AI-HW.1)
 *   - tpm2-tools subprocess for TPM 2.0 attestation (AI-HW.3)
 *
 * Security: All hardware identifiers (GPU UUIDs, bus IDs, hostnames,
 * PCR digests, endorsement keys) are SHA-256 hashed at discovery time.
 * Raw values never leave this module.
 */

import { execSync } from "node:child_process";
import { hostname } from "node:os";
import { sha256Truncated } from "./fingerprint.js";

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
  topology: string;    // NVL72, DGX-H100, DGX-A100, HGX, multi-gpu, single, unknown
  interconnect: string; // nvswitch, nvlink, pcie, unknown
  totalMemoryMb: number;
  hostnameHash: string; // SHA-256 truncated, never cleartext
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
 * Query GPU hardware and return a pre-hashed snapshot.
 * Returns empty snapshot if no GPUs are detectable.
 */
export function queryHardware(): HardwareSnapshot {
  const [gpus, driverVersion] = queryNvidiaSmi();
  const topology = detectTopology(gpus);
  // Only query interconnect if GPUs were found (avoids unnecessary subprocess)
  const interconnect = gpus.length > 0 ? detectInterconnect() : "unknown";
  const totalMemoryMb = gpus.reduce((sum, g) => sum + g.memoryMb, 0);
  const hostnameHash = sha256Truncated(hostname());

  return {
    gpus,
    driverVersion,
    cudaVersion: "", // Not available via nvidia-smi CSV
    topology,
    interconnect,
    totalMemoryMb,
    hostnameHash,
  };
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
