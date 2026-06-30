/**
 * SWT3 Witness Node Agent
 *
 * Discovers accelerator hardware on Kubernetes nodes and mints
 * AI-HW.1 Witness Anchors. Runs as a DaemonSet pod -- one per node.
 *
 * Local mode (default): anchors emit as structured JSON to stdout.
 * Cloud mode: anchors flush to the SWT3 clearing house AND stdout.
 *
 * Hardware discovery covers NVIDIA GPU, Google TPU, AMD MI,
 * AWS Trainium/Inferentia, Intel Gaudi, and PCI fallback.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import {
  queryHardware,
  topologyCode,
  mintFingerprint,
  timestampMs,
  Witness,
  type HardwareSnapshot,
  type WitnessPayload,
  type GpuInfo,
} from "@tenova/swt3-ai";

// ── Version ─────────────────────────────────────────────────────────

const VERSION = "0.5.8";

// ── Configuration ───────────────────────────────────────────────────

const VALID_MODES = ["local", "cloud"] as const;
const rawMode = process.env.SWT3_MODE ?? "local";
if (!VALID_MODES.includes(rawMode as typeof VALID_MODES[number])) {
  console.error(JSON.stringify({
    swt3_witness: true,
    level: "error",
    message: `Invalid SWT3_MODE "${rawMode}". Must be "local" or "cloud".`,
  }));
  process.exit(1);
}
const MODE = rawMode as typeof VALID_MODES[number];

const rawInterval = parseInt(process.env.SWT3_INTERVAL ?? "3600", 10);
const INTERVAL = (rawInterval > 0 ? rawInterval : 3600) * 1000;

const rawClearingLevel = parseInt(process.env.SWT3_CLEARING_LEVEL ?? "1", 10);
const CLEARING_LEVEL = (rawClearingLevel >= 0 && rawClearingLevel <= 3 ? rawClearingLevel : 1) as 0 | 1 | 2 | 3;

const AGENT_ID = process.env.SWT3_AGENT_ID || `witness-${(process.env.HOSTNAME ?? "node").slice(0, 12)}`;
const HEALTH_PORT = parseInt(process.env.SWT3_HEALTH_PORT ?? "9090", 10);
const TENANT_ID = process.env.SWT3_TENANT_ID ?? "";
const API_KEY = process.env.SWT3_API_KEY ?? "";
const ENDPOINT = process.env.SWT3_ENDPOINT ?? "https://sovereign.tenova.io";
const SIGNING_KEY = process.env.SWT3_SIGNING_KEY ?? "";

// ── State ───────────────────────────────────────────────────────────

let lastAttestation = 0;
let lastSnapshot: HardwareSnapshot | null = null;
let witness: InstanceType<typeof Witness> | null = null;

// ── Cloud mode witness ──────────────────────────────────────────────

if (MODE === "cloud") {
  if (!API_KEY || !TENANT_ID) {
    console.error(JSON.stringify({
      swt3_witness: true,
      level: "error",
      message: "Cloud mode requires SWT3_API_KEY and SWT3_TENANT_ID",
    }));
    process.exit(1);
  }

  witness = new Witness({
    endpoint: ENDPOINT,
    apiKey: API_KEY,
    tenantId: TENANT_ID,
    clearingLevel: CLEARING_LEVEL,
    agentId: AGENT_ID,
    signingKey: SIGNING_KEY || undefined,
    onFlush: (payloads: WitnessPayload[]) => {
      for (const p of payloads) {
        console.log(JSON.stringify({ swt3_witness: true, ...p }));
      }
    },
  });
}

// ── Discovery + Attestation ─────────────────────────────────────────

function discover(): void {
  const snapshot = queryHardware();
  lastSnapshot = snapshot;
  lastAttestation = Date.now();

  const accelCount = snapshot.accelerators?.length ?? snapshot.gpus.length;
  const health = accelCount > 0 ? 1 : 0;
  const topoCode = topologyCode(snapshot.topology);

  if (MODE === "cloud" && witness) {
    witness.witnessHardware({ snapshot });
  } else {
    const [tsMs, epoch] = timestampMs();
    const fp = mintFingerprint(
      TENANT_ID || "LOCAL",
      "AI-HW.1",
      accelCount,
      health,
      topoCode,
      tsMs,
    );

    console.log(JSON.stringify({
      swt3_witness: true,
      procedure: "AI-HW.1",
      anchor_fingerprint: fp,
      anchor_epoch: epoch,
      factor_a: accelCount,
      factor_b: health,
      factor_c: topoCode,
      clearing_level: CLEARING_LEVEL,
      agent_id: AGENT_ID,
      silicon_vendor: snapshot.siliconVendor ?? "none",
      discovery_method: snapshot.discoveryMethod ?? "",
      topology: snapshot.topology,
      accelerator_count: accelCount,
      gpu_count: snapshot.gpus.length,
      total_memory_mb: snapshot.totalMemoryMb,
      hostname_hash: snapshot.hostnameHash,
      timestamp: new Date(tsMs).toISOString(),
    }));
  }
}

// ── Health Server ───────────────────────────────────────────────────

const server = createServer((req: IncomingMessage, res: ServerResponse) => {
  if (req.url === "/health" || req.url === "/healthz") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      status: "ok",
      version: VERSION,
      mode: MODE,
      last_attestation: lastAttestation > 0 ? new Date(lastAttestation).toISOString() : null,
      silicon_vendor: lastSnapshot?.siliconVendor ?? null,
      topology: lastSnapshot?.topology ?? null,
      accelerator_count: lastSnapshot?.accelerators?.length ?? 0,
      gpu_count: lastSnapshot?.gpus.length ?? 0,
      pending: witness?.pending ?? 0,
    }));
    return;
  }
  res.writeHead(404);
  res.end();
});

// ── Startup ─────────────────────────────────────────────────────────

console.log(JSON.stringify({
  swt3_witness: true,
  level: "info",
  message: "SWT3 Witness starting",
  version: VERSION,
  mode: MODE,
  interval_seconds: INTERVAL / 1000,
  clearing_level: CLEARING_LEVEL,
  agent_id: AGENT_ID,
  health_port: HEALTH_PORT,
}));

discover();

const intervalId = setInterval(discover, INTERVAL);

server.listen(HEALTH_PORT, () => {
  console.log(JSON.stringify({
    swt3_witness: true,
    level: "info",
    message: `Health server listening on :${HEALTH_PORT}`,
  }));
});

// ── Graceful Shutdown ───────────────────────────────────────────────

async function shutdown(): Promise<void> {
  console.log(JSON.stringify({
    swt3_witness: true,
    level: "info",
    message: "Shutting down",
  }));
  clearInterval(intervalId);
  if (witness) await witness.stop();
  server.close();
  process.exit(0);
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
