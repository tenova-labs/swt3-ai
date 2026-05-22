/**
 * SWT3 AI Witness SDK -- Environmental Telemetry (AI-ENV.1 / AI-ENV.2).
 *
 * Out-of-band thermal and power snapshot for distributed AI compute nodes.
 * Reads Linux sysfs sensors automatically. Graceful no-op on non-Linux
 * or when sensors are unavailable.
 *
 * Security: hostnames are SHA-256 hashed at discovery time.
 * No GPS, no PII, no raw identifiers leave this module.
 *
 * Usage:
 *   import { queryEnvironment } from "@tenova/swt3-ai";
 *   const snap = queryEnvironment();
 *   // -> { temperatureCelsius: 42, powerWatts: 120, ... }
 *
 *   // Or let the Witness handle it:
 *   witness.witnessEnvironment();
 *   witness.witnessEnergyDraw();
 */

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { hostname } from "node:os";
import { sha256Truncated } from "./fingerprint.js";

export interface EnvironmentSnapshot {
  temperatureCelsius: number;  // highest detected temp (0 if unavailable)
  powerWatts: number;          // total power draw (0 if unavailable)
  thermalZones: number;        // count of thermal zones detected
  powerDomains: number;        // count of power domains detected
  hostnameHash: string;        // SHA-256 truncated, never cleartext
  nodeType: string;            // unknown, datacenter, edge, residential
}

export const NODE_TYPE_CODES: Record<string, number> = {
  unknown: 0,
  datacenter: 1,
  edge: 2,
  residential: 3,
  mobile: 4,
};

/**
 * Query thermal and power sensors. Returns a snapshot with best-effort
 * readings. If no sensors are available, all values are 0.
 */
export function queryEnvironment(): EnvironmentSnapshot {
  const tempC = readThermalZones();
  const power = readPowerDomains();
  return {
    temperatureCelsius: tempC.max,
    powerWatts: power.total,
    thermalZones: tempC.count,
    powerDomains: power.count,
    hostnameHash: sha256Truncated(hostname()),
    nodeType: "unknown",
  };
}

function readThermalZones(): { max: number; count: number } {
  const base = "/sys/class/thermal";
  try {
    if (!existsSync(base)) return { max: 0, count: 0 };
    const zones = readdirSync(base).filter((d) => d.startsWith("thermal_zone"));
    let max = 0;
    let count = 0;
    for (const zone of zones) {
      try {
        const raw = readFileSync(`${base}/${zone}/temp`, "utf-8").trim();
        const millideg = parseInt(raw, 10);
        if (!isNaN(millideg)) {
          const celsius = Math.round(millideg / 1000);
          if (celsius > max) max = celsius;
          count++;
        }
      } catch { /* skip unreadable zone */ }
    }
    return { max, count };
  } catch {
    return { max: 0, count: 0 };
  }
}

function readPowerDomains(): { total: number; count: number } {
  const base = "/sys/class/powercap";
  try {
    if (!existsSync(base)) return { total: 0, count: 0 };
    const domains = readdirSync(base).filter((d) => d.startsWith("intel-rapl"));
    let total = 0;
    let count = 0;
    for (const domain of domains) {
      try {
        const raw = readFileSync(`${base}/${domain}/energy_uj`, "utf-8").trim();
        const uj = parseInt(raw, 10);
        if (!isNaN(uj)) count++;
      } catch { /* skip unreadable domain */ }
    }
    // Power in watts requires two readings with a time delta.
    // For a snapshot, report domain count. Actual wattage comes
    // from manual input or external APIs (Span panel, IPMI, etc.).
    return { total, count };
  } catch {
    return { total: 0, count: 0 };
  }
}
