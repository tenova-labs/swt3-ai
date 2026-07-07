/**
 * SWT3 Crosswalk Resolver -- offline regulatory mapping.
 *
 * Maps SWT3 procedures to framework requirements using the bundled
 * crosswalks.json. Zero network calls, zero dependencies.
 *
 *   import { resolve } from "@tenova/swt3-ai";
 *   resolve("AI-FAIR.1");
 *   // { "EU-AI-ACT": "Art.10", "NIST-AI-RMF": "MAP 2.1", ... }
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

interface CrosswalkData {
  schema_version: string;
  generated_at: string;
  frameworks: Record<string, FrameworkMeta>;
  procedures: Record<string, ProcedureMeta>;
  by_framework: Record<string, Record<string, string[]>>;
}

export interface FrameworkMeta {
  name: string;
  authority?: string;
  document?: string;
  version?: string;
  url?: string;
  enforcement_date?: string;
  procedure_count: number;
  requirement_count?: number;
}

export interface ProcedureMeta {
  title: string;
  namespace: string;
  frameworks: Record<string, string>;
}

const STALENESS_DAYS = 90;
let _data: CrosswalkData | null = null;

function load(): CrosswalkData {
  if (_data) return _data;

  const dir = dirname(fileURLToPath(import.meta.url));
  const dataPath = join(dir, "data", "crosswalks.json");
  _data = JSON.parse(readFileSync(dataPath, "utf-8"));

  if (_data!.generated_at) {
    const ageDays = Math.floor(
      (Date.now() - new Date(_data!.generated_at).getTime()) / 86_400_000,
    );
    if (ageDays > STALENESS_DAYS) {
      console.warn(
        `[swt3-ai] Bundled crosswalks.json is ${ageDays} days old ` +
          `(generated ${_data!.generated_at}). Update @tenova/swt3-ai ` +
          `for current regulatory mappings.`,
      );
    }
  }

  return _data!;
}

/** Resolve a procedure to all framework controls it satisfies. */
export function resolve(procedureId: string): Record<string, string> {
  const proc = load().procedures[procedureId];
  return proc ? { ...proc.frameworks } : {};
}

/** Resolve a framework to all its requirement-to-procedure mappings. */
export function resolveFramework(
  frameworkId: string,
): Record<string, string[]> {
  const fw = load().by_framework[frameworkId];
  if (!fw) return {};
  const result: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(fw)) result[k] = [...v];
  return result;
}

/** Return metadata for all known frameworks. */
export function frameworks(): Record<string, FrameworkMeta> {
  return JSON.parse(JSON.stringify(load().frameworks));
}

/** Return metadata for all known procedures. */
export function procedures(): Record<string, ProcedureMeta> {
  return JSON.parse(JSON.stringify(load().procedures));
}

/** Return the generated_at timestamp of the bundled crosswalks. */
export function crosswalkVersion(): string {
  return load().generated_at ?? "unknown";
}
