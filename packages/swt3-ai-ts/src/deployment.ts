/**
 * SWT3 AI Witness SDK -- Deployment Context Detection.
 *
 * Auto-detects cloud provider, region, runtime environment, and
 * accelerator hardware from environment variables.
 *
 * Detection is best-effort and never blocks. Unknown fields remain
 * as "unknown". Container IDs and hostnames are SHA-256 hashed.
 */

import { sha256Truncated } from "./fingerprint.js";
import { existsSync } from "node:fs";

export interface DeploymentContext {
  cloud_provider: string;
  region: string;
  availability_zone: string;
  runtime: string;
  container_id: string;
  accelerator_type: string;
  accelerator_count: number;
}

let _cachedContext: DeploymentContext | null = null;
let _cacheExpiry = 0;
const CACHE_TTL_MS = 300_000; // 5 minutes

/**
 * Detect deployment environment from env vars.
 * Cached for 5 minutes. Pass force=true to bypass cache.
 */
export function detectDeploymentContext(opts?: { force?: boolean }): DeploymentContext {
  const now = Date.now();
  if (!opts?.force && _cachedContext && now < _cacheExpiry) {
    return _cachedContext;
  }

  const env = process.env;
  const ctx: DeploymentContext = {
    cloud_provider: "unknown",
    region: "unknown",
    availability_zone: "unknown",
    runtime: "unknown",
    container_id: "unknown",
    accelerator_type: "none",
    accelerator_count: 0,
  };

  // -- Cloud Provider --
  if (env.AWS_REGION || env.AWS_DEFAULT_REGION) {
    ctx.cloud_provider = "aws";
    ctx.region = env.AWS_REGION || env.AWS_DEFAULT_REGION || "unknown";
    ctx.availability_zone = env.AWS_AVAILABILITY_ZONE || "unknown";
  } else if (env.GOOGLE_CLOUD_PROJECT || env.GCLOUD_PROJECT) {
    ctx.cloud_provider = "gcp";
    ctx.region = env.GOOGLE_CLOUD_REGION || env.CLOUD_RUN_REGION || "unknown";
    ctx.availability_zone = env.GOOGLE_CLOUD_ZONE || "unknown";
  } else if (env.AZURE_RESOURCE_GROUP || env.WEBSITE_SITE_NAME) {
    ctx.cloud_provider = "azure";
    ctx.region = env.REGION_NAME || env.WEBSITE_REGION || "unknown";
  } else if (env.VULTR_API_KEY || env.VULTR_REGION) {
    ctx.cloud_provider = "vultr";
    ctx.region = env.VULTR_REGION || "unknown";
  }

  // -- Runtime --
  if (env.KUBERNETES_SERVICE_HOST) {
    ctx.runtime = "kubernetes";
    ctx.container_id = sha256Truncated(env.HOSTNAME || "unknown");
  } else if (env.LAMBDA_TASK_ROOT || env.AWS_LAMBDA_FUNCTION_NAME) {
    ctx.runtime = "lambda";
  } else if (env.ECS_CONTAINER_METADATA_URI || env.ECS_CONTAINER_METADATA_URI_V4) {
    ctx.runtime = "ecs";
    ctx.container_id = sha256Truncated(env.HOSTNAME || "unknown");
  } else if (env.CLOUD_RUN_JOB || env.K_SERVICE) {
    ctx.runtime = "cloud-run";
  } else if (env.AZURE_FUNCTIONS_ENVIRONMENT) {
    ctx.runtime = "azure-functions";
  } else {
    try {
      if (existsSync("/.dockerenv") || existsSync("/run/.containerenv")) {
        ctx.runtime = "container";
        ctx.container_id = sha256Truncated(env.HOSTNAME || "unknown");
      } else {
        ctx.runtime = "bare-metal";
      }
    } catch {
      ctx.runtime = "bare-metal";
    }
  }

  // -- Accelerator --
  const nvDevices = env.NVIDIA_VISIBLE_DEVICES || env.CUDA_VISIBLE_DEVICES;
  if (nvDevices && nvDevices !== "none") {
    ctx.accelerator_type = "nvidia-gpu";
    ctx.accelerator_count = nvDevices === "all" ? -1 : nvDevices.split(",").length;
  } else if (env.TPU_NAME || env.TPU_WORKER_HOSTNAMES) {
    ctx.accelerator_type = "tpu";
    ctx.accelerator_count = 1;
  } else if (env.NEURON_RT_VISIBLE_CORES) {
    ctx.accelerator_type = "aws-neuron";
    ctx.accelerator_count = env.NEURON_RT_VISIBLE_CORES.split(",").length;
  }

  _cachedContext = ctx;
  _cacheExpiry = now + CACHE_TTL_MS;
  return ctx;
}

/**
 * Convert DeploymentContext to observations dict, clearing-level aware.
 *
 * CL 0-1: Full context.
 * CL 2: Provider + runtime only.
 * CL 3: All fields hashed.
 */
export function contextToObservations(
  ctx: DeploymentContext,
  clearingLevel: number = 1,
): Record<string, unknown> {
  if (clearingLevel <= 1) {
    return { ...ctx };
  } else if (clearingLevel === 2) {
    return {
      cloud_provider: ctx.cloud_provider,
      runtime: ctx.runtime,
      accelerator_type: ctx.accelerator_type,
      accelerator_count: ctx.accelerator_count,
    };
  } else {
    return {
      cloud_provider: sha256Truncated(ctx.cloud_provider, 8),
      runtime: sha256Truncated(ctx.runtime, 8),
      region: sha256Truncated(ctx.region, 8),
    };
  }
}

/** Reset the cache (for testing). */
export function resetCache(): void {
  _cachedContext = null;
  _cacheExpiry = 0;
}
