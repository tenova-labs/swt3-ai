/**
 * Tests for deployment context detection.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { sha256Truncated } from "../src/fingerprint.js";

// We need to control process.env, so import after setup
let detectDeploymentContext: typeof import("../src/deployment.js").detectDeploymentContext;
let contextToObservations: typeof import("../src/deployment.js").contextToObservations;
let resetCache: typeof import("../src/deployment.js").resetCache;

beforeEach(async () => {
  const mod = await import("../src/deployment.js");
  detectDeploymentContext = mod.detectDeploymentContext;
  contextToObservations = mod.contextToObservations;
  resetCache = mod.resetCache;
  resetCache();
});

describe("detectDeploymentContext", () => {
  const originalEnv = { ...process.env };
  afterEach(() => { process.env = { ...originalEnv }; resetCache(); });

  it("returns unknown defaults when no env vars set", () => {
    // Clear relevant env vars
    delete process.env.AWS_REGION;
    delete process.env.AWS_DEFAULT_REGION;
    delete process.env.GOOGLE_CLOUD_PROJECT;
    delete process.env.AZURE_RESOURCE_GROUP;
    delete process.env.KUBERNETES_SERVICE_HOST;
    delete process.env.LAMBDA_TASK_ROOT;
    delete process.env.NVIDIA_VISIBLE_DEVICES;
    delete process.env.CUDA_VISIBLE_DEVICES;
    delete process.env.TPU_NAME;
    const ctx = detectDeploymentContext({ force: true });
    expect(ctx.cloud_provider).toBe("unknown");
    expect(ctx.accelerator_type).toBe("none");
  });

  it("detects AWS from env vars", () => {
    process.env.AWS_REGION = "us-east-1";
    process.env.AWS_AVAILABILITY_ZONE = "us-east-1a";
    const ctx = detectDeploymentContext({ force: true });
    expect(ctx.cloud_provider).toBe("aws");
    expect(ctx.region).toBe("us-east-1");
    expect(ctx.availability_zone).toBe("us-east-1a");
  });

  it("detects GCP from env vars", () => {
    delete process.env.AWS_REGION;
    delete process.env.AWS_DEFAULT_REGION;
    process.env.GOOGLE_CLOUD_PROJECT = "my-project";
    process.env.GOOGLE_CLOUD_REGION = "us-central1";
    const ctx = detectDeploymentContext({ force: true });
    expect(ctx.cloud_provider).toBe("gcp");
    expect(ctx.region).toBe("us-central1");
  });

  it("detects Azure from env vars", () => {
    delete process.env.AWS_REGION;
    delete process.env.AWS_DEFAULT_REGION;
    delete process.env.GOOGLE_CLOUD_PROJECT;
    process.env.AZURE_RESOURCE_GROUP = "my-rg";
    process.env.REGION_NAME = "eastus";
    const ctx = detectDeploymentContext({ force: true });
    expect(ctx.cloud_provider).toBe("azure");
    expect(ctx.region).toBe("eastus");
  });

  it("detects Kubernetes runtime", () => {
    process.env.KUBERNETES_SERVICE_HOST = "10.0.0.1";
    process.env.HOSTNAME = "pod-abc123";
    const ctx = detectDeploymentContext({ force: true });
    expect(ctx.runtime).toBe("kubernetes");
    expect(ctx.container_id).toBe(sha256Truncated("pod-abc123"));
  });

  it("detects Lambda runtime", () => {
    process.env.AWS_REGION = "us-west-2";
    process.env.LAMBDA_TASK_ROOT = "/var/task";
    const ctx = detectDeploymentContext({ force: true });
    expect(ctx.runtime).toBe("lambda");
    expect(ctx.cloud_provider).toBe("aws");
  });

  it("detects NVIDIA GPUs", () => {
    process.env.NVIDIA_VISIBLE_DEVICES = "0,1,2";
    const ctx = detectDeploymentContext({ force: true });
    expect(ctx.accelerator_type).toBe("nvidia-gpu");
    expect(ctx.accelerator_count).toBe(3);
  });

  it("handles NVIDIA all GPUs", () => {
    process.env.NVIDIA_VISIBLE_DEVICES = "all";
    const ctx = detectDeploymentContext({ force: true });
    expect(ctx.accelerator_type).toBe("nvidia-gpu");
    expect(ctx.accelerator_count).toBe(-1);
  });

  it("caches results", () => {
    process.env.AWS_REGION = "us-east-1";
    const ctx1 = detectDeploymentContext({ force: true });
    process.env.AWS_REGION = "eu-west-1";
    const ctx2 = detectDeploymentContext(); // should use cache
    expect(ctx2.region).toBe("us-east-1");
  });
});

describe("contextToObservations", () => {
  const ctx = {
    cloud_provider: "aws",
    region: "us-east-1",
    availability_zone: "us-east-1a",
    runtime: "kubernetes",
    container_id: "abc123",
    accelerator_type: "nvidia-gpu",
    accelerator_count: 4,
  };

  it("returns full context at CL 1", () => {
    const obs = contextToObservations(ctx, 1);
    expect(obs.cloud_provider).toBe("aws");
    expect(obs.region).toBe("us-east-1");
    expect(obs.runtime).toBe("kubernetes");
    expect(obs.accelerator_count).toBe(4);
  });

  it("redacts at CL 2", () => {
    const obs = contextToObservations(ctx, 2);
    expect(obs.cloud_provider).toBe("aws");
    expect(obs.runtime).toBe("kubernetes");
    expect(obs).not.toHaveProperty("region");
  });

  it("hashes at CL 3", () => {
    const obs = contextToObservations(ctx, 3);
    expect(obs.cloud_provider).toBe(sha256Truncated("aws", 8));
    expect(obs.runtime).toBe(sha256Truncated("kubernetes", 8));
    expect(obs.region).toBe(sha256Truncated("us-east-1", 8));
  });
});
