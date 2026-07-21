"""SWT3 AI Witness SDK -- Deployment Context Detection.

Auto-detects cloud provider, region, runtime environment, and
accelerator hardware from environment variables and metadata.
Results are embedded in witness payloads as deployment_context.

Detection is best-effort and never blocks. Unknown fields remain
as "unknown". All raw identifiers are hashing-safe (no secrets).

Security: Container IDs and hostnames are SHA-256 hashed before
inclusion in any witness payload.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional

from .fingerprint import sha256_truncated


@dataclass
class DeploymentContext:
    cloud_provider: str = "unknown"
    region: str = "unknown"
    availability_zone: str = "unknown"
    runtime: str = "unknown"
    container_id: str = "unknown"
    accelerator_type: str = "none"
    accelerator_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Module-level cache
_cached_context: Optional[DeploymentContext] = None
_cache_expiry: float = 0.0
_CACHE_TTL_SECONDS = 300  # 5 minutes


def detect_deployment_context(*, force: bool = False) -> DeploymentContext:
    """Detect deployment environment from env vars and metadata.

    Cached for 5 minutes. Pass force=True to bypass cache.
    """
    global _cached_context, _cache_expiry

    now = time.monotonic()
    if not force and _cached_context is not None and now < _cache_expiry:
        return _cached_context

    ctx = DeploymentContext()

    # -- Cloud Provider Detection --
    if os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"):
        ctx.cloud_provider = "aws"
        ctx.region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", "unknown")
        ctx.availability_zone = os.environ.get("AWS_AVAILABILITY_ZONE", "unknown")
    elif os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCLOUD_PROJECT"):
        ctx.cloud_provider = "gcp"
        ctx.region = os.environ.get("GOOGLE_CLOUD_REGION", os.environ.get("CLOUD_RUN_REGION", "unknown"))
        ctx.availability_zone = os.environ.get("GOOGLE_CLOUD_ZONE", "unknown")
    elif os.environ.get("AZURE_RESOURCE_GROUP") or os.environ.get("WEBSITE_SITE_NAME"):
        ctx.cloud_provider = "azure"
        ctx.region = os.environ.get("REGION_NAME", os.environ.get("WEBSITE_REGION", "unknown"))
    elif os.environ.get("VULTR_API_KEY") or os.environ.get("VULTR_REGION"):
        ctx.cloud_provider = "vultr"
        ctx.region = os.environ.get("VULTR_REGION", "unknown")

    # -- Runtime Detection --
    if os.environ.get("KUBERNETES_SERVICE_HOST") or os.path.exists("/var/run/secrets/kubernetes.io"):
        ctx.runtime = "kubernetes"
        ctx.container_id = sha256_truncated(os.environ.get("HOSTNAME", "unknown"))
    elif os.environ.get("LAMBDA_TASK_ROOT") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        ctx.runtime = "lambda"
    elif os.environ.get("ECS_CONTAINER_METADATA_URI") or os.environ.get("ECS_CONTAINER_METADATA_URI_V4"):
        ctx.runtime = "ecs"
        ctx.container_id = sha256_truncated(os.environ.get("HOSTNAME", "unknown"))
    elif os.environ.get("CLOUD_RUN_JOB") or os.environ.get("K_SERVICE"):
        ctx.runtime = "cloud-run"
    elif os.environ.get("AZURE_FUNCTIONS_ENVIRONMENT"):
        ctx.runtime = "azure-functions"
    elif os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        ctx.runtime = "container"
        ctx.container_id = sha256_truncated(os.environ.get("HOSTNAME", "unknown"))
    else:
        ctx.runtime = "bare-metal"

    # -- Accelerator Detection (lightweight, no subprocess) --
    if os.environ.get("NVIDIA_VISIBLE_DEVICES") or os.environ.get("CUDA_VISIBLE_DEVICES"):
        devices = os.environ.get("NVIDIA_VISIBLE_DEVICES") or os.environ.get("CUDA_VISIBLE_DEVICES", "")
        if devices and devices != "none":
            ctx.accelerator_type = "nvidia-gpu"
            if devices == "all":
                ctx.accelerator_count = -1  # unknown count, all GPUs
            else:
                ctx.accelerator_count = len(devices.split(","))
    elif os.environ.get("TPU_NAME") or os.environ.get("TPU_WORKER_HOSTNAMES"):
        ctx.accelerator_type = "tpu"
        ctx.accelerator_count = 1
    elif os.environ.get("NEURON_RT_VISIBLE_CORES"):
        ctx.accelerator_type = "aws-neuron"
        cores = os.environ.get("NEURON_RT_VISIBLE_CORES", "")
        ctx.accelerator_count = len(cores.split(",")) if cores else 1

    _cached_context = ctx
    _cache_expiry = now + _CACHE_TTL_SECONDS
    return ctx


def context_to_observations(
    ctx: DeploymentContext,
    clearing_level: int = 1,
) -> Dict[str, Any]:
    """Convert DeploymentContext to observations dict, clearing-level aware.

    CL 0-1: Full context (all fields).
    CL 2: Provider + runtime only (no region/zone/container).
    CL 3: All fields hashed.
    """
    if clearing_level <= 1:
        return ctx.to_dict()
    elif clearing_level == 2:
        return {
            "cloud_provider": ctx.cloud_provider,
            "runtime": ctx.runtime,
            "accelerator_type": ctx.accelerator_type,
            "accelerator_count": ctx.accelerator_count,
        }
    else:
        return {
            "cloud_provider": sha256_truncated(ctx.cloud_provider, 8),
            "runtime": sha256_truncated(ctx.runtime, 8),
            "region": sha256_truncated(ctx.region, 8),
        }


def reset_cache() -> None:
    """Reset the deployment context cache (for testing)."""
    global _cached_context, _cache_expiry
    _cached_context = None
    _cache_expiry = 0.0
