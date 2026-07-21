"""Tests for deployment context detection."""

import os
from unittest.mock import patch
from swt3_ai.deployment import (
    DeploymentContext,
    detect_deployment_context,
    context_to_observations,
    reset_cache,
)
from swt3_ai.fingerprint import sha256_truncated


class TestDeploymentContextDetection:
    def setup_method(self):
        reset_cache()

    def test_default_unknown(self):
        with patch.dict(os.environ, {}, clear=True):
            ctx = detect_deployment_context(force=True)
        assert ctx.cloud_provider == "unknown"
        assert ctx.runtime == "bare-metal"
        assert ctx.accelerator_type == "none"
        assert ctx.accelerator_count == 0

    def test_aws_detection(self):
        env = {"AWS_REGION": "us-east-1", "AWS_AVAILABILITY_ZONE": "us-east-1a"}
        with patch.dict(os.environ, env, clear=True):
            ctx = detect_deployment_context(force=True)
        assert ctx.cloud_provider == "aws"
        assert ctx.region == "us-east-1"
        assert ctx.availability_zone == "us-east-1a"

    def test_gcp_detection(self):
        env = {"GOOGLE_CLOUD_PROJECT": "my-project", "GOOGLE_CLOUD_REGION": "us-central1"}
        with patch.dict(os.environ, env, clear=True):
            ctx = detect_deployment_context(force=True)
        assert ctx.cloud_provider == "gcp"
        assert ctx.region == "us-central1"

    def test_azure_detection(self):
        env = {"AZURE_RESOURCE_GROUP": "my-rg", "REGION_NAME": "eastus"}
        with patch.dict(os.environ, env, clear=True):
            ctx = detect_deployment_context(force=True)
        assert ctx.cloud_provider == "azure"
        assert ctx.region == "eastus"

    def test_kubernetes_runtime(self):
        env = {"KUBERNETES_SERVICE_HOST": "10.0.0.1", "HOSTNAME": "pod-abc123"}
        with patch.dict(os.environ, env, clear=True):
            ctx = detect_deployment_context(force=True)
        assert ctx.runtime == "kubernetes"
        assert ctx.container_id == sha256_truncated("pod-abc123")

    def test_lambda_runtime(self):
        env = {"LAMBDA_TASK_ROOT": "/var/task", "AWS_REGION": "us-west-2"}
        with patch.dict(os.environ, env, clear=True):
            ctx = detect_deployment_context(force=True)
        assert ctx.runtime == "lambda"
        assert ctx.cloud_provider == "aws"

    def test_nvidia_gpu_detection(self):
        env = {"NVIDIA_VISIBLE_DEVICES": "0,1,2"}
        with patch.dict(os.environ, env, clear=True):
            ctx = detect_deployment_context(force=True)
        assert ctx.accelerator_type == "nvidia-gpu"
        assert ctx.accelerator_count == 3

    def test_nvidia_all_gpus(self):
        env = {"NVIDIA_VISIBLE_DEVICES": "all"}
        with patch.dict(os.environ, env, clear=True):
            ctx = detect_deployment_context(force=True)
        assert ctx.accelerator_type == "nvidia-gpu"
        assert ctx.accelerator_count == -1

    def test_tpu_detection(self):
        env = {"TPU_NAME": "tpu-v4"}
        with patch.dict(os.environ, env, clear=True):
            ctx = detect_deployment_context(force=True)
        assert ctx.accelerator_type == "tpu"

    def test_cache_works(self):
        env = {"AWS_REGION": "us-east-1"}
        with patch.dict(os.environ, env, clear=True):
            ctx1 = detect_deployment_context(force=True)
        # Second call should return cached even if env changes
        with patch.dict(os.environ, {"AWS_REGION": "eu-west-1"}, clear=True):
            ctx2 = detect_deployment_context()
        assert ctx1 is ctx2
        assert ctx2.region == "us-east-1"

    def test_to_dict(self):
        ctx = DeploymentContext(cloud_provider="aws", region="us-east-1")
        d = ctx.to_dict()
        assert d["cloud_provider"] == "aws"
        assert d["region"] == "us-east-1"


class TestContextToObservations:
    def test_cl1_full_context(self):
        ctx = DeploymentContext(
            cloud_provider="aws", region="us-east-1",
            runtime="kubernetes", accelerator_type="nvidia-gpu",
        )
        obs = context_to_observations(ctx, clearing_level=1)
        assert obs["cloud_provider"] == "aws"
        assert obs["region"] == "us-east-1"
        assert obs["runtime"] == "kubernetes"

    def test_cl2_redacted(self):
        ctx = DeploymentContext(
            cloud_provider="gcp", region="us-central1",
            runtime="cloud-run", accelerator_type="tpu",
        )
        obs = context_to_observations(ctx, clearing_level=2)
        assert obs["cloud_provider"] == "gcp"
        assert obs["runtime"] == "cloud-run"
        assert "region" not in obs

    def test_cl3_hashed(self):
        ctx = DeploymentContext(
            cloud_provider="azure", region="eastus",
            runtime="azure-functions",
        )
        obs = context_to_observations(ctx, clearing_level=3)
        assert obs["cloud_provider"] == sha256_truncated("azure", 8)
        assert obs["runtime"] == sha256_truncated("azure-functions", 8)
        assert obs["region"] == sha256_truncated("eastus", 8)
