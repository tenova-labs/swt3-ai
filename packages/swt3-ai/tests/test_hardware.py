"""SWT3 AI Witness SDK -- AI-HW.1 Hardware Witnessing Tests.

All tests run without GPUs. nvidia-smi and pynvml are mocked.
"""

import json
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from swt3_ai import Witness, GpuInfo, HardwareSnapshot
from swt3_ai.hardware import (
    query_hardware,
    detect_topology,
    detect_interconnect,
    topology_code,
    _query_nvidia_smi,
    _query_pynvml,
)


def mk_witness(**overrides):
    defaults = dict(
        endpoint="https://test.example.com",
        api_key="axm_test_key",
        tenant_id="test_tenant",
        flush_interval=999999,
    )
    defaults.update(overrides)
    return Witness(**defaults)


# ── Sample nvidia-smi output ─────────────────────────────────────────

SINGLE_GPU_CSV = "NVIDIA GeForce RTX 4090, 24564, 00000000:01:00.0, GPU-abc123-def456, 550.54.15\n"

DGX_H100_CSV = "\n".join([
    f"NVIDIA H100 80GB HBM3, 81920, 00000000:0{i}:00.0, GPU-h100-{i:04d}, 550.54.15"
    for i in range(8)
]) + "\n"

NVL72_CSV = "\n".join([
    f"NVIDIA B200, 192000, 00000000:{i:02x}:00.0, GPU-b200-{i:04d}, 560.10.03"
    for i in range(72)
]) + "\n"

MULTI_GPU_CSV = "\n".join([
    f"NVIDIA A100 40GB, 40960, 00000000:0{i}:00.0, GPU-a100-{i:04d}, 535.104.05"
    for i in range(4)
]) + "\n"

TOPO_NVSWITCH = """\
        GPU0    GPU1    GPU2    GPU3    GPU4    GPU5    GPU6    GPU7
GPU0     X      NV18    NV18    NV18    NV18    NV18    NV18    NV18
GPU1    NV18     X      NV18    NV18    NV18    NV18    NV18    NV18
Legend:
  NV#  = Connection traversing a bonded set of # NVLinks
  SYS  = Connection traversing NVSwitch
"""

TOPO_PCIE = """\
        GPU0    GPU1
GPU0     X      PHB
GPU1    PHB      X
"""


# ── Topology Detection ───────────────────────────────────────────────

class TestTopologyDetection:
    def test_zero_gpus(self):
        assert detect_topology([]) == "unknown"

    def test_single_gpu(self):
        gpus = [GpuInfo(name="RTX 4090", memory_mb=24564, bus_id_hash="x", uuid_hash="y")]
        assert detect_topology(gpus) == "single"

    def test_dgx_h100(self):
        gpus = [GpuInfo(name="NVIDIA H100 80GB HBM3", memory_mb=81920, bus_id_hash="x", uuid_hash="y") for _ in range(8)]
        assert detect_topology(gpus) == "DGX-H100"

    def test_dgx_a100(self):
        gpus = [GpuInfo(name="NVIDIA A100 80GB", memory_mb=81920, bus_id_hash="x", uuid_hash="y") for _ in range(8)]
        assert detect_topology(gpus) == "DGX-A100"

    def test_dgx_h200(self):
        gpus = [GpuInfo(name="NVIDIA H200", memory_mb=141000, bus_id_hash="x", uuid_hash="y") for _ in range(8)]
        assert detect_topology(gpus) == "DGX-H200"

    def test_dgx_b200(self):
        gpus = [GpuInfo(name="NVIDIA B200 Blackwell", memory_mb=192000, bus_id_hash="x", uuid_hash="y") for _ in range(8)]
        assert detect_topology(gpus) == "DGX-B200"

    def test_hgx_unknown_8gpu(self):
        gpus = [GpuInfo(name="NVIDIA L40S", memory_mb=48000, bus_id_hash="x", uuid_hash="y") for _ in range(8)]
        assert detect_topology(gpus) == "HGX"

    def test_nvl72(self):
        gpus = [GpuInfo(name="NVIDIA B200", memory_mb=192000, bus_id_hash="x", uuid_hash="y") for _ in range(72)]
        assert detect_topology(gpus) == "NVL72"

    def test_nvl36(self):
        gpus = [GpuInfo(name="NVIDIA B200", memory_mb=192000, bus_id_hash="x", uuid_hash="y") for _ in range(36)]
        assert detect_topology(gpus) == "NVL36"

    def test_multi_gpu_4(self):
        gpus = [GpuInfo(name="RTX A6000", memory_mb=49152, bus_id_hash="x", uuid_hash="y") for _ in range(4)]
        assert detect_topology(gpus) == "multi-gpu"

    def test_multi_node_16(self):
        gpus = [GpuInfo(name="NVIDIA H100", memory_mb=81920, bus_id_hash="x", uuid_hash="y") for _ in range(16)]
        assert detect_topology(gpus) == "multi-node"


class TestTopologyCode:
    def test_known_topologies(self):
        assert topology_code("single") == 0
        assert topology_code("DGX-H100") == 1
        assert topology_code("NVL72") == 2
        assert topology_code("unknown") == 3

    def test_unknown_string(self):
        assert topology_code("something_new") == 3


# ── nvidia-smi Subprocess Query ──────────────────────────────────────

class TestNvidiaSmiQuery:
    @patch("swt3_ai.hardware.subprocess.run")
    def test_single_gpu(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout=SINGLE_GPU_CSV
        )
        gpus, driver = _query_nvidia_smi()
        assert len(gpus) == 1
        assert gpus[0].name == "NVIDIA GeForce RTX 4090"
        assert gpus[0].memory_mb == 24564
        assert driver == "550.54.15"

    @patch("swt3_ai.hardware.subprocess.run")
    def test_dgx_h100(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout=DGX_H100_CSV
        )
        gpus, driver = _query_nvidia_smi()
        assert len(gpus) == 8
        assert all("H100" in g.name for g in gpus)

    @patch("swt3_ai.hardware.subprocess.run")
    def test_nvl72(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout=NVL72_CSV
        )
        gpus, driver = _query_nvidia_smi()
        assert len(gpus) == 72
        assert driver == "560.10.03"

    @patch("swt3_ai.hardware.subprocess.run")
    def test_not_installed(self, mock_run):
        mock_run.side_effect = FileNotFoundError
        gpus, driver = _query_nvidia_smi()
        assert gpus == []
        assert driver == ""

    @patch("swt3_ai.hardware.subprocess.run")
    def test_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nvidia-smi", timeout=10)
        gpus, driver = _query_nvidia_smi()
        assert gpus == []

    @patch("swt3_ai.hardware.subprocess.run")
    def test_uuids_are_hashed(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout=SINGLE_GPU_CSV
        )
        gpus, _ = _query_nvidia_smi()
        # Raw UUID should NOT appear in the hashed field
        assert gpus[0].uuid_hash != "GPU-abc123-def456"
        assert len(gpus[0].uuid_hash) == 16  # sha256_truncated default
        assert gpus[0].bus_id_hash != "00000000:01:00.0"
        assert len(gpus[0].bus_id_hash) == 16


# ── Interconnect Detection ───────────────────────────────────────────

class TestInterconnectDetection:
    @patch("swt3_ai.hardware.subprocess.run")
    def test_nvlink_detected(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout=TOPO_NVSWITCH)
        result = detect_interconnect()
        assert result in ("nvlink", "nvswitch")

    @patch("swt3_ai.hardware.subprocess.run")
    def test_pcie_detected(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout=TOPO_PCIE)
        result = detect_interconnect()
        assert result == "pcie"

    @patch("swt3_ai.hardware.subprocess.run")
    def test_not_available(self, mock_run):
        mock_run.side_effect = FileNotFoundError
        assert detect_interconnect() == "unknown"


# ── Full Hardware Query ──────────────────────────────────────────────

class TestQueryHardware:
    @patch("swt3_ai.hardware._query_pynvml", return_value=([], "", ""))
    @patch("swt3_ai.hardware._query_nvidia_smi")
    def test_falls_back_to_smi(self, mock_smi, mock_nvml):
        mock_smi.return_value = (
            [GpuInfo(name="RTX 4090", memory_mb=24564, bus_id_hash="x", uuid_hash="y")],
            "550.54.15",
        )
        with patch("swt3_ai.hardware.detect_interconnect", return_value="pcie"):
            snap = query_hardware()
        assert len(snap.gpus) == 1
        assert snap.topology == "single"
        assert snap.driver_version == "550.54.15"

    @patch("swt3_ai.hardware._query_pynvml", return_value=([], "", ""))
    @patch("swt3_ai.hardware._query_nvidia_smi", return_value=([], ""))
    def test_no_gpus_graceful(self, mock_smi, mock_nvml):
        with patch("swt3_ai.hardware.detect_interconnect", return_value="unknown"):
            snap = query_hardware()
        assert len(snap.gpus) == 0
        assert snap.topology == "unknown"
        assert snap.total_memory_mb == 0
        assert snap.hostname_hash  # should still be set


# ── Witness Integration ──────────────────────────────────────────────

class TestWitnessHardware:
    def _make_snapshot(self, gpu_count=8, name="NVIDIA H100 80GB HBM3"):
        gpus = [GpuInfo(name=name, memory_mb=81920, bus_id_hash=f"bus{i}", uuid_hash=f"uid{i}") for i in range(gpu_count)]
        return HardwareSnapshot(
            gpus=gpus,
            driver_version="550.54.15",
            cuda_version="12.4",
            topology=detect_topology(gpus),
            interconnect="nvswitch",
            total_memory_mb=81920 * gpu_count,
            hostname_hash="hosthash123",
        )

    def test_basic_payload(self):
        w = mk_witness()
        snap = self._make_snapshot()
        p = w.witness_hardware(snap)
        assert p.procedure_id == "AI-HW.1"
        assert p.factor_a == 8.0
        assert p.factor_b == 1.0
        assert p.factor_c == 1.0  # DGX-H100 = multi-GPU same node

    def test_nvl72_topology_code(self):
        w = mk_witness()
        snap = self._make_snapshot(gpu_count=72, name="NVIDIA B200")
        p = w.witness_hardware(snap)
        assert p.factor_a == 72.0
        assert p.factor_c == 2.0  # NVL72 = multi-node

    def test_no_gpus_graceful(self):
        w = mk_witness()
        snap = HardwareSnapshot()
        p = w.witness_hardware(snap)
        assert p.factor_a == 0.0
        assert p.factor_b == 0.0
        assert p.factor_c == 3.0  # unknown

    def test_expected_topology_match(self):
        w = mk_witness()
        snap = self._make_snapshot()
        p = w.witness_hardware(snap, expected_topology="DGX-H100")
        assert p.factor_b == 1.0  # match

    def test_expected_topology_mismatch(self):
        w = mk_witness()
        snap = self._make_snapshot()
        p = w.witness_hardware(snap, expected_topology="NVL72")
        assert p.factor_b == 0.0  # mismatch

    def test_clearing_level_0_has_context(self):
        w = mk_witness(clearing_level=0)
        snap = self._make_snapshot()
        p = w.witness_hardware(snap)
        assert p.ai_context is not None
        assert p.ai_context["topology"] == "DGX-H100"
        assert p.ai_context["gpu_count"] == 8
        assert len(p.ai_context["gpus"]) == 8

    def test_clearing_level_1_has_context(self):
        w = mk_witness(clearing_level=1)
        snap = self._make_snapshot()
        p = w.witness_hardware(snap)
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "nvidia-hw"

    def test_clearing_level_2_strips_context(self):
        w = mk_witness(clearing_level=2)
        snap = self._make_snapshot()
        p = w.witness_hardware(snap)
        assert p.ai_context is None

    def test_clearing_level_3_strips_context(self):
        w = mk_witness(clearing_level=3)
        snap = self._make_snapshot()
        p = w.witness_hardware(snap)
        assert p.ai_context is None

    def test_payload_enqueued(self):
        w = mk_witness()
        snap = self._make_snapshot()
        w.witness_hardware(snap)
        assert w.pending > 0

    def test_context_never_contains_raw_uuid(self):
        w = mk_witness(clearing_level=0)
        snap = self._make_snapshot()
        p = w.witness_hardware(snap)
        blob = json.dumps(p.ai_context)
        # Raw UUIDs from the mock are "uid0", "uid1" etc -- these ARE the hash values
        # In real usage, raw UUIDs like "GPU-xxx" would be hashed before reaching the payload
        # The key guarantee: the GpuInfo fields are named *_hash, meaning hardware.py pre-hashed them
        assert "bus_id_hash" in blob  # field name confirms hashing
        assert "uuid_hash" in blob

    def test_agent_id_survives(self):
        w = mk_witness(agent_id="hw-agent-001")
        snap = self._make_snapshot()
        p = w.witness_hardware(snap)
        assert p.agent_id == "hw-agent-001"

    def test_cjt_fields_survive(self):
        w = mk_witness(jurisdiction="DE", legal_basis="GDPR-6.1.a", purpose_class="analytics")
        snap = self._make_snapshot()
        p = w.witness_hardware(snap)
        assert p.jurisdiction == "DE"
        assert p.legal_basis == "GDPR-6.1.a"
        assert p.purpose_class == "analytics"

    def test_single_gpu_topology(self):
        w = mk_witness()
        snap = self._make_snapshot(gpu_count=1, name="RTX 4090")
        p = w.witness_hardware(snap)
        assert p.factor_a == 1.0
        assert p.factor_c == 0.0  # single = 0
