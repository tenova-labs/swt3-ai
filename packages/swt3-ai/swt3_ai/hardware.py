"""SWT3 AI Witness SDK -- Hardware Discovery (AI-HW.1, AI-HW.3).

Out-of-band hardware inventory snapshots. Records what GPU hardware
and TPM state were present when the service started.
Does NOT sit in the inference path.

GPU data sources (AI-HW.1), tried in order:
  1. pynvml (structured NVML query, optional dependency)
  2. nvidia-smi subprocess fallback (works anywhere nvidia-smi is installed)

TPM data source (AI-HW.3):
  - tpm2-tools subprocess (tpm2_pcrread, tpm2_getcap)

If hardware is unavailable, returns an empty snapshot. No crash, no error.

Security: All hardware identifiers (GPU UUIDs, bus IDs, hostnames,
PCR digests, endorsement keys) are SHA-256 hashed at discovery time.
Raw values never leave this module.
"""

from __future__ import annotations

import logging
import platform
import subprocess
from typing import List, Optional

import re

from .fingerprint import sha256_truncated
from .types import GpuInfo, HardwareSnapshot, PcrRegister, TPMSnapshot

logger = logging.getLogger("swt3_ai.hardware")

# Topology codes for factor_c
TOPOLOGY_CODES = {
    "single": 0,
    "multi-gpu": 1,
    "HGX": 1,
    "DGX-A100": 1,
    "DGX-H100": 1,
    "DGX-H200": 1,
    "DGX-B200": 1,
    "NVL36": 2,
    "NVL72": 2,
    "multi-node": 2,
    "unknown": 3,
}


def query_hardware() -> HardwareSnapshot:
    """Query GPU hardware and return a pre-hashed snapshot.

    Tries pynvml first (structured), falls back to nvidia-smi subprocess.
    Returns empty snapshot if no GPUs are detectable.

    Subprocess timeouts are capped at 5 seconds each. On systems without
    nvidia-smi, the function returns in <10ms (two fast FileNotFoundError).
    """
    gpus: List[GpuInfo] = []
    driver_version = ""
    cuda_version = ""

    # Try pynvml first
    gpus, driver_version, cuda_version = _query_pynvml()

    # Fallback to nvidia-smi
    if not gpus:
        gpus, driver_version = _query_nvidia_smi()

    topology = detect_topology(gpus)
    # Only query interconnect if GPUs were found (avoids unnecessary subprocess)
    interconnect = detect_interconnect() if gpus else "unknown"
    total_memory = sum(g.memory_mb for g in gpus)
    hostname_hash = sha256_truncated(platform.node())

    return HardwareSnapshot(
        gpus=gpus,
        driver_version=driver_version,
        cuda_version=cuda_version,
        topology=topology,
        interconnect=interconnect,
        total_memory_mb=total_memory,
        hostname_hash=hostname_hash,
    )


def detect_topology(gpus: List[GpuInfo]) -> str:
    """Infer cluster topology from GPU count and model names."""
    count = len(gpus)
    if count == 0:
        return "unknown"
    if count == 1:
        return "single"

    # Check GPU names for known platforms
    names = {g.name.upper() for g in gpus}
    name_str = " ".join(names)

    if count == 72:
        return "NVL72"
    if count == 36:
        return "NVL36"
    if count == 8:
        if "B200" in name_str or "BLACKWELL" in name_str:
            return "DGX-B200"
        if "H200" in name_str:
            return "DGX-H200"
        if "H100" in name_str:
            return "DGX-H100"
        if "A100" in name_str:
            return "DGX-A100"
        return "HGX"
    if count in (2, 3, 4, 6):
        return "multi-gpu"
    return "multi-node"


def detect_interconnect() -> str:
    """Detect GPU interconnect type from nvidia-smi topology matrix.

    Parses the GPU-to-GPU connection matrix, not the header row.
    NVSwitch connections show as SYS, NVLink as NVxx, PCIe as PIX/PHB/PXB.
    """
    try:
        result = subprocess.run(
            ["nvidia-smi", "topo", "-m"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return "unknown"

        # Parse only data rows (skip header, legend, blanks)
        # Data rows start with "GPU" followed by digits
        connections = []
        for line in result.stdout.split("\n"):
            stripped = line.strip()
            if stripped.startswith("GPU") and any(c.isdigit() for c in stripped[:5]):
                # Extract connection types from this row (skip the GPU label column)
                parts = stripped.split()
                connections.extend(p.upper() for p in parts[1:] if p != "X")

        if not connections:
            return "unknown"

        conn_str = " ".join(connections)
        if "SYS" in conn_str:
            return "nvswitch"
        # NVxx pattern (NV12, NV18, etc.) indicates NVLink
        if any(c.startswith("NV") and len(c) >= 3 for c in connections):
            return "nvlink"
        if "PIX" in conn_str or "PHB" in conn_str or "PXB" in conn_str:
            return "pcie"
        return "unknown"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return "unknown"


def topology_code(topology: str) -> int:
    """Convert topology string to factor_c integer code."""
    return TOPOLOGY_CODES.get(topology, 3)


# ── Data Source: pynvml ──────────────────────────────────────────────

def _query_pynvml() -> tuple:
    """Query GPUs via pynvml (optional dependency). Returns (gpus, driver, cuda)."""
    try:
        import pynvml  # type: ignore[import-untyped]
    except ImportError:
        return [], "", ""

    initialized = False
    try:
        pynvml.nvmlInit()
        initialized = True
        driver = pynvml.nvmlSystemGetDriverVersion()
        if isinstance(driver, bytes):
            driver = driver.decode("utf-8")

        cuda = ""
        try:
            cuda = pynvml.nvmlSystemGetCudaDriverVersion_v2()
            major = cuda // 1000
            minor = (cuda % 1000) // 10
            cuda = f"{major}.{minor}"
        except Exception:
            pass

        count = pynvml.nvmlDeviceGetCount()
        gpus: List[GpuInfo] = []
        for i in range(count):
            handle = pynvml.nvmlDeviceGetHandleByIndex(i)
            name = pynvml.nvmlDeviceGetName(handle)
            if isinstance(name, bytes):
                name = name.decode("utf-8")
            mem_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
            uuid = pynvml.nvmlDeviceGetUUID(handle)
            if isinstance(uuid, bytes):
                uuid = uuid.decode("utf-8")

            try:
                pci = pynvml.nvmlDeviceGetPciInfo(handle)
                bus_id = pci.busId
                if isinstance(bus_id, bytes):
                    bus_id = bus_id.decode("utf-8")
            except Exception:
                bus_id = f"gpu-{i}"

            gpus.append(GpuInfo(
                name=name,
                memory_mb=mem_info.total // (1024 * 1024),
                bus_id_hash=sha256_truncated(bus_id),
                uuid_hash=sha256_truncated(uuid),
            ))

        pynvml.nvmlShutdown()
        initialized = False
        return gpus, driver, cuda
    except Exception as e:
        logger.debug("pynvml query failed: %s", e)
        if initialized:
            try:
                pynvml.nvmlShutdown()
            except Exception:
                pass
        return [], "", ""


# ── Data Source: nvidia-smi subprocess ───────────────────────────────

def _query_nvidia_smi() -> tuple:
    """Query GPUs via nvidia-smi subprocess. Returns (gpus, driver)."""
    try:
        result = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=name,memory.total,pci.bus_id,uuid,driver_version",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return [], ""

        gpus: List[GpuInfo] = []
        driver = ""

        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 5:
                continue

            name, memory_str, bus_id, uuid, drv = parts[0], parts[1], parts[2], parts[3], parts[4]
            if not driver:
                driver = drv

            try:
                memory_mb = int(float(memory_str))
            except (ValueError, TypeError):
                memory_mb = 0

            gpus.append(GpuInfo(
                name=name,
                memory_mb=memory_mb,
                bus_id_hash=sha256_truncated(bus_id),
                uuid_hash=sha256_truncated(uuid),
            ))

        return gpus, driver
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        logger.debug("nvidia-smi not available")
        return [], ""


# ── TPM 2.0 Attestation (AI-HW.3) ──────────────────────────────────

# SHA-256 hash of the all-zeros PCR value (uninitialized register)
ZERO_PCR_HASH = sha256_truncated("0" * 64)


def query_tpm() -> TPMSnapshot:
    """Query TPM 2.0 PCR registers and return a pre-hashed snapshot.

    Returns empty snapshot if no TPM device or tpm2-tools not installed.
    """
    pcrs = _query_tpm_pcrs()
    hostname_hash = sha256_truncated(platform.node())

    if not pcrs:
        return TPMSnapshot(available=False, hostname_hash=hostname_hash)

    props = _query_tpm_properties()

    return TPMSnapshot(
        available=True,
        manufacturer=props["manufacturer"],
        firmware_version=props["firmware_version"],
        pcrs=pcrs,
        endorsement_key_hash=props["endorsement_key_hash"],
        hostname_hash=hostname_hash,
    )


def parse_tpm_pcr_output(output: str) -> List[PcrRegister]:
    """Parse tpm2_pcrread output into pre-hashed PcrRegister list.

    Expected format::

        sha256:
          0 : 0x3d458cfe55cc03ea...
          7 : 0xb5bb9d8014a0f9b1...
    """
    pcrs: List[PcrRegister] = []
    current_bank = ""

    for line in output.split("\n"):
        trimmed = line.strip()
        # Bank header: "sha256:" or "sha1:"
        bank_match = re.match(r"^(\w+):$", trimmed)
        if bank_match:
            current_bank = bank_match.group(1)
            continue
        # PCR line: "0 : 0x3d458c..."
        pcr_match = re.match(r"^(\d+)\s*:\s*0x([0-9a-fA-F]+)$", trimmed)
        if pcr_match and current_bank:
            pcrs.append(PcrRegister(
                index=int(pcr_match.group(1)),
                bank=current_bank,
                digest_hash=sha256_truncated(pcr_match.group(2)),
            ))

    return pcrs


def _query_tpm_pcrs() -> List[PcrRegister]:
    """Read TPM PCR registers via tpm2_pcrread. Returns hashed digests."""
    try:
        result = subprocess.run(
            ["tpm2_pcrread", "sha256:0,1,2,3,4,5,6,7"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return []
        return parse_tpm_pcr_output(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []


def _query_tpm_properties() -> dict:
    """Query TPM manufacturer and firmware via tpm2_getcap.

    Returns hashed values. Falls back to empty strings on failure.
    """
    props = {"manufacturer": "", "firmware_version": "", "endorsement_key_hash": ""}

    try:
        result = subprocess.run(
            ["tpm2_getcap", "properties-fixed"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                kv = line.strip()
                if kv.startswith("TPM2_PT_MANUFACTURER:"):
                    props["manufacturer"] = sha256_truncated(
                        kv.split(":", 1)[1].strip()
                    )
                elif kv.startswith("TPM2_PT_FIRMWARE_VERSION_1:"):
                    props["firmware_version"] = sha256_truncated(
                        kv.split(":", 1)[1].strip()
                    )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # Endorsement key
    try:
        result = subprocess.run(
            ["tpm2_readpublic", "-c", "0x81010001"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            props["endorsement_key_hash"] = sha256_truncated(result.stdout.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return props
