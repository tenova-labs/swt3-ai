"""SWT3 AI Witness SDK -- Hardware Discovery (AI-HW.1, AI-HW.3).

Out-of-band hardware inventory snapshots. Records what accelerator
hardware and TPM state were present when the service started.
Does NOT sit in the inference path.

Accelerator data sources (AI-HW.1), tried in order:
  1. pynvml (NVIDIA, structured NVML query, optional dependency)
  2. nvidia-smi subprocess (NVIDIA fallback)
  3. JAX device enumeration (Google TPU, optional dependency)
  4. rocm-smi subprocess (AMD MI series)
  5. neuron-ls subprocess (AWS Trainium/Inferentia)
  6. hl-smi subprocess (Intel Gaudi)
  7. PCI device class fallback (generic, last resort)

TPM data source (AI-HW.3):
  - tpm2-tools subprocess (tpm2_pcrread, tpm2_getcap)

If hardware is unavailable, returns an empty snapshot. No crash, no error.

Security: All hardware identifiers (GPU UUIDs, bus IDs, hostnames,
PCR digests, endorsement keys) are SHA-256 hashed at discovery time.
Raw values never leave this module.
"""

from __future__ import annotations

import json as _json
import logging
import os
import platform
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

import re

from .fingerprint import sha256_truncated
from .types import AcceleratorInfo, GpuInfo, HardwareSnapshot, PcrRegister, TPMSnapshot

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

# PCI vendor IDs for accelerator detection (fallback path)
_PCI_VENDORS = {
    "10de": "nvidia",   # NVIDIA Corporation
    "1002": "amd",      # Advanced Micro Devices
    "8086": "intel",    # Intel Corporation
}


def query_hardware() -> HardwareSnapshot:
    """Query accelerator hardware and return a pre-hashed snapshot.

    Tries all silicon vendors in priority order: NVIDIA (pynvml/nvidia-smi),
    Google TPU (JAX), AMD (rocm-smi), AWS (neuron-ls), Intel (hl-smi),
    PCI fallback. Returns empty snapshot if no accelerators are detectable.

    Subprocess timeouts are capped at 5 seconds each. On systems without
    any accelerator tools, the function returns quickly via graceful fallback.
    """
    return query_accelerators()


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


# ── Vendor Family Parsing ──────────────────────────────────────────

def _parse_nvidia_family(name: str) -> str:
    """Extract GPU family from NVIDIA product name. 'NVIDIA H100 80GB HBM3' -> 'H100'."""
    for token in name.upper().split():
        if token in ("A100", "A800", "H100", "H200", "H800", "B100", "B200",
                      "L4", "L40", "L40S", "A10", "A10G", "A30", "A40",
                      "T4", "V100", "P100", "RTX"):
            return token
    return "GPU"


# ── Google TPU Discovery ───────────────────────────────────────────

def _query_jax_tpu() -> Tuple[List[AcceleratorInfo], str]:
    """Query TPU devices via JAX (optional dependency). Returns (accelerators, method)."""
    try:
        import jax  # type: ignore[import-untyped]
    except ImportError:
        return [], ""

    try:
        devices = jax.devices("tpu")
        if not devices:
            return [], ""

        accels: List[AcceleratorInfo] = []
        for dev in devices:
            kind = getattr(dev, "device_kind", "TPU")
            family = kind.replace(" ", "-") if kind else "TPU"
            dev_id = str(getattr(dev, "id", 0))
            accels.append(AcceleratorInfo(
                name=kind,
                memory_mb=0,  # JAX doesn't expose memory via devices()
                bus_id_hash=sha256_truncated(f"tpu-{dev_id}"),
                uuid_hash=sha256_truncated(f"tpu-{dev_id}-{getattr(dev, 'process_index', 0)}"),
                vendor="google",
                family=family,
                discovery_method="jax",
            ))
        return accels, "jax"
    except Exception as e:
        logger.debug("JAX TPU query failed: %s", e)
        return [], ""


# ── AMD ROCm Discovery ─────────────────────────────────────────────

def _query_rocm_smi() -> Tuple[List[AcceleratorInfo], str]:
    """Query AMD GPUs via rocm-smi subprocess. Returns (accelerators, method)."""
    try:
        result = subprocess.run(
            ["rocm-smi", "--showproductname", "--showmeminfo", "vram",
             "--showbus", "--showuniqueid", "--csv"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return [], ""

        accels: List[AcceleratorInfo] = []
        lines = result.stdout.strip().split("\n")
        if len(lines) < 2:
            return [], ""

        for line in lines[1:]:  # skip header
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 4:
                continue
            name = parts[0] if parts[0] else "AMD GPU"
            try:
                memory_mb = int(float(parts[1])) if parts[1] else 0
            except (ValueError, TypeError):
                memory_mb = 0
            bus_id = parts[2] if len(parts) > 2 else f"amd-{len(accels)}"
            unique_id = parts[3] if len(parts) > 3 else f"amd-uid-{len(accels)}"

            family = "MI300X" if "MI300X" in name.upper() else \
                     "MI325X" if "MI325X" in name.upper() else \
                     "MI300" if "MI300" in name.upper() else \
                     "MI250" if "MI250" in name.upper() else "MI"

            accels.append(AcceleratorInfo(
                name=name,
                memory_mb=memory_mb,
                bus_id_hash=sha256_truncated(bus_id),
                uuid_hash=sha256_truncated(unique_id),
                vendor="amd",
                family=family,
                discovery_method="rocm-smi",
            ))
        return accels, "rocm-smi"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        logger.debug("rocm-smi not available")
        return [], ""


# ── AWS Trainium/Inferentia Discovery ──────────────────────────────

def _query_neuron_ls() -> Tuple[List[AcceleratorInfo], str]:
    """Query AWS Neuron devices via neuron-ls subprocess. Returns (accelerators, method)."""
    try:
        result = subprocess.run(
            ["neuron-ls", "--json-output"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return [], ""

        data = _json.loads(result.stdout)
        devices = data if isinstance(data, list) else data.get("neuron_devices", [])
        if not devices:
            return [], ""

        accels: List[AcceleratorInfo] = []
        for dev in devices:
            dev_id = dev.get("neuron_device", len(accels))
            nc_count = dev.get("nc_count", 1)
            mem = dev.get("memory_size", 0)
            dev_type = str(dev.get("device_type", "")).lower()
            if "trainium2" in dev_type or "trn2" in dev_type:
                family = "Trainium2"
            elif "trainium" in dev_type or "trn1" in dev_type:
                family = "Trainium"
            elif "inferentia" in dev_type or "inf" in dev_type:
                family = "Inferentia"
            else:
                # Fallback: Trainium devices typically have higher nc_count
                family = "Trainium" if nc_count >= 16 else "Neuron"

            accels.append(AcceleratorInfo(
                name=f"AWS {family}",
                memory_mb=mem,
                bus_id_hash=sha256_truncated(f"neuron-{dev_id}"),
                uuid_hash=sha256_truncated(f"neuron-{dev_id}-{nc_count}"),
                vendor="aws",
                family=family,
                discovery_method="neuron-ls",
            ))
        return accels, "neuron-ls"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError, _json.JSONDecodeError):
        logger.debug("neuron-ls not available")
        return [], ""


# ── Intel Gaudi Discovery ──────────────────────────────────────────

def _query_hl_smi() -> Tuple[List[AcceleratorInfo], str]:
    """Query Intel Gaudi devices via hl-smi subprocess. Returns (accelerators, method)."""
    try:
        result = subprocess.run(
            ["hl-smi", "-Q", "name,memory.total,bus_id,serial", "-f", "csv,noheader"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return [], ""

        accels: List[AcceleratorInfo] = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 3:
                continue
            name = parts[0] if parts[0] else "Intel Gaudi"
            try:
                memory_mb = int(float(parts[1])) if parts[1] else 0
            except (ValueError, TypeError):
                memory_mb = 0
            bus_id = parts[2] if len(parts) > 2 else f"gaudi-{len(accels)}"
            serial = parts[3] if len(parts) > 3 else f"gaudi-sn-{len(accels)}"

            family = "Gaudi3" if "GAUDI3" in name.upper() else \
                     "Gaudi2" if "GAUDI2" in name.upper() else "Gaudi"

            accels.append(AcceleratorInfo(
                name=name,
                memory_mb=memory_mb,
                bus_id_hash=sha256_truncated(bus_id),
                uuid_hash=sha256_truncated(serial),
                vendor="intel",
                family=family,
                discovery_method="hl-smi",
            ))
        return accels, "hl-smi"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        logger.debug("hl-smi not available")
        return [], ""


# ── PCI Device Class Fallback ──────────────────────────────────────

def _query_pci_fallback() -> Tuple[List[AcceleratorInfo], str]:
    """Detect accelerators via PCI device class codes (last resort).

    Scans /sys/bus/pci/devices for class 0x0302 (3D controller) or
    0x1200 (processing accelerator) and maps vendor IDs.
    """
    pci_base = Path("/sys/bus/pci/devices")
    if not pci_base.exists():
        return [], ""

    accels: List[AcceleratorInfo] = []
    try:
        for dev_path in sorted(pci_base.iterdir()):
            class_file = dev_path / "class"
            vendor_file = dev_path / "vendor"
            if not class_file.exists() or not vendor_file.exists():
                continue
            try:
                pci_class = class_file.read_text().strip().lower()
                pci_vendor = vendor_file.read_text().strip().lower().replace("0x", "")
            except OSError:
                continue

            # 0x030200 = 3D controller, 0x120000 = processing accelerator
            if not (pci_class.startswith("0x0302") or pci_class.startswith("0x1200")):
                continue

            vendor = _PCI_VENDORS.get(pci_vendor[:4], "unknown")
            bus_id = dev_path.name

            accels.append(AcceleratorInfo(
                name=f"PCI {vendor} accelerator",
                memory_mb=0,
                bus_id_hash=sha256_truncated(bus_id),
                uuid_hash=sha256_truncated(f"pci-{bus_id}"),
                vendor=vendor,
                family="unknown",
                discovery_method="pci",
            ))
    except OSError:
        pass

    return accels, "pci" if accels else ""


# ── Unified Accelerator Discovery ──────────────────────────────────

def query_accelerators() -> HardwareSnapshot:
    """Query all accelerator types across silicon vendors.

    Tries each discovery path in priority order. Returns a unified
    HardwareSnapshot with silicon_vendor populated. Zero dependencies
    required -- each path fails gracefully.
    """
    hostname_hash = sha256_truncated(platform.node())

    # 1. NVIDIA (existing path)
    gpus: List[GpuInfo] = []
    driver_version = ""
    cuda_version = ""
    gpus, driver_version, cuda_version = _query_pynvml()
    if not gpus:
        gpus, driver_version = _query_nvidia_smi()

    if gpus:
        topology = detect_topology(gpus)
        interconnect = detect_interconnect()
        total_memory = sum(g.memory_mb for g in gpus)
        accelerators = [
            AcceleratorInfo(
                name=g.name, memory_mb=g.memory_mb,
                bus_id_hash=g.bus_id_hash, uuid_hash=g.uuid_hash,
                vendor="nvidia", family=_parse_nvidia_family(g.name),
                discovery_method="pynvml" if cuda_version else "nvidia-smi",
            ) for g in gpus
        ]
        return HardwareSnapshot(
            gpus=gpus, driver_version=driver_version, cuda_version=cuda_version,
            topology=topology, interconnect=interconnect,
            total_memory_mb=total_memory, hostname_hash=hostname_hash,
            silicon_vendor="nvidia", accelerators=accelerators,
            discovery_method="pynvml" if cuda_version else "nvidia-smi",
        )

    # 2. Google TPU
    accels, method = _query_jax_tpu()
    if accels:
        count = len(accels)
        total_mem = sum(a.memory_mb for a in accels)
        topo = "single" if count == 1 else "multi-gpu" if count <= 8 else "multi-node"
        return HardwareSnapshot(
            topology=topo, total_memory_mb=total_mem, hostname_hash=hostname_hash,
            silicon_vendor="google", accelerators=accels, discovery_method=method,
        )

    # 3. AMD ROCm
    accels, method = _query_rocm_smi()
    if accels:
        count = len(accels)
        total_mem = sum(a.memory_mb for a in accels)
        topo = "single" if count == 1 else "multi-gpu" if count <= 8 else "multi-node"
        return HardwareSnapshot(
            topology=topo, total_memory_mb=total_mem, hostname_hash=hostname_hash,
            silicon_vendor="amd", accelerators=accels, discovery_method=method,
        )

    # 4. AWS Trainium/Inferentia
    accels, method = _query_neuron_ls()
    if accels:
        count = len(accels)
        total_mem = sum(a.memory_mb for a in accels)
        topo = "single" if count == 1 else "multi-gpu" if count <= 8 else "multi-node"
        return HardwareSnapshot(
            topology=topo, total_memory_mb=total_mem, hostname_hash=hostname_hash,
            silicon_vendor="aws", accelerators=accels, discovery_method=method,
        )

    # 5. Intel Gaudi
    accels, method = _query_hl_smi()
    if accels:
        count = len(accels)
        total_mem = sum(a.memory_mb for a in accels)
        topo = "single" if count == 1 else "multi-gpu" if count <= 8 else "multi-node"
        return HardwareSnapshot(
            topology=topo, total_memory_mb=total_mem, hostname_hash=hostname_hash,
            silicon_vendor="intel", accelerators=accels, discovery_method=method,
        )

    # 6. PCI fallback (last resort)
    accels, method = _query_pci_fallback()
    if accels:
        vendors = {a.vendor for a in accels}
        vendor = vendors.pop() if len(vendors) == 1 else "mixed" if len(vendors) > 1 else "unknown"
        total_mem = sum(a.memory_mb for a in accels)
        return HardwareSnapshot(
            topology="unknown", total_memory_mb=total_mem, hostname_hash=hostname_hash,
            silicon_vendor=vendor, accelerators=accels, discovery_method=method,
        )

    # Nothing found
    return HardwareSnapshot(hostname_hash=hostname_hash)


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
