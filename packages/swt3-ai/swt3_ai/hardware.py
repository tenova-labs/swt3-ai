"""SWT3 AI Witness SDK -- Hardware Discovery (AI-HW.1, AI-HW.3).

Out-of-band hardware inventory snapshots. Records what accelerator
hardware and TPM state were present when the service started.
Does NOT sit in the inference path.

Discovery paths (priority order):
  1. NVIDIA GPU -- pynvml (optional) or nvidia-smi subprocess
  2. Google TPU -- TPU_NAME / TPU_WORKER_HOSTNAMES env vars
  3. AMD GPU -- rocm-smi subprocess
  4. AWS Trainium/Inferentia -- neuron-ls subprocess
  5. Intel Gaudi -- hl-smi subprocess
  6. PCI fallback -- /sys/bus/pci/devices sysfs (Linux only)
  7. TPM 2.0 -- tpm2-tools subprocess (AI-HW.3, separate procedure)

Security: All hardware identifiers (GPU UUIDs, bus IDs, hostnames,
PCR digests, endorsement keys, serial numbers) are SHA-256 hashed
at discovery time. Raw values never leave this module.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
from pathlib import Path
from typing import List, Optional, Set, Tuple

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
    "tpu-single": 0,
    "tpu-pod": 2,
    "mi-single": 0,
    "mi-cluster": 1,
    "trn-single": 0,
    "trn-cluster": 1,
    "inf-single": 0,
    "gaudi-single": 0,
    "gaudi-cluster": 1,
    "unknown": 3,
}

# PCI vendor ID to silicon vendor mapping
PCI_VENDOR_MAP = {
    "0x10de": "nvidia",
    "0x1002": "amd",
    "0x8086": "intel-gaudi",
    "0x1d0f": "aws-trainium",  # Annapurna Labs
    "0x1ae0": "google-tpu",
}


def query_hardware() -> HardwareSnapshot:
    """Query all accelerator hardware and return a pre-hashed snapshot.

    Tries all 6 discovery paths. Returns empty snapshot if nothing found.
    Subprocess timeouts are capped at 5 seconds each.
    """
    gpus: List[GpuInfo] = []
    driver_version = ""
    cuda_version = ""

    # 1. NVIDIA (existing path)
    gpus, driver_version, cuda_version = _query_pynvml()
    if not gpus:
        gpus, driver_version = _query_nvidia_smi()

    nvidia_accels = [
        AcceleratorInfo(
            vendor="nvidia", name=g.name, memory_mb=g.memory_mb,
            id_hash=g.uuid_hash, bus_id_hash=g.bus_id_hash,
            discovery_method="nvidia-smi",
        )
        for g in gpus
    ]

    # 2-5. Non-NVIDIA discovery
    tpu_accels = _query_google_tpu()
    amd_accels, _ = _query_amd_rocm()
    neuron_accels = _query_aws_neuron()
    gaudi_accels, _ = _query_intel_gaudi()

    # 6. PCI fallback (skip already-discovered bus IDs)
    seen_bus_ids: Set[str] = set()
    for a in [*nvidia_accels, *tpu_accels, *amd_accels, *neuron_accels, *gaudi_accels]:
        seen_bus_ids.add(a.bus_id_hash)
    pci_accels = _query_pci_fallback(seen_bus_ids)

    # Aggregate
    accelerators = [*nvidia_accels, *tpu_accels, *amd_accels, *neuron_accels, *gaudi_accels, *pci_accels]

    # Determine silicon vendor
    vendors = set(a.vendor for a in accelerators)
    if len(vendors) == 1:
        silicon_vendor = next(iter(vendors))
    elif len(vendors) > 1:
        silicon_vendor = "mixed"
    else:
        silicon_vendor = "none"

    # Build discovery method string
    methods = sorted(set(a.discovery_method for a in accelerators))
    disc_method = ",".join(methods)

    topology = detect_topology(gpus, accelerators)
    interconnect = detect_interconnect() if gpus else "unknown"
    total_memory = sum(a.memory_mb for a in accelerators)
    hostname_hash = sha256_truncated(platform.node())

    return HardwareSnapshot(
        gpus=gpus,
        driver_version=driver_version,
        cuda_version=cuda_version,
        topology=topology,
        interconnect=interconnect,
        total_memory_mb=total_memory,
        hostname_hash=hostname_hash,
        accelerators=accelerators,
        silicon_vendor=silicon_vendor,
        discovery_method=disc_method,
    )


# ── Cross-Silicon Discovery ──────────────────────────────────────────

def _query_google_tpu() -> List[AcceleratorInfo]:
    """Google TPU: reads TPU_NAME and TPU_WORKER_HOSTNAMES env vars."""
    tpu_name = os.environ.get("TPU_NAME")
    if not tpu_name:
        return []

    workers = os.environ.get("TPU_WORKER_HOSTNAMES", "")
    chip_count = len(workers.split(",")) if workers else 1

    upper = tpu_name.upper()
    mem_mb = 0
    if "V6E" in upper or "TRILLIUM" in upper:
        mem_mb = 32_768
    elif "V5P" in upper:
        mem_mb = 95_000
    elif "V5E" in upper or "V5LITEPOD" in upper:
        mem_mb = 16_384
    elif "V4" in upper:
        mem_mb = 32_768

    return [
        AcceleratorInfo(
            vendor="google-tpu", name=tpu_name, memory_mb=mem_mb,
            id_hash=sha256_truncated(f"{tpu_name}-chip-{i}"),
            bus_id_hash=sha256_truncated(f"tpu-{tpu_name}-{i}"),
            discovery_method="tpu-env",
        )
        for i in range(chip_count)
    ]


def _query_amd_rocm() -> Tuple[List[AcceleratorInfo], str]:
    """AMD GPU: queries rocm-smi for MI-series accelerators."""
    try:
        result = subprocess.run(
            ["rocm-smi", "--showproductname", "--showmeminfo", "vram", "--showbus", "--csv"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return [], ""
        accels: List[AcceleratorInfo] = []
        for line in result.stdout.strip().split("\n")[1:]:
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 4:
                continue
            dev_id, name, mem_str, bus_id = parts[0], parts[1], parts[2], parts[3]
            accels.append(AcceleratorInfo(
                vendor="amd", name=name or f"AMD-{dev_id}",
                memory_mb=int(float(mem_str) / 1_048_576) if mem_str else 0,
                id_hash=sha256_truncated(dev_id),
                bus_id_hash=sha256_truncated(bus_id),
                discovery_method="rocm-smi",
            ))
        driver = ""
        try:
            dr = subprocess.run(
                ["rocm-smi", "--showdriverversion", "--csv"],
                capture_output=True, text=True, timeout=5,
            )
            driver = dr.stdout.strip().split("\n")[-1].strip()
        except Exception:
            pass
        return accels, driver
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return [], ""


def _query_aws_neuron() -> List[AcceleratorInfo]:
    """AWS Trainium/Inferentia: queries neuron-ls for Neuron devices."""
    try:
        result = subprocess.run(
            ["neuron-ls", "--json-output"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return []
        devices = json.loads(result.stdout)
        if not isinstance(devices, list):
            return []
        return [
            AcceleratorInfo(
                vendor="aws-trainium",
                name=str(d.get("model_name", d.get("model", f"neuron-{i}"))),
                memory_mb=int(d.get("memory_size", 0)),
                id_hash=sha256_truncated(str(d.get("neuron_device", d.get("device_id", i)))),
                bus_id_hash=sha256_truncated(str(d.get("pci_bdf", d.get("connected_to", f"neuron-bus-{i}")))),
                discovery_method="neuron-ls",
            )
            for i, d in enumerate(devices)
        ]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
        return []


def _query_intel_gaudi() -> Tuple[List[AcceleratorInfo], str]:
    """Intel Gaudi: queries hl-smi for Habana accelerators."""
    try:
        result = subprocess.run(
            ["hl-smi", "-Q", "name,memory.total,bus_id,serial", "-f", "csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return [], ""
        accels: List[AcceleratorInfo] = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 4:
                continue
            name, mem_str, bus_id, serial = parts[0], parts[1], parts[2], parts[3]
            accels.append(AcceleratorInfo(
                vendor="intel-gaudi", name=name,
                memory_mb=int(float(mem_str)) if mem_str else 0,
                id_hash=sha256_truncated(serial),
                bus_id_hash=sha256_truncated(bus_id),
                discovery_method="hl-smi",
            ))
        driver = ""
        try:
            dr = subprocess.run(
                ["hl-smi", "-Q", "driver_version", "-f", "csv,noheader"],
                capture_output=True, text=True, timeout=5,
            )
            driver = dr.stdout.strip()
        except Exception:
            pass
        return accels, driver
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return [], ""


def _query_pci_fallback(seen_bus_ids: Set[str] = frozenset()) -> List[AcceleratorInfo]:
    """PCI fallback: scans /sys/bus/pci/devices for accelerator class codes. Linux only."""
    if not platform.system().startswith("Linux"):
        return []
    accels: List[AcceleratorInfo] = []
    dev_dir = Path("/sys/bus/pci/devices")
    if not dev_dir.exists():
        return []
    try:
        for entry in dev_dir.iterdir():
            try:
                class_code = (entry / "class").read_text().strip()
                # 0x0302xx = 3D controller, 0x1200xx = processing accelerator
                if not (class_code.startswith("0x0302") or class_code.startswith("0x1200")):
                    continue
                bus_hash = sha256_truncated(entry.name)
                if bus_hash in seen_bus_ids:
                    continue
                vendor_id = (entry / "vendor").read_text().strip()
                device_id = (entry / "device").read_text().strip()
                vendor = PCI_VENDOR_MAP.get(vendor_id, "pci-generic")
                accels.append(AcceleratorInfo(
                    vendor=vendor,
                    name=f"PCI-{vendor_id}-{device_id}",
                    memory_mb=0,
                    id_hash=sha256_truncated(f"{vendor_id}:{device_id}:{entry.name}"),
                    bus_id_hash=bus_hash,
                    discovery_method="pci-sysfs",
                ))
            except (OSError, IOError):
                continue
    except (OSError, IOError):
        pass
    return accels


def detect_topology(
    gpus: List[GpuInfo],
    accelerators: Optional[List[AcceleratorInfo]] = None,
) -> str:
    """Infer cluster topology from GPU count, model names, and accelerators."""
    # NVIDIA path (existing logic, unchanged)
    if gpus:
        count = len(gpus)
        if count == 1:
            return "single"
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

    # Non-NVIDIA path
    if not accelerators:
        return "unknown"
    count = len(accelerators)
    vendor = accelerators[0].vendor

    if vendor == "google-tpu":
        return "tpu-pod" if count > 1 else "tpu-single"
    if vendor == "amd":
        return "mi-cluster" if count > 1 else "mi-single"
    if vendor == "aws-trainium":
        name = accelerators[0].name.lower()
        if "inf" in name:
            return "inf-single"
        return "trn-cluster" if count > 1 else "trn-single"
    if vendor == "intel-gaudi":
        return "gaudi-cluster" if count > 1 else "gaudi-single"
    return "multi-gpu" if count > 1 else "single"


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
