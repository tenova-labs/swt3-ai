"""SWT3 AI Witness SDK -- Environmental Telemetry (AI-ENV.1 / AI-ENV.2).

Out-of-band thermal and power snapshot for distributed AI compute nodes.
Reads Linux sysfs sensors automatically. Graceful no-op on non-Linux
or when sensors are unavailable.

Security: hostnames are SHA-256 hashed at discovery time.
No GPS, no PII, no raw identifiers leave this module.

Usage:
    from swt3_ai.environment import query_environment
    snap = query_environment()
    # -> EnvironmentSnapshot(temperature_celsius=42, power_watts=0, ...)

    # Or let the Witness handle it:
    witness.witness_environment()
    witness.witness_energy_draw()
"""

from __future__ import annotations

import logging
import platform
from pathlib import Path
from typing import Optional

from .fingerprint import sha256_truncated
from .types import EnvironmentSnapshot

logger = logging.getLogger("swt3_ai.environment")

NODE_TYPE_CODES = {
    "unknown": 0,
    "datacenter": 1,
    "edge": 2,
    "residential": 3,
    "mobile": 4,
}


def query_environment() -> EnvironmentSnapshot:
    """Query thermal and power sensors.

    Returns a snapshot with best-effort readings.
    If no sensors are available, all values are 0.
    """
    temp_c, thermal_zones = _read_thermal_zones()
    power_domains = _read_power_domains()
    hostname_hash = sha256_truncated(platform.node())

    return EnvironmentSnapshot(
        temperature_celsius=temp_c,
        power_watts=0,
        thermal_zones=thermal_zones,
        power_domains=power_domains,
        hostname_hash=hostname_hash,
        node_type="unknown",
    )


def _read_thermal_zones() -> tuple:
    """Read Linux sysfs thermal zones. Returns (max_celsius, zone_count)."""
    base = Path("/sys/class/thermal")
    try:
        if not base.exists():
            return (0, 0)
        max_temp = 0
        count = 0
        for zone in sorted(base.iterdir()):
            if not zone.name.startswith("thermal_zone"):
                continue
            temp_file = zone / "temp"
            try:
                raw = temp_file.read_text().strip()
                millideg = int(raw)
                celsius = round(millideg / 1000)
                if celsius > max_temp:
                    max_temp = celsius
                count += 1
            except (ValueError, OSError):
                continue
        return (max_temp, count)
    except OSError:
        return (0, 0)


def _read_power_domains() -> int:
    """Count available RAPL power domains."""
    base = Path("/sys/class/powercap")
    try:
        if not base.exists():
            return 0
        count = 0
        for domain in base.iterdir():
            if domain.name.startswith("intel-rapl"):
                energy_file = domain / "energy_uj"
                if energy_file.exists():
                    count += 1
        return count
    except OSError:
        return 0
