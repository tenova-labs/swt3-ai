"""SWT3 CLI -- Upgrade check.

Checks the current SDK version against PyPI and reports if an update
is available. For Terraform users, shows the new binary checksum.

Usage:
    swt3 upgrade              Check for updates
    swt3 upgrade --json       Machine-readable output

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional
from urllib.request import urlopen
from urllib.error import URLError

VERSION = "8.2.0"
PYPI_URL = "https://pypi.org/pypi/swt3-ai/json"
NPM_URL = "https://registry.npmjs.org/@tenova/swt3-ai"

# ANSI
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_DIM = "\033[90m"
_BOLD = "\033[1m"
_CYAN = "\033[36m"
_RESET = "\033[0m"

if not sys.stdout.isatty():
    _GREEN = _YELLOW = _RED = _DIM = _BOLD = _CYAN = _RESET = ""


def _fetch_json(url: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
    """Fetch JSON from URL with timeout. Returns None on failure."""
    try:
        with urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read())
    except (URLError, OSError, json.JSONDecodeError, ValueError):
        return None


def _parse_version(v: str) -> tuple:
    """Parse semver string to comparable tuple."""
    parts = v.strip().split(".")
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    return tuple(result)


def _check_pypi() -> Dict[str, Any]:
    """Check PyPI for latest swt3-ai version."""
    data = _fetch_json(PYPI_URL)
    if not data:
        return {"registry": "pypi", "error": "Could not reach PyPI"}

    latest = data.get("info", {}).get("version", "")
    releases = sorted(data.get("releases", {}).keys(), key=_parse_version, reverse=True)

    return {
        "registry": "pypi",
        "package": "swt3-ai",
        "current": VERSION,
        "latest": latest,
        "update_available": _parse_version(latest) > _parse_version(VERSION),
        "recent_versions": releases[:5],
    }


def _check_npm() -> Dict[str, Any]:
    """Check npm for latest @tenova/swt3-ai version."""
    data = _fetch_json(NPM_URL)
    if not data:
        return {"registry": "npm", "error": "Could not reach npm"}

    latest = data.get("dist-tags", {}).get("latest", "")
    versions = sorted(data.get("versions", {}).keys(), key=_parse_version, reverse=True)

    return {
        "registry": "npm",
        "package": "@tenova/swt3-ai",
        "current": VERSION,
        "latest": latest,
        "update_available": _parse_version(latest) > _parse_version(VERSION),
        "recent_versions": versions[:5],
    }


def _print_result(checks: List[Dict[str, Any]], use_json: bool = False) -> None:
    if use_json:
        print(json.dumps({"current": VERSION, "checks": checks}, indent=2))
        return

    print(f"\n  {_BOLD}SWT3 Upgrade Check{_RESET}")
    print(f"  Installed: {_CYAN}{VERSION}{_RESET}\n")

    any_update = False
    for c in checks:
        reg = c.get("registry", "?")
        if "error" in c:
            print(f"  {_DIM}[--]  {reg}: {c['error']}{_RESET}")
            continue

        latest = c.get("latest", "?")
        pkg = c.get("package", "?")
        if c.get("update_available"):
            any_update = True
            print(f"  {_YELLOW}[UPDATE]{_RESET}  {reg}: {_BOLD}{latest}{_RESET} available  {_DIM}(current: {VERSION}){_RESET}")
            if reg == "pypi":
                print(f"           {_DIM}pip install --upgrade swt3-ai{_RESET}")
            elif reg == "npm":
                print(f"           {_DIM}npm install @tenova/swt3-ai@latest{_RESET}")
        else:
            print(f"  {_GREEN}[CURRENT]{_RESET} {reg}: {_BOLD}{latest}{_RESET}  {_DIM}(up to date){_RESET}")

    if any_update:
        print(f"\n  {_BOLD}Terraform users:{_RESET}")
        print(f"  {_DIM}After upgrading, update binary_version and binary_sha256 in your .tf files.{_RESET}")
        print(f"  {_DIM}Get checksums from the GitHub release: https://github.com/tenova-labs/swt3-infra-witness/releases{_RESET}")
    else:
        print(f"\n  {_GREEN}All packages are current.{_RESET}")

    print()


def handle_upgrade(args: List[str]) -> None:
    """CLI handler for `swt3 upgrade`."""
    use_json = "--json" in args

    checks = []
    checks.append(_check_pypi())
    checks.append(_check_npm())

    _print_result(checks, use_json=use_json)
