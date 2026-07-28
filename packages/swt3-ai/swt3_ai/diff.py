"""SWT3 Diff -- compliance posture delta over time.

Run with:
    swt3 diff --since 7d
    swt3 diff --since 30d --json
    swt3 diff --since 2026-07-17 --compact
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

# ── Colors ──

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
AMBER = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[37m"

if not sys.stdout.isatty():
    RESET = BOLD = DIM = RED = GREEN = AMBER = CYAN = WHITE = ""


# ── Data Types ──

@dataclass
class WalAnchor:
    procedure_id: str
    timestamp_ms: int = 0
    verdict: str = ""
    fingerprint: str = ""
    model_id: str = ""
    agent_id: str = ""
    namespace: str = ""


@dataclass
class DiffResult:
    tenant_id: str = ""
    since_label: str = ""
    since_ms: int = 0
    now_ms: int = 0
    # Before period
    before_procedures: Set[str] = field(default_factory=set)
    before_models: Set[str] = field(default_factory=set)
    before_agents: Set[str] = field(default_factory=set)
    before_anchors: int = 0
    before_namespaces: Set[str] = field(default_factory=set)
    # After period (since cutoff)
    after_procedures: Set[str] = field(default_factory=set)
    after_models: Set[str] = field(default_factory=set)
    after_agents: Set[str] = field(default_factory=set)
    after_anchors: int = 0
    after_namespaces: Set[str] = field(default_factory=set)
    # Computed deltas
    new_procedures: Set[str] = field(default_factory=set)
    dropped_procedures: Set[str] = field(default_factory=set)
    new_models: Set[str] = field(default_factory=set)
    dropped_models: Set[str] = field(default_factory=set)
    new_agents: Set[str] = field(default_factory=set)
    new_namespaces: Set[str] = field(default_factory=set)
    # Coverage
    total_procedures_now: int = 0
    total_procedures_before: int = 0
    anchor_delta: int = 0
    # Drift/violations in period
    drift_count: int = 0
    violation_count: int = 0
    revocation_count: int = 0


# ── Period Parser ──

def _parse_since(since: str) -> int:
    """Parse --since value into a timestamp in milliseconds."""
    now_ms = int(time.time() * 1000)

    # Duration format: 1d, 7d, 14d, 30d, 90d
    if since.endswith("d"):
        try:
            days = int(since[:-1])
            return now_ms - (days * 86400 * 1000)
        except ValueError:
            pass

    # Duration format: 1w, 2w, 4w
    if since.endswith("w"):
        try:
            weeks = int(since[:-1])
            return now_ms - (weeks * 7 * 86400 * 1000)
        except ValueError:
            pass

    # ISO date: 2026-07-17
    try:
        from datetime import datetime, timezone
        dt = datetime.strptime(since, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        pass

    return 0


def _since_label(since: str, since_ms: int) -> str:
    """Generate human-readable label for the period."""
    from datetime import datetime, timezone
    dt = datetime.fromtimestamp(since_ms / 1000, tz=timezone.utc)
    now = datetime.now(tz=timezone.utc)
    return f"{dt.strftime('%b %d')} to {now.strftime('%b %d')}"


# ── WAL Scanner (time-aware) ──

def scan_wal_anchors(tenant_id: str, wal_dir: Optional[str] = None) -> List[WalAnchor]:
    """Scan local WAL and return all anchors as structured entries."""
    if not wal_dir:
        wal_dir = os.path.join(tempfile.gettempdir(), "swt3-wal")

    safe_tenant = "".join(c if c.isalnum() or c in "-_" else "_" for c in tenant_id)
    wal_path = Path(wal_dir) / f"{safe_tenant}.wal"

    anchors: List[WalAnchor] = []

    if not wal_path.is_file():
        return anchors

    try:
        with open(wal_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    payload = row.get("payload", {})
                    proc_id = payload.get("procedure_id", "")
                    if not proc_id:
                        continue

                    ns = proc_id.split("-")[1].split(".")[0] if "-" in proc_id else ""

                    anchors.append(WalAnchor(
                        procedure_id=proc_id,
                        timestamp_ms=payload.get("timestamp_ms", 0),
                        verdict=payload.get("verdict", ""),
                        fingerprint=row.get("fingerprint", ""),
                        model_id=payload.get("ai_model_id", ""),
                        agent_id=payload.get("agent_id", ""),
                        namespace=ns,
                    ))
                except (json.JSONDecodeError, KeyError):
                    continue
    except OSError:
        pass

    return anchors


# ── Diff Computation ──

def compute_diff(
    tenant_id: str,
    since: str,
    wal_dir: Optional[str] = None,
) -> DiffResult:
    """Compute compliance posture delta since a given time."""
    since_ms = _parse_since(since)
    now_ms = int(time.time() * 1000)

    if not since_ms:
        return DiffResult(tenant_id=tenant_id)

    result = DiffResult(
        tenant_id=tenant_id,
        since_label=_since_label(since, since_ms),
        since_ms=since_ms,
        now_ms=now_ms,
    )

    anchors = scan_wal_anchors(tenant_id, wal_dir)

    if not anchors:
        return result

    for a in anchors:
        if a.timestamp_ms < since_ms:
            # Before the period
            result.before_procedures.add(a.procedure_id)
            result.before_anchors += 1
            if a.model_id:
                result.before_models.add(a.model_id)
            if a.agent_id:
                result.before_agents.add(a.agent_id)
            if a.namespace:
                result.before_namespaces.add(a.namespace)
        else:
            # During the period
            result.after_procedures.add(a.procedure_id)
            result.after_anchors += 1
            if a.model_id:
                result.after_models.add(a.model_id)
            if a.agent_id:
                result.after_agents.add(a.agent_id)
            if a.namespace:
                result.after_namespaces.add(a.namespace)

            # Track drift/violations/revocations
            if a.procedure_id == "AI-DRIFT.1" or a.procedure_id == "AI-DRIFT.2":
                result.drift_count += 1
            elif a.procedure_id == "AI-VIO.1":
                result.violation_count += 1
            elif a.procedure_id == "AI-REV.1":
                result.revocation_count += 1

    # Compute deltas
    all_procs_before = result.before_procedures
    all_procs_now = result.before_procedures | result.after_procedures

    result.new_procedures = result.after_procedures - result.before_procedures
    result.dropped_procedures = result.before_procedures - (result.before_procedures | result.after_procedures)
    result.new_models = result.after_models - result.before_models
    result.dropped_models = result.before_models - (result.before_models | result.after_models)
    result.new_agents = result.after_agents - result.before_agents
    result.new_namespaces = result.after_namespaces - result.before_namespaces
    result.total_procedures_now = len(all_procs_now)
    result.total_procedures_before = len(all_procs_before)
    result.anchor_delta = result.after_anchors

    return result


# ── Renderers ──

def render_diff(result: DiffResult) -> str:
    """Render human-readable diff output."""
    lines: List[str] = []

    lines.append("")
    lines.append(f"  {BOLD}SWT3 Diff{RESET}  {DIM}{result.since_label}{RESET}")
    lines.append(f"  {'─' * 50}")

    if not result.after_anchors and not result.before_anchors:
        lines.append(f"  {DIM}No anchors found in WAL.{RESET}")
        lines.append("")
        return "\n".join(lines)

    if not result.after_anchors:
        lines.append(f"  {DIM}No new anchors in this period.{RESET}")
        lines.append("")
        return "\n".join(lines)

    lines.append("")

    # New models
    if result.new_models:
        for m in sorted(result.new_models):
            lines.append(f"  {GREEN}+{RESET} New model witnessed: {WHITE}{m}{RESET}")

    # Dropped models
    if result.dropped_models:
        for m in sorted(result.dropped_models):
            lines.append(f"  {RED}-{RESET} Model no longer witnessed: {DIM}{m}{RESET}")

    # New procedures
    if result.new_procedures:
        lines.append(f"  {GREEN}+{RESET} {len(result.new_procedures)} new procedure{'s' if len(result.new_procedures) != 1 else ''}: {WHITE}{', '.join(sorted(result.new_procedures))}{RESET}")

    # New agents
    if result.new_agents:
        lines.append(f"  {GREEN}+{RESET} {len(result.new_agents)} new agent{'s' if len(result.new_agents) != 1 else ''}: {WHITE}{', '.join(sorted(result.new_agents))}{RESET}")

    # New namespaces
    if result.new_namespaces:
        lines.append(f"  {GREEN}+{RESET} {len(result.new_namespaces)} new namespace{'s' if len(result.new_namespaces) != 1 else ''}: {WHITE}{', '.join(sorted(result.new_namespaces))}{RESET}")

    # Drift alerts
    if result.drift_count:
        lines.append(f"  {AMBER}~{RESET} {result.drift_count} drift event{'s' if result.drift_count != 1 else ''} detected")

    # Violations
    if result.violation_count:
        lines.append(f"  {RED}!{RESET} {result.violation_count} violation{'s' if result.violation_count != 1 else ''} recorded")

    # Revocations
    if result.revocation_count:
        lines.append(f"  {RED}!{RESET} {result.revocation_count} revocation{'s' if result.revocation_count != 1 else ''} issued")

    # Summary
    lines.append("")
    proc_delta = result.total_procedures_now - result.total_procedures_before
    proc_sign = f"+{proc_delta}" if proc_delta > 0 else str(proc_delta)
    if proc_delta > 0:
        lines.append(f"  Procedures: {result.total_procedures_before} {GREEN}{chr(0x2192)} {result.total_procedures_now} ({proc_sign}){RESET}")
    elif proc_delta < 0:
        lines.append(f"  Procedures: {result.total_procedures_before} {RED}{chr(0x2192)} {result.total_procedures_now} ({proc_sign}){RESET}")
    else:
        lines.append(f"  Procedures: {result.total_procedures_now} {DIM}(unchanged){RESET}")

    lines.append(f"  Anchors:    {GREEN}+{result.after_anchors}{RESET} in period")

    # Footer
    lines.append("")
    lines.append(f"  {DIM}Full timeline: https://sovereign.tenova.io/ai-witness{RESET}")
    lines.append("")

    return "\n".join(lines)


def render_diff_json(result: DiffResult) -> str:
    """Render machine-readable JSON diff."""
    data = {
        "tenant_id": result.tenant_id,
        "period": result.since_label,
        "since_ms": result.since_ms,
        "procedures": {
            "before": result.total_procedures_before,
            "now": result.total_procedures_now,
            "new": sorted(result.new_procedures),
            "dropped": sorted(result.dropped_procedures),
        },
        "models": {
            "new": sorted(result.new_models),
            "dropped": sorted(result.dropped_models),
        },
        "agents": {
            "new": sorted(result.new_agents),
        },
        "anchors": {
            "in_period": result.after_anchors,
            "before_period": result.before_anchors,
        },
        "events": {
            "drift": result.drift_count,
            "violations": result.violation_count,
            "revocations": result.revocation_count,
        },
    }
    return json.dumps(data, indent=2)


def render_diff_compact(result: DiffResult) -> str:
    """Render one-line compact diff."""
    proc_delta = result.total_procedures_now - result.total_procedures_before
    proc_str = f"+{proc_delta}" if proc_delta > 0 else str(proc_delta)
    parts = [
        f"procs:{result.total_procedures_now}({proc_str})",
        f"anchors:+{result.after_anchors}",
        f"models:+{len(result.new_models)}",
    ]
    if result.drift_count:
        parts.append(f"drift:{result.drift_count}")
    if result.violation_count:
        parts.append(f"violations:{result.violation_count}")
    if result.revocation_count:
        parts.append(f"revocations:{result.revocation_count}")
    return " | ".join(parts)


# ── CLI Entry Point ──

def handle_diff(args: List[str]) -> None:
    """CLI handler for `swt3 diff`."""
    use_json = "--json" in args
    use_compact = "--compact" in args
    wal_dir = None

    since = ""
    for i, arg in enumerate(args):
        if arg == "--since" and i + 1 < len(args):
            since = args[i + 1]
        elif arg == "--wal-path" and i + 1 < len(args):
            wal_dir = args[i + 1]

    if not since:
        print(f"\n  {BOLD}Usage:{RESET} swt3 diff --since <period>")
        print(f"  {DIM}Examples: --since 7d, --since 30d, --since 2026-07-17{RESET}\n")
        return

    since_ms = _parse_since(since)
    if not since_ms:
        print(f"\n  {RED}Invalid period: {since}{RESET}")
        print(f"  {DIM}Use: 1d, 7d, 14d, 30d, 90d, or YYYY-MM-DD{RESET}\n")
        sys.exit(1)

    # Load config for tenant_id
    from .status import _load_config_light
    config = _load_config_light()

    if config is None:
        if use_json:
            print(json.dumps({"error": "no config found"}))
        else:
            print(f"\n  {AMBER}No config found.{RESET} Run: {WHITE}swt3 init{RESET}\n")
        return

    tenant_id = config.get("tenant_id", "")
    if not tenant_id:
        print(f"\n  {RED}tenant_id not set in swt3.yaml{RESET}\n")
        return

    result = compute_diff(tenant_id=tenant_id, since=since, wal_dir=wal_dir)

    if use_json:
        print(render_diff_json(result))
    elif use_compact:
        print(render_diff_compact(result))
    else:
        print(render_diff(result))
