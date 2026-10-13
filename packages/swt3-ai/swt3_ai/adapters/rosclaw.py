"""SWT3 AI Witness SDK -- ROSClaw Structured Audit Log Consumer.

Consumes structured audit log entries emitted by ROSClaw (the OpenClaw
ROS 2 executive layer for agentic robot control) and mints SWT3 witness
anchors for each governance-relevant event.

ROSClaw formalizes the boundary between cognition and actuation as a
contract C = (A, O, V, L) where L is a structured audit logger. Every
robot action gets an append-only log entry recording the proposal,
validation decision, and execution outcome.

SWT3 is an independent witness protocol. It records evidence of what
ROSClaw's validator reported. It does not define safety envelopes,
keep-out zones, or velocity bounds.

Architecture:
    - Zero external dependencies (reads JSON, uses stdlib only)
    - Zero ROS dependencies (reads structured log output, does NOT import rospy/rclpy)
    - Event consumer pattern (ROSClaw validates, we witness)
    - Stays out of the robot's control loop

Usage:
    from swt3_ai.adapters.rosclaw import ROSClawWitness

    # Programmatic: process entries from any source
    rcw = ROSClawWitness()
    rcw.process_entry(audit_log_entry_dict)

    # Log tailing: watch a ROSClaw audit log
    import asyncio
    asyncio.run(rcw.watch_log("/var/log/rosclaw/audit.jsonl"))

Requires: SWT3_DSN or SWT3_ENDPOINT + SWT3_API_KEY + SWT3_TENANT_ID env vars.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, AsyncIterator, Dict, Optional

logger = logging.getLogger("swt3_ai.rosclaw")

# ── ROSClaw Audit Entry to SWT3 Procedure Mapping ────────────────────

# ROSClaw audit log entries follow the schema:
#   (t, o_t, u_t, d_t, r_t, y_t) where:
#   t   = timestamp
#   o_t = observation (sensor data summary)
#   u_t = action proposed (command to actuator)
#   d_t = validator decision (executed, blocked, modified)
#   r_t = validation reason (velocity_bound, keepout_zone, etc.)
#   y_t = execution outcome (completed, failed, aborted) or null if blocked
#
# We map (entry_type, decision/reason) to SWT3 procedures.

ROSCLAW_TO_PROCEDURE: Dict[str, Dict[str, str]] = {
    "action_proposal": {
        "executed": "AI-TOOL.1",    # actuator command executed
        "blocked": "AI-SAFE.1",     # validator blocked the action
        "modified": "AI-TOOL.1",    # action was modified before execution
    },
    "safety_violation": {
        "velocity_bound": "AI-SAFE.1",   # exceeded velocity limits
        "keepout_zone": "AI-SAFE.1",     # entered restricted zone
        "rate_limit": "AI-SAFE.1",       # action rate exceeded
        "precondition": "AI-SAFE.1",     # precondition check failed
        "force_limit": "AI-SAFE.1",      # force/torque exceeded
        "collision": "AI-SAFE.1",        # collision detected
    },
    "capability_discovery": {
        "registered": "AI-TOOL.2",       # new tool/actuator registered
        "deregistered": "AI-TOOL.2",     # tool/actuator removed
    },
    "observation": {
        "processed": "AI-INF.1",         # sensor observation processed
    },
    "lifecycle": {
        "spawn": "AI-LCM.1",            # agent spawned
        "terminate": "AI-LCM.1",        # agent terminated
        "checkpoint": "AI-LCM.1",       # state checkpointed
    },
}

_BLOCKED_DECISIONS = {"blocked", "denied", "rejected"}


def _get_procedure(entry: Dict[str, Any]) -> Optional[str]:
    """Map a ROSClaw audit log entry to an SWT3 procedure ID."""
    entry_type = entry.get("entry_type", "")
    # Decision field varies: d_t for action_proposal, reason for safety_violation
    decision = entry.get("decision", entry.get("reason", entry.get("status", "")))

    if isinstance(decision, str):
        decision = decision.lower()

    mapping = ROSCLAW_TO_PROCEDURE.get(entry_type)
    if mapping is None:
        return None

    return mapping.get(decision)


# ── Witness Resolution ────────────────────────────────────────────────

def _resolve_witness(explicit: Any, overrides: Dict[str, Any]) -> Any:
    """Resolve or create a Witness instance from env vars."""
    if explicit is not None:
        return explicit

    from ..witness import Witness

    dsn = os.environ.get("SWT3_DSN")
    if dsn:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(dsn)
            api_key = parsed.username or ""
            host = parsed.hostname or ""
            scheme = parsed.scheme or "https"
            port = f":{parsed.port}" if parsed.port else ""
            tenant_id = parsed.path.lstrip("/")
            endpoint = f"{scheme}://{host}{port}"
        except Exception:
            logger.warning("Failed to parse SWT3_DSN, falling back to individual env vars")
            dsn = None

    if not dsn:
        endpoint = os.environ.get("SWT3_ENDPOINT")
        api_key = os.environ.get("SWT3_API_KEY", "")
        tenant_id = os.environ.get("SWT3_TENANT_ID", "")

    if not endpoint or not api_key or not tenant_id:
        logger.debug(
            "SWT3 witness not configured. Set SWT3_DSN or "
            "SWT3_ENDPOINT+SWT3_API_KEY+SWT3_TENANT_ID to enable."
        )
        return None

    clearing = int(overrides.get(
        "clearing_level",
        os.environ.get("SWT3_CLEARING_LEVEL", "1"),
    ))

    return Witness(
        endpoint=endpoint,
        api_key=api_key,
        tenant_id=tenant_id,
        clearing_level=clearing,
        agent_id=overrides.get("agent_id", os.environ.get("SWT3_AGENT_ID")),
        signing_key=overrides.get("signing_key", os.environ.get("SWT3_SIGNING_KEY")),
        signing_key_id=overrides.get("signing_key_id", os.environ.get("SWT3_SIGNING_KEY_ID")),
        signing_key_version=overrides.get("signing_key_version"),
        jurisdiction=overrides.get("jurisdiction", os.environ.get("SWT3_JURISDICTION")),
        legal_basis=overrides.get("legal_basis", os.environ.get("SWT3_LEGAL_BASIS")),
        purpose_class=overrides.get("purpose_class", os.environ.get("SWT3_PURPOSE_CLASS")),
    )


def _sha256_truncated(text: str, length: int = 16) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


# ── ROSClawWitness Class ──────────────────────────────────────────────

class ROSClawWitness:
    """Consumes ROSClaw structured audit log entries and mints SWT3 anchors.

    Stays out of the robot's control loop -- reads audit logs after events
    occur. Zero external dependencies. Zero ROS dependencies.

    Args:
        witness: Explicit Witness instance (overrides env config).
        **overrides: Override env vars (clearing_level, agent_id, etc.).
    """

    def __init__(self, witness: Any = None, **overrides: Any) -> None:
        self._witness = _resolve_witness(witness, overrides)
        self._entries_processed = 0
        self._entries_skipped = 0

    @property
    def is_configured(self) -> bool:
        """Whether a Witness instance is available."""
        return self._witness is not None

    @property
    def stats(self) -> Dict[str, int]:
        """Processing statistics."""
        return {
            "processed": self._entries_processed,
            "skipped": self._entries_skipped,
        }

    def process_entry(self, entry: Dict[str, Any]) -> Optional[str]:
        """Process a single ROSClaw audit log entry and mint the appropriate anchor.

        Args:
            entry: ROSClaw audit log entry dict with at minimum:
                - entry_type: "action_proposal" | "safety_violation" | etc.
                - decision: "executed" | "blocked" | "modified" (for action_proposal)
                - reason: "velocity_bound" | "keepout_zone" | etc. (for safety_violation)
                Optional fields consumed:
                - action_name: Name of the proposed action / actuator command
                - agent_id: Agent that proposed the action
                - outcome: Execution outcome ("completed", "failed", "aborted")
                - timestamp: Entry timestamp in ms
                - observation_hash: Hash of sensor observation at decision time

        Returns:
            The SWT3 procedure ID that was witnessed, or None if skipped.
        """
        if self._witness is None:
            return None

        procedure = _get_procedure(entry)
        if procedure is None:
            self._entries_skipped += 1
            return None

        self._entries_processed += 1

        from ..types import InferenceRecord

        timestamp_ms = entry.get("timestamp", int(time.time() * 1000))
        decision = entry.get("decision", entry.get("reason", entry.get("status", "unknown")))
        blocked = decision.lower() in _BLOCKED_DECISIONS if isinstance(decision, str) else False
        action_name = entry.get("action_name", entry.get("entry_type", "unknown"))
        agent_id = entry.get("agent_id", "unknown")
        outcome = entry.get("outcome")

        model_id = f"rosclaw-{action_name}"

        record = InferenceRecord(
            model_id=model_id,
            model_hash=_sha256_truncated(model_id),
            prompt_hash=_sha256_truncated(f"{agent_id}:{action_name}:{timestamp_ms}"),
            response_hash=_sha256_truncated(f"{decision}:{outcome or 'none'}:{timestamp_ms}"),
            latency_ms=entry.get("execution_ms", 0),
            provider="rosclaw",
            has_refusal=blocked,
            guardrails_active=1 if procedure == "AI-SAFE.1" else 0,
            guardrails_required=1 if procedure == "AI-SAFE.1" else 0,
            guardrail_passed=not blocked,
            tool_name=action_name if procedure in ("AI-TOOL.1", "AI-TOOL.2") else None,
            access_target=None,
            access_granted=not blocked,
        )

        self._witness.record(record, procedures=[procedure])
        return procedure

    async def watch_log(self, log_path: str, poll_interval: float = 0.5) -> None:
        """Tail a ROSClaw audit log file and process entries.

        Reads JSONL (one JSON entry per line). Tails indefinitely until
        cancelled.

        Args:
            log_path: Path to the ROSClaw .jsonl audit log.
            poll_interval: Seconds between poll cycles (default 0.5s).
        """
        logger.info("Watching ROSClaw log: %s", log_path)

        while not os.path.exists(log_path):
            await asyncio.sleep(poll_interval)

        with open(log_path, "r") as f:
            f.seek(0, 2)

            while True:
                line = f.readline()
                if not line:
                    await asyncio.sleep(poll_interval)
                    continue

                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                    self.process_entry(entry)
                except json.JSONDecodeError:
                    logger.debug("Skipping non-JSON line: %s", line[:80])

    async def watch_stream(self, stream: AsyncIterator[Dict[str, Any]]) -> None:
        """Process entries from an async iterator.

        Args:
            stream: Async iterator yielding ROSClaw audit log entry dicts.
        """
        async for entry in stream:
            self.process_entry(entry)
