"""SWT3 AI Witness SDK -- NVIDIA OpenShell OCSF Event Consumer.

Consumes OCSF v1.7.0 structured events emitted by OpenShell sandboxes
and mints SWT3 witness anchors for each compliance-relevant event.

OpenShell is NVIDIA's open-source (Apache 2.0) sandboxed agent runtime.
It emits events for network connections, process lifecycle, filesystem
policy decisions, and configuration changes. This adapter reads those
events and produces cryptographic attestation anchors.

Architecture:
    - Zero external dependencies (reads JSON, uses stdlib only)
    - Event consumer pattern (not a decorator -- OpenShell emits, we consume)
    - Stays out of the critical path (reads logs after events occur)
    - Graceful degradation (unknown events skipped, no witness = no-op)

Usage:
    from swt3_ai.adapters.openshell import OpenShellWitness

    # Programmatic: process events from any source
    osw = OpenShellWitness()
    osw.process_event(ocsf_event_dict)

    # Log tailing: watch a sandbox log file
    import asyncio
    asyncio.run(osw.watch_log("/var/log/openshell/sandbox-001.jsonl"))

    # Stream: pipe from stdin or socket
    asyncio.run(osw.watch_stream(async_event_iterator))

Requires: SWT3_DSN or SWT3_ENDPOINT + SWT3_API_KEY + SWT3_TENANT_ID env vars.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, AsyncIterator, Dict, Optional

logger = logging.getLogger("swt3_ai.openshell")

# ── OCSF Event Class to SWT3 Procedure Mapping ─────────────────────────

# OpenShell OCSF v1.7.0 event classes mapped to SWT3 procedures.
# Keys are (class_name, disposition) tuples. Disposition values:
#   "allow" = policy permitted the action
#   "deny"  = policy blocked the action
#   "route" = credential injection / proxy forward

OCSF_TO_PROCEDURE: Dict[str, Dict[str, str]] = {
    "network_activity": {
        "allow": "AI-INF.1",      # inference call permitted
        "deny": "AI-SEC.1",       # blocked by sandbox policy
        "route": "AI-ACC.1",      # credential injection / proxy
    },
    "process_activity": {
        "launch": "AI-ID.1",      # agent identity established
        "terminate": "AI-ID.1",   # agent lifecycle end
        "tool_call": "AI-TOOL.1", # tool invocation
    },
    "file_activity": {
        "allow": "AI-DATA.1",     # data access permitted
        "deny": "AI-SEC.1",       # data access blocked
    },
    "configuration_change": {
        "update": "AI-MDL.2",     # policy mutation
    },
    "security_finding": {
        "guardrail_allow": "AI-GRD.1",   # guardrail passed
        "guardrail_deny": "AI-GRD.1",    # guardrail blocked
    },
}

# Procedures that map to security events (factor_c = 0 for denied)
_SECURITY_PROCEDURES = {"AI-SEC.1", "AI-GRD.1"}


def _get_procedure(event: Dict[str, Any]) -> Optional[str]:
    """Map an OCSF event to an SWT3 procedure ID.

    Returns None if the event class/disposition is not mapped (skip silently).
    """
    class_name = event.get("class_name", "")
    disposition = event.get("disposition", "allow")

    # Normalize disposition string
    if isinstance(disposition, int):
        # OCSF uses integer disposition IDs: 1=allowed, 2=denied, 6=routed
        disposition = {1: "allow", 2: "deny", 6: "route"}.get(disposition, "allow")

    mapping = OCSF_TO_PROCEDURE.get(class_name)
    if mapping is None:
        return None

    return mapping.get(disposition)


# ── Witness Resolution (reuses Dynamo env pattern) ──────────────────────

def _resolve_witness(explicit: Any, overrides: Dict[str, Any]) -> Any:
    """Resolve or create a Witness instance from env vars."""
    if explicit is not None:
        return explicit

    from ..witness import Witness

    # Try DSN first
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


# ── Helper: SHA-256 truncated ───────────────────────────────────────────

def _sha256_truncated(text: str, length: int = 16) -> str:
    """SHA-256 hash truncated to `length` hex chars."""
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


# ── OpenShellWitness Class ──────────────────────────────────────────────

class OpenShellWitness:
    """Consumes NVIDIA OpenShell OCSF events and mints SWT3 witness anchors.

    Stays out of the critical path -- reads events after they occur.
    Zero external dependencies beyond stdlib.

    Args:
        witness: Explicit Witness instance (overrides env config).
        **overrides: Override env vars (clearing_level, agent_id, etc.).
    """

    def __init__(self, witness: Any = None, **overrides: Any) -> None:
        self._witness = _resolve_witness(witness, overrides)
        self._events_processed = 0
        self._events_skipped = 0

    @property
    def is_configured(self) -> bool:
        """Whether a Witness instance is available."""
        return self._witness is not None

    @property
    def stats(self) -> Dict[str, int]:
        """Processing statistics."""
        return {
            "processed": self._events_processed,
            "skipped": self._events_skipped,
        }

    def process_event(self, event: Dict[str, Any]) -> Optional[str]:
        """Process a single OCSF event and mint the appropriate anchor.

        Args:
            event: OCSF v1.7.0 event dict from OpenShell sandbox log.

        Returns:
            The SWT3 procedure ID that was witnessed, or None if skipped.
        """
        if self._witness is None:
            return None

        procedure = _get_procedure(event)
        if procedure is None:
            self._events_skipped += 1
            return None

        self._events_processed += 1

        # Build InferenceRecord from OCSF event
        from ..types import InferenceRecord

        # Extract common fields
        timestamp_ms = event.get("time", int(time.time() * 1000))
        activity_name = event.get("activity_name", "unknown")
        disposition = event.get("disposition", "allow")
        denied = disposition in ("deny", 2) or (isinstance(disposition, str) and "deny" in disposition)

        # Model ID: try dst_endpoint for network events, else use activity
        dst = event.get("dst_endpoint", {})
        model_id = dst.get("hostname", activity_name) if isinstance(dst, dict) else activity_name

        # Content hashes from event metadata (if available)
        metadata = event.get("metadata", {})
        request_uid = event.get("request_uid", "")
        response_uid = event.get("response_uid", "")

        prompt_hash = _sha256_truncated(request_uid or str(event.get("activity_id", "")))
        response_hash = _sha256_truncated(response_uid or str(timestamp_ms))

        # Duration (OCSF duration field is in milliseconds)
        duration_ms = event.get("duration", 0)

        # For security events: factor_c = 0 (denied), factor_c = 1 (allowed)
        # The clearing engine uses guardrail_passed to determine verdict
        guardrail_passed = not denied

        # Tool name for process_activity/tool_call events
        tool_name = None
        if procedure == "AI-TOOL.1":
            process = event.get("process", {})
            tool_name = process.get("name", activity_name) if isinstance(process, dict) else activity_name

        # Access target for network/file events
        access_target = None
        access_granted = not denied
        if procedure in ("AI-ACC.1", "AI-DATA.1", "AI-SEC.1"):
            if isinstance(dst, dict):
                access_target = dst.get("url") or dst.get("hostname") or dst.get("ip")
            file_info = event.get("file", {})
            if isinstance(file_info, dict) and file_info.get("path"):
                access_target = file_info["path"]

        record = InferenceRecord(
            model_id=model_id,
            model_hash=_sha256_truncated(model_id),
            prompt_hash=prompt_hash,
            response_hash=response_hash,
            latency_ms=duration_ms,
            provider="nvidia-openshell",
            has_refusal=denied,
            guardrails_active=1 if procedure in _SECURITY_PROCEDURES else 0,
            guardrails_required=1 if procedure in _SECURITY_PROCEDURES else 0,
            guardrail_passed=guardrail_passed,
            tool_name=tool_name,
            access_target=access_target,
            access_granted=access_granted,
        )

        # Record with specific procedure override
        self._witness.record(record, procedures=[procedure])
        return procedure

    async def watch_log(self, log_path: str, poll_interval: float = 0.5) -> None:
        """Tail an OpenShell sandbox log file and process events.

        Reads JSONL (one JSON event per line). Tails indefinitely until
        cancelled. New lines are processed as they appear.

        Args:
            log_path: Path to the sandbox .jsonl log file.
            poll_interval: Seconds between poll cycles (default 0.5s).
        """
        logger.info("Watching OpenShell log: %s", log_path)

        # Wait for file to exist
        while not os.path.exists(log_path):
            await asyncio.sleep(poll_interval)

        with open(log_path, "r") as f:
            # Seek to end (only process new events)
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
                    event = json.loads(line)
                    self.process_event(event)
                except json.JSONDecodeError:
                    logger.debug("Skipping non-JSON line: %s", line[:80])

    async def watch_stream(self, stream: AsyncIterator[Dict[str, Any]]) -> None:
        """Process events from an async iterator.

        Use this for programmatic integration (stdin, socket, queue).

        Args:
            stream: Async iterator yielding OCSF event dicts.
        """
        async for event in stream:
            self.process_event(event)
