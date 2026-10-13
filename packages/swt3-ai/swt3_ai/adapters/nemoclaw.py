"""SWT3 AI Witness SDK -- NVIDIA NemoClaw Policy Engine Event Consumer.

Consumes structured policy decision events emitted by NemoClaw and mints
SWT3 witness anchors for each compliance-relevant decision.

NemoClaw is NVIDIA's open-source agent governance stack that sits above
OpenShell. While OpenShell sandboxes the runtime, NemoClaw evaluates
policy rules before actions reach the sandbox. This adapter witnesses
NemoClaw's policy decisions -- what was allowed, denied, and which rule
governed the decision.

SWT3 is an independent witness protocol. It records evidence of what
NemoClaw's policy engine reported. It does not enforce policy, define
rules, or intercept agent behavior.

Architecture:
    - Zero external dependencies (reads JSON, uses stdlib only)
    - Event consumer pattern (NemoClaw decides, we witness)
    - Stays out of the critical path (reads logs after decisions occur)
    - Complements OpenShell adapter (gate vs sandbox -- two independent attestations)

Usage:
    from swt3_ai.adapters.nemoclaw import NemoClawWitness

    # Programmatic: process events from any source
    ncw = NemoClawWitness()
    ncw.process_event(policy_decision_dict)

    # Log tailing: watch a NemoClaw decision log
    import asyncio
    asyncio.run(ncw.watch_log("/var/log/nemoclaw/decisions.jsonl"))

Requires: SWT3_DSN or SWT3_ENDPOINT + SWT3_API_KEY + SWT3_TENANT_ID env vars.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, AsyncIterator, Dict, Optional

logger = logging.getLogger("swt3_ai.nemoclaw")

# ── NemoClaw Event to SWT3 Procedure Mapping ─────────────────────────

# NemoClaw policy decision events mapped to SWT3 procedures.
# Keys are (request_type, decision) tuples.

NEMOCLAW_TO_PROCEDURE: Dict[str, Dict[str, str]] = {
    "tool_request": {
        "allow": "AI-TOOL.1",     # tool invocation permitted by policy
        "deny": "AI-SAND.1",      # tool blocked by policy
    },
    "network_request": {
        "allow": "AI-ACC.1",      # network access permitted
        "deny": "AI-ACC.1",       # network access denied
    },
    "filesystem_request": {
        "allow": "AI-DATA.1",     # file access permitted
        "deny": "AI-ACC.1",       # file access denied
    },
    "policy_evaluation": {
        "pass": "AI-TOOL.2",      # tool permission set matches charter
        "fail": "AI-TOOL.2",      # tool permission drift detected
    },
    "credential_access": {
        "allow": "AI-ACC.1",      # credential access permitted
        "deny": "AI-ACC.1",       # credential access denied
    },
}

_DENIED_DECISIONS = {"deny", "fail", "blocked"}


def _get_procedure(event: Dict[str, Any]) -> Optional[str]:
    """Map a NemoClaw policy event to an SWT3 procedure ID."""
    request_type = event.get("request_type", "")
    decision = event.get("decision", "allow")

    if isinstance(decision, str):
        decision = decision.lower()

    mapping = NEMOCLAW_TO_PROCEDURE.get(request_type)
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


# ── NemoClawWitness Class ─────────────────────────────────────────────

class NemoClawWitness:
    """Consumes NVIDIA NemoClaw policy decision events and mints SWT3 anchors.

    Stays out of the critical path -- reads decisions after they occur.
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
        """Process a single NemoClaw policy decision and mint the appropriate anchor.

        Args:
            event: NemoClaw policy decision dict with at minimum:
                - request_type: "tool_request" | "network_request" | etc.
                - decision: "allow" | "deny" | "pass" | "fail"
                Optional fields consumed:
                - policy_rule: Name of the rule that governed the decision
                - policy_version: Version of the policy document
                - resource: Target resource (tool name, URL, file path)
                - agent_id: Agent that made the request
                - timestamp: Event timestamp in ms

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

        from ..types import InferenceRecord

        timestamp_ms = event.get("timestamp", int(time.time() * 1000))
        decision = event.get("decision", "allow")
        denied = decision.lower() in _DENIED_DECISIONS if isinstance(decision, str) else False
        resource = event.get("resource", event.get("request_type", "unknown"))
        policy_rule = event.get("policy_rule", "default")
        agent_id = event.get("agent_id", "unknown")

        model_id = f"nemoclaw-{policy_rule}"

        record = InferenceRecord(
            model_id=model_id,
            model_hash=_sha256_truncated(model_id),
            prompt_hash=_sha256_truncated(f"{agent_id}:{resource}:{timestamp_ms}"),
            response_hash=_sha256_truncated(f"{decision}:{timestamp_ms}"),
            latency_ms=event.get("evaluation_ms", 0),
            provider="nvidia-nemoclaw",
            has_refusal=denied,
            guardrails_active=1,
            guardrails_required=1,
            guardrail_passed=not denied,
            tool_name=resource if procedure in ("AI-TOOL.1", "AI-SAND.1", "AI-TOOL.2") else None,
            access_target=resource if procedure in ("AI-ACC.1", "AI-DATA.1") else None,
            access_granted=not denied,
        )

        self._witness.record(record, procedures=[procedure])
        return procedure

    async def watch_log(self, log_path: str, poll_interval: float = 0.5) -> None:
        """Tail a NemoClaw decision log file and process events.

        Reads JSONL (one JSON decision per line). Tails indefinitely until
        cancelled.

        Args:
            log_path: Path to the NemoClaw .jsonl decision log.
            poll_interval: Seconds between poll cycles (default 0.5s).
        """
        logger.info("Watching NemoClaw log: %s", log_path)

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
                    event = json.loads(line)
                    self.process_event(event)
                except json.JSONDecodeError:
                    logger.debug("Skipping non-JSON line: %s", line[:80])

    async def watch_stream(self, stream: AsyncIterator[Dict[str, Any]]) -> None:
        """Process events from an async iterator.

        Args:
            stream: Async iterator yielding NemoClaw policy decision dicts.
        """
        async for event in stream:
            self.process_event(event)
