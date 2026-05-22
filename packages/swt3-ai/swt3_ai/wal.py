"""SWT3 AI Witness SDK -- Write-Ahead Log (WAL).

Crash-resilient buffer persistence. Payloads are written to a JSONL
file before network transmission. If the process crashes, unsent
entries survive on disk and replay on next startup.

Format:
    Each line: JSON object with { seq, fingerprint, payload }
    Checkpoint file: single number (last successfully flushed seq)

Replay protection:
    A bounded ``OrderedDict`` of recently-seen anchor_fingerprint values
    prevents duplicate witness anchors from being submitted. The dict is
    populated from the WAL on startup and updated on each enqueue.

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional

from .types import WitnessPayload

logger = logging.getLogger("swt3_ai")

# Default WAL directory under OS temp
DEFAULT_WAL_DIR = os.path.join(tempfile.gettempdir(), "swt3-wal")

# Maximum fingerprints tracked for replay protection
DEFAULT_REPLAY_WINDOW = 50_000

# WAL file rotation threshold (5 MB)
WAL_ROTATION_BYTES = 5 * 1024 * 1024


class WriteAheadLog:
    """Crash-resilient write-ahead log for witness payloads.

    Payloads are persisted to a JSONL file before network transmission.
    On startup, unflushed entries are recovered and replayed into the
    buffer. A bounded replay set prevents duplicate anchor submission.

    Args:
        tenant_id: Tenant identifier (scopes the WAL file).
        wal_dir: Directory for WAL files. Default: $TMPDIR/swt3-wal
        replay_window: Max fingerprints in replay set. Default: 50000
        replay_protection: Enable dedup. Default: True
    """

    def __init__(
        self,
        tenant_id: str,
        wal_dir: Optional[str] = None,
        replay_window: int = DEFAULT_REPLAY_WINDOW,
        replay_protection: bool = True,
    ) -> None:
        self._lock = threading.Lock()
        self._replay_window = replay_window
        self._replay_enabled = replay_protection
        self._replay_set: OrderedDict[str, None] = OrderedDict()
        self._seq = 0
        self._checkpoint = 0

        # Tenant-scoped WAL file
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", tenant_id)
        wal_dir = wal_dir or DEFAULT_WAL_DIR
        os.makedirs(wal_dir, mode=0o700, exist_ok=True)
        self._wal_path = os.path.join(wal_dir, f"{safe}.wal")
        self._ckpt_path = os.path.join(wal_dir, f"{safe}.ckpt")

        # Load checkpoint
        if os.path.exists(self._ckpt_path):
            try:
                raw = Path(self._ckpt_path).read_text().strip()
                self._checkpoint = int(raw) if raw else 0
            except (ValueError, OSError):
                self._checkpoint = 0

        # Scan existing WAL to find max seq and populate replay set
        if os.path.exists(self._wal_path):
            self._scan_wal()

    def append(self, payload: WitnessPayload) -> int:
        """Write a payload to the WAL before sending.

        Returns:
            Sequence number (>0) on success, -1 if duplicate (replay protection).
        """
        fp = payload.anchor_fingerprint

        with self._lock:
            # Replay protection: reject duplicates
            if self._replay_enabled and fp and fp in self._replay_set:
                return -1

            self._seq += 1
            entry = {
                "seq": self._seq,
                "fingerprint": fp or "",
                "payload": payload.to_dict(),
            }

            with open(self._wal_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")

            # Track fingerprint
            if self._replay_enabled and fp:
                self._add_to_replay_set(fp)

            return self._seq

    def mark_flushed(self, up_to_seq: int) -> None:
        """Mark entries up to this sequence as successfully flushed.

        Updates the checkpoint file atomically (write-then-rename).
        """
        with self._lock:
            if up_to_seq <= self._checkpoint:
                return
            self._checkpoint = up_to_seq

            # Atomic write: temp then rename
            tmp = self._ckpt_path + ".tmp"
            Path(tmp).write_text(str(self._checkpoint))
            os.replace(tmp, self._ckpt_path)

            # Rotate WAL if large
            self._maybe_rotate()

    def recover(self) -> List[WitnessPayload]:
        """Recover unflushed entries from the WAL.

        Returns payloads that were written but never confirmed as flushed.
        Called on startup to replay into the buffer.
        """
        if not os.path.exists(self._wal_path):
            return []

        entries = self._read_entries()
        unflushed = [e for e in entries if e["seq"] > self._checkpoint]

        if unflushed:
            logger.info(
                "WAL recovery: %d unflushed entries found (checkpoint: %d, max seq: %d)",
                len(unflushed), self._checkpoint, self._seq,
            )

        payloads: List[WitnessPayload] = []
        for entry in unflushed:
            p = entry["payload"]
            payloads.append(WitnessPayload(
                procedure_id=p.get("procedure_id", ""),
                factor_a=p.get("factor_a", 0.0),
                factor_b=p.get("factor_b", 0.0),
                factor_c=p.get("factor_c", 0.0),
                clearing_level=p.get("clearing_level", 0),
                anchor_fingerprint=p.get("anchor_fingerprint", ""),
                anchor_epoch=p.get("anchor_epoch", 0),
                fingerprint_timestamp_ms=p.get("fingerprint_timestamp_ms", 0),
                ai_model_id=p.get("ai_model_id"),
                ai_prompt_hash=p.get("ai_prompt_hash"),
                ai_response_hash=p.get("ai_response_hash"),
                ai_system_prompt_hash=p.get("ai_system_prompt_hash"),
                ai_latency_ms=p.get("ai_latency_ms"),
                ai_input_tokens=p.get("ai_input_tokens"),
                ai_output_tokens=p.get("ai_output_tokens"),
                ai_context=p.get("ai_context"),
                agent_id=p.get("agent_id"),
                cycle_id=p.get("cycle_id"),
                payload_signature=p.get("payload_signature"),
                signing_key_id=p.get("signing_key_id"),
                signing_key_version=p.get("signing_key_version"),
                policy_version_hash=p.get("policy_version_hash"),
                jurisdiction=p.get("jurisdiction"),
                legal_basis=p.get("legal_basis"),
                purpose_class=p.get("purpose_class"),
                authorization_id=p.get("authorization_id"),
                revocation_target=p.get("revocation_target"),
                revocation_reason=p.get("revocation_reason"),
            ))
        return payloads

    def is_duplicate(self, fingerprint: str) -> bool:
        """Check if a fingerprint has already been seen (replay protection)."""
        if not self._replay_enabled or not fingerprint:
            return False
        with self._lock:
            return fingerprint in self._replay_set

    @property
    def current_seq(self) -> int:
        """Current sequence number."""
        return self._seq

    @property
    def current_checkpoint(self) -> int:
        """Last flushed checkpoint."""
        return self._checkpoint

    @property
    def replay_set_size(self) -> int:
        """Number of fingerprints in the replay set."""
        return len(self._replay_set)

    def destroy(self) -> None:
        """Remove WAL and checkpoint files (for testing or cleanup)."""
        for path in (self._wal_path, self._ckpt_path,
                     self._wal_path + ".tmp", self._ckpt_path + ".tmp"):
            try:
                os.unlink(path)
            except OSError:
                pass

    # -- Internal --

    def _scan_wal(self) -> None:
        """Scan WAL to find max seq and populate replay set."""
        entries = self._read_entries()
        for entry in entries:
            seq = entry.get("seq", 0)
            if seq > self._seq:
                self._seq = seq
            fp = entry.get("fingerprint", "")
            if self._replay_enabled and fp:
                self._add_to_replay_set(fp)

    def _read_entries(self) -> List[Dict[str, Any]]:
        """Read all WAL entries. Corrupted lines (from crashes) are skipped."""
        if not os.path.exists(self._wal_path):
            return []
        entries: List[Dict[str, Any]] = []
        try:
            with open(self._wal_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        # Corrupted line from partial write during crash
                        pass
        except OSError:
            pass
        return entries

    def _add_to_replay_set(self, fp: str) -> None:
        """Add fingerprint to replay set with FIFO eviction."""
        self._replay_set[fp] = None
        # Evict oldest if over window
        while len(self._replay_set) > self._replay_window:
            self._replay_set.popitem(last=False)

    def _maybe_rotate(self) -> None:
        """Rotate WAL if it exceeds size threshold."""
        if not os.path.exists(self._wal_path):
            return
        try:
            size = os.path.getsize(self._wal_path)
            if size < WAL_ROTATION_BYTES:
                return
        except OSError:
            return

        entries = self._read_entries()
        unflushed = [e for e in entries if e.get("seq", 0) > self._checkpoint]

        if not unflushed:
            # All flushed -- truncate
            Path(self._wal_path).write_text("")
        else:
            # Rewrite with only unflushed entries
            tmp = self._wal_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                for e in unflushed:
                    f.write(json.dumps(e, separators=(",", ":")) + "\n")
            os.replace(tmp, self._wal_path)
