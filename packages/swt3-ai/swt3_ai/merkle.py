"""SWT3 AI Witness SDK -- Merkle Tree + Tiered Accumulator.

Inline port of libswt3 Merkle primitives (no external dependency)
plus a tiered accumulator that computes session-level Merkle roots
on each flush.

Domain separation (SWT3:LEAF: / SWT3:NODE:) prevents second-preimage
attacks. Fingerprints are sorted lexicographically before tree
construction for determinism.

Tiers:
    Session root  -- computed per flush (SDK-side, this file)
    Endpoint root -- computed per interval (server-side, daily_merkle_rollups)

Spec: SWT3-SPEC-v1.0.md, Section 6.3 (Enclave Integrity)
Patent pending.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# -- Domain Separators --

LEAF_PREFIX = "SWT3:LEAF:"
NODE_PREFIX = "SWT3:NODE:"


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def hash_leaf(fingerprint: str) -> str:
    """Hash a leaf node (a single fingerprint). Domain-separated."""
    return _sha256(LEAF_PREFIX + fingerprint)


def hash_node(left: str, right: str) -> str:
    """Hash an internal node (two child hashes). Domain-separated."""
    return _sha256(NODE_PREFIX + left + ":" + right)


def get_merkle_root(fingerprints: List[str]) -> str:
    """Compute the Merkle root from a set of fingerprints.

    Sorted lexicographically for determinism. Returns empty string
    if the input list is empty.
    """
    if not fingerprints:
        return ""

    sorted_fps = sorted(fingerprints)
    level = [hash_leaf(fp) for fp in sorted_fps]

    while len(level) > 1:
        next_level: List[str] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                next_level.append(hash_node(level[i], level[i + 1]))
            else:
                next_level.append(level[i])
        level = next_level

    return level[0]


@dataclass
class MerkleProofStep:
    """A single step in a Merkle inclusion proof."""
    hash: str
    position: str  # "left" | "right"


@dataclass
class MerkleProof:
    """Merkle inclusion proof for a single fingerprint."""
    fingerprint: str
    leaf_hash: str
    root: str
    steps: List[MerkleProofStep] = field(default_factory=list)


def get_merkle_proof(
    fingerprints: List[str],
    target: str,
) -> Optional[MerkleProof]:
    """Generate a Merkle inclusion proof for a fingerprint.

    Returns None if the fingerprint is not in the set.
    """
    if not fingerprints:
        return None

    sorted_fps = sorted(fingerprints)
    if target not in sorted_fps:
        return None
    target_index = sorted_fps.index(target)

    level = [hash_leaf(fp) for fp in sorted_fps]
    index = target_index
    steps: List[MerkleProofStep] = []

    while len(level) > 1:
        next_level: List[str] = []
        next_index = index // 2

        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                if i == index or i + 1 == index:
                    if index % 2 == 0:
                        steps.append(MerkleProofStep(hash=level[i + 1], position="right"))
                    else:
                        steps.append(MerkleProofStep(hash=level[i], position="left"))
                next_level.append(hash_node(level[i], level[i + 1]))
            else:
                next_level.append(level[i])

        level = next_level
        index = next_index

    return MerkleProof(
        fingerprint=target,
        leaf_hash=hash_leaf(target),
        root=level[0],
        steps=steps,
    )


def verify_merkle_proof(fingerprint: str, proof: MerkleProof) -> bool:
    """Verify a Merkle inclusion proof.

    Requires only the fingerprint, proof steps, and claimed root.
    No access to the full fingerprint set needed.
    """
    current = hash_leaf(fingerprint)

    for step in proof.steps:
        if step.position == "left":
            current = hash_node(step.hash, current)
        else:
            current = hash_node(current, step.hash)

    return current == proof.root


# -- Session Root Entry --

@dataclass
class SessionRoot:
    """A session-level Merkle root computed on flush."""
    root: str
    fingerprints: List[str]
    count: int
    timestamp: str


# -- Merkle Config --

@dataclass
class MerkleConfig:
    """Merkle accumulator configuration from .swt3.yaml merkle section."""
    enabled: bool = True
    accumulator_interval: int = 0


# -- Tiered Merkle Accumulator --

class MerkleAccumulator:
    """Tiered Merkle Accumulator.

    Collects anchor fingerprints and computes a session-level Merkle root
    on each flush. Session roots are persisted to a JSONL file for
    crash recovery and auditor export.

    Usage::

        acc = MerkleAccumulator(tenant_id="ACME")
        acc.add("abc123def456")
        acc.add("789012345678")
        root = acc.flush()  # computes + persists session root
    """

    def __init__(
        self,
        persist_dir: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> None:
        self._fingerprints: List[str] = []
        self._session_roots: List[SessionRoot] = []
        self._persist_path: Optional[Path] = None

        if persist_dir or tenant_id:
            d = Path(persist_dir) if persist_dir else Path(os.path.join(
                os.environ.get("TMPDIR", "/tmp"), "swt3-merkle"
            ))
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
            safe = re.sub(r"[^a-zA-Z0-9_-]", "_", tenant_id or "default")
            self._persist_path = d / f"{safe}.roots.jsonl"

            # Load existing session roots
            if self._persist_path.is_file():
                for line in self._persist_path.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        self._session_roots.append(SessionRoot(
                            root=data["root"],
                            fingerprints=data["fingerprints"],
                            count=data["count"],
                            timestamp=data["timestamp"],
                        ))
                    except (json.JSONDecodeError, KeyError):
                        pass  # corrupted line

    def add(self, fingerprint: str) -> None:
        """Add a fingerprint to the current session batch."""
        self._fingerprints.append(fingerprint)

    def add_many(self, fingerprints: List[str]) -> None:
        """Add multiple fingerprints."""
        self._fingerprints.extend(fingerprints)

    @property
    def pending(self) -> int:
        """Number of fingerprints in the current (unflushed) batch."""
        return len(self._fingerprints)

    @property
    def roots(self) -> List[SessionRoot]:
        """All session roots computed so far."""
        return list(self._session_roots)

    def flush(self) -> Optional[SessionRoot]:
        """Compute the Merkle root for the current batch and persist it.

        Returns the session root entry, or None if the batch is empty.
        """
        if not self._fingerprints:
            return None

        fps = list(self._fingerprints)
        root = get_merkle_root(fps)
        entry = SessionRoot(
            root=root,
            fingerprints=fps,
            count=len(fps),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        self._session_roots.append(entry)
        self._fingerprints = []

        # Persist to JSONL
        if self._persist_path:
            with open(self._persist_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "root": entry.root,
                    "fingerprints": entry.fingerprints,
                    "count": entry.count,
                    "timestamp": entry.timestamp,
                }) + "\n")

        return entry

    def prove(
        self,
        fingerprint: str,
        root_hash: Optional[str] = None,
    ) -> Optional[MerkleProof]:
        """Generate a Merkle proof for a fingerprint within a session root.

        If no root_hash is specified, searches the most recent session.
        """
        if root_hash:
            sessions = [s for s in self._session_roots if s.root == root_hash]
        else:
            sessions = self._session_roots[-1:] if self._session_roots else []

        for session in sessions:
            proof = get_merkle_proof(session.fingerprints, fingerprint)
            if proof:
                return proof

        return None

    def reset(self) -> None:
        """Reset pending fingerprints (keeps history)."""
        self._fingerprints = []

    def clear(self) -> None:
        """Clear all state including history (for testing)."""
        self._fingerprints = []
        self._session_roots = []

    def compose_session_roots(
        self,
        session_root_hashes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Compose multiple session roots into a higher-level Merkle root.

        Enables aggregate attestation over an entire audit period (daily,
        weekly, organizational) without re-processing individual anchors.
        Any individual session can be proven as included via prove_session().

        Args:
            session_root_hashes: Session root hashes to compose.
                If None, uses all session roots from this accumulator's history.

        Returns:
            Dict with aggregate_root, session_count, and prove_session callable.
        """
        roots = session_root_hashes if session_root_hashes is not None else [
            s.root for s in self._session_roots
        ]
        if not roots:
            return {"aggregate_root": "", "session_count": 0, "prove_session": lambda _: None}

        aggregate_root = get_merkle_root(roots)

        def prove_session(session_root_hash: str) -> Optional[MerkleProof]:
            return get_merkle_proof(roots, session_root_hash)

        return {
            "aggregate_root": aggregate_root,
            "session_count": len(roots),
            "prove_session": prove_session,
        }
