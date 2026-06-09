"""SWT3 AI Witness SDK -- Client-side chain verification.

Walk provenance reference chains using locally available data.
No HTTP calls -- the caller provides a lookup map built from their payloads.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .types import AnchorReference, ChainLink, ChainSummary


def build_lookup(
    payloads: Sequence[Dict[str, Any]],
) -> Dict[str, List[AnchorReference]]:
    """Build a lookup dict from an array of payload-like dicts.

    Each dict must have an ``anchor_fingerprint`` key and optional ``references`` list.
    References can be dicts with a ``fingerprint`` key or AnchorReference instances.
    """
    result: Dict[str, List[AnchorReference]] = {}
    for p in payloads:
        fp = p.get("anchor_fingerprint", "")
        refs_raw = p.get("references") or []
        refs: List[AnchorReference] = []
        for r in refs_raw:
            if isinstance(r, AnchorReference):
                refs.append(r)
            elif isinstance(r, dict):
                refs.append(AnchorReference(
                    fingerprint=r.get("fingerprint", ""),
                    relationship=r.get("relationship"),
                    provenance_token=r.get("provenance_token"),
                ))
            else:
                refs.append(AnchorReference(fingerprint=str(r)))
        result[fp] = refs
    return result


def walk_chain(
    start_fingerprint: str,
    lookup: Dict[str, List[AnchorReference]],
    max_depth: int = 10,
) -> ChainSummary:
    """Walk a provenance chain starting from a fingerprint using BFS.

    Cycle-safe via visited set. Depth-limited via max_depth.
    """
    links: List[ChainLink] = []
    gaps: List[str] = []
    visited: set = set()
    max_reached = 0
    truncated = False

    queue: deque[Tuple[str, int]] = deque()
    queue.append((start_fingerprint, 0))

    while queue:
        fp, depth = queue.popleft()

        if fp in visited:
            continue
        visited.add(fp)

        if depth > max_depth:
            truncated = True
            continue

        refs = lookup.get(fp)
        if refs is None:
            gaps.append(fp)
            continue

        if depth > max_reached:
            max_reached = depth

        links.append(ChainLink(fingerprint=fp, references=list(refs), depth=depth))

        for ref in refs:
            if ref.fingerprint not in visited:
                queue.append((ref.fingerprint, depth + 1))

    return ChainSummary(
        root=start_fingerprint,
        links=links,
        depth=max_reached,
        gaps=gaps,
        complete=len(gaps) == 0,
        truncated=truncated,
    )


def verify_chain_integrity(chain: ChainSummary) -> Dict[str, Any]:
    """Verify the integrity of a chain walk result.

    Returns dict with ``intact`` (bool) and ``issues`` (list of strings).
    """
    issues: List[str] = []

    if not chain.links:
        issues.append("Chain has no resolved links")

    if chain.gaps:
        issues.append(f"{len(chain.gaps)} referenced fingerprint(s) not found in lookup")

    if chain.truncated:
        issues.append("Chain traversal was truncated at max depth")

    return {"intact": len(issues) == 0, "issues": issues}
