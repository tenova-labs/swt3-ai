"""SWT3 AI Witness SDK -- Evidence Bundle Exporter.

Produces self-contained evidence bundles for sandbox environments
and auditor handoff. Reads WAL entries and Merkle session roots,
applies a watermark tier (demo/connected/sovereign), and exports
as JSON or HTML.

Patent pending.
"""

from __future__ import annotations

import html
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class EvidenceBundleMetadata:
    generated_at: str
    sdk_version: str
    tenant_id: str
    agent_id: str
    clearing_level: int
    anchor_count: int
    watermark: str  # "demo" | "connected" | "sovereign"
    export_timestamp: int


@dataclass
class EvidenceAnchor:
    seq: int
    fingerprint: str
    procedure_id: str
    factor_a: float
    factor_b: float
    factor_c: float
    epoch: int
    timestamp_ms: int


@dataclass
class EvidenceBundle:
    metadata: EvidenceBundleMetadata
    anchors: List[EvidenceAnchor]
    merkle_roots: List[Dict[str, Any]]


class EvidenceExporter:
    """Evidence bundle exporter for sandbox and auditor handoff.

    Watermark tiers:
        demo      -- no API key configured
        connected -- API key present
        sovereign -- signing key + hardware attestation
    """

    def __init__(
        self,
        *,
        wal_dir: Optional[str] = None,
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        clearing_level: int = 1,
        api_key: Optional[str] = None,
        signing_key: Optional[str] = None,
        has_hardware_attestation: bool = False,
        merkle_roots: Optional[List[Any]] = None,
    ) -> None:
        self.wal_dir = wal_dir
        self.tenant_id = tenant_id or "UNKNOWN"
        self.agent_id = agent_id or "UNKNOWN"
        self.clearing_level = clearing_level
        self.api_key = api_key
        self.signing_key = signing_key
        self.has_hardware_attestation = has_hardware_attestation
        self.merkle_roots = merkle_roots or []

    def _compute_watermark(self) -> str:
        if self.signing_key and self.has_hardware_attestation:
            return "sovereign"
        if self.api_key:
            return "connected"
        return "demo"

    def _read_wal(self) -> List[Dict[str, Any]]:
        d = Path(self.wal_dir) if self.wal_dir else Path(
            os.environ.get("TMPDIR", "/tmp"), "swt3-wal"
        )
        safe = self.tenant_id.replace("/", "_").replace("\\", "_")
        wal_path = d / f"{safe}.wal"

        if not wal_path.is_file():
            return []

        entries = []
        for line in wal_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entries.append(json.loads(line))
            except (json.JSONDecodeError, KeyError):
                pass
        return entries

    def build_bundle(self) -> EvidenceBundle:
        entries = self._read_wal()
        watermark = self._compute_watermark()

        anchors = []
        for e in entries:
            p = e.get("payload", {})
            anchors.append(EvidenceAnchor(
                seq=e.get("seq", 0),
                fingerprint=e.get("fingerprint", ""),
                procedure_id=p.get("procedure_id", "unknown"),
                factor_a=p.get("factor_a", 0),
                factor_b=p.get("factor_b", 0),
                factor_c=p.get("factor_c", 0),
                epoch=p.get("anchor_epoch", 0),
                timestamp_ms=p.get("fingerprint_timestamp_ms", 0),
            ))

        anchors.sort(key=lambda a: a.timestamp_ms)

        merkle = []
        for r in self.merkle_roots:
            root_val = getattr(r, "root", None) or r.get("root", "") if isinstance(r, dict) else ""
            count_val = getattr(r, "count", None) or r.get("count", 0) if isinstance(r, dict) else 0
            ts_val = getattr(r, "timestamp", None) or r.get("timestamp", "") if isinstance(r, dict) else ""
            if hasattr(r, "root"):
                root_val = r.root
                count_val = r.count
                ts_val = r.timestamp
            merkle.append({"root": root_val, "count": count_val, "timestamp": ts_val})

        now = datetime.now(timezone.utc)
        return EvidenceBundle(
            metadata=EvidenceBundleMetadata(
                generated_at=now.isoformat(),
                sdk_version="0.6.1",
                tenant_id=self.tenant_id,
                agent_id=self.agent_id,
                clearing_level=self.clearing_level,
                anchor_count=len(anchors),
                watermark=watermark,
                export_timestamp=int(now.timestamp() * 1000),
            ),
            anchors=anchors,
            merkle_roots=merkle,
        )

    def export_json(self) -> str:
        bundle = self.build_bundle()
        return json.dumps({
            "metadata": {
                "generatedAt": bundle.metadata.generated_at,
                "sdkVersion": bundle.metadata.sdk_version,
                "tenantId": bundle.metadata.tenant_id,
                "agentId": bundle.metadata.agent_id,
                "clearingLevel": bundle.metadata.clearing_level,
                "anchorCount": bundle.metadata.anchor_count,
                "watermark": bundle.metadata.watermark,
                "exportTimestamp": bundle.metadata.export_timestamp,
            },
            "anchors": [
                {
                    "seq": a.seq,
                    "fingerprint": a.fingerprint,
                    "procedureId": a.procedure_id,
                    "factorA": a.factor_a,
                    "factorB": a.factor_b,
                    "factorC": a.factor_c,
                    "epoch": a.epoch,
                    "timestampMs": a.timestamp_ms,
                }
                for a in bundle.anchors
            ],
            "merkleRoots": bundle.merkle_roots,
        }, indent=2)

    def export_html(self) -> str:
        bundle = self.build_bundle()
        m = bundle.metadata
        ts = m.generated_at.replace("T", " ")[:19]

        wm_styles = {
            "demo": ("#FEF3C7", "#92400E", "DEMO / UNVERIFIED"),
            "connected": ("#D1FAE5", "#065F46", "CONNECTED"),
            "sovereign": ("#FEF9C3", "#854D0E", "SOVEREIGN"),
        }
        bg, fg, label = wm_styles.get(m.watermark, wm_styles["demo"])

        anchor_rows = "\n".join(
            f"<tr><td>{a.seq}</td><td>{a.procedure_id}</td>"
            f"<td style='font-family:monospace;font-size:.8rem'>{html.escape(a.fingerprint)}</td>"
            f"<td>{a.factor_a}</td><td>{a.factor_b}</td><td>{a.factor_c}</td></tr>"
            for a in bundle.anchors
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SWT3 Evidence Bundle</title>
<style>
  body{{background:#0F172A;color:#E2E8F0;font-family:system-ui,sans-serif;margin:0;padding:2rem}}
  h1{{color:#F8FAFC;font-size:1.5rem}}
  h2{{color:#94A3B8;font-size:1.1rem;margin-top:2rem}}
  table{{border-collapse:collapse;width:100%;margin:.5rem 0}}
  th,td{{border:1px solid #334155;padding:.4rem .6rem;text-align:left;font-size:.85rem}}
  th{{background:#1E293B;color:#94A3B8}}
  .watermark{{display:inline-block;padding:.3rem .8rem;border-radius:4px;font-weight:700;font-size:.9rem;margin-bottom:1rem;background:{bg};color:{fg}}}
  .meta{{color:#94A3B8;font-size:.85rem;margin:.2rem 0}}
  .footer{{margin-top:2rem;padding-top:1rem;border-top:1px solid #334155;color:#64748B;font-size:.75rem}}
</style>
</head>
<body>
<h1>SWT3 Evidence Bundle</h1>
<div class="watermark">{label}</div>
<p class="meta">Generated: {ts} UTC</p>
<p class="meta">Tenant: {html.escape(m.tenant_id)} | Agent: {html.escape(m.agent_id)} | Clearing Level: {m.clearing_level}</p>
<p class="meta">Anchors: {m.anchor_count} | Merkle Roots: {len(bundle.merkle_roots)}</p>

<h2>Witness Anchors</h2>
{"<table><tr><th>#</th><th>Procedure</th><th>Fingerprint</th><th>A</th><th>B</th><th>C</th></tr>" + anchor_rows + "</table>" if bundle.anchors else "<p>No anchors in WAL.</p>"}

<div class="footer">
  <p>SWT3 AI Witness SDK v{html.escape(m.sdk_version)} | {label} | Patent pending</p>
</div>
</body>
</html>"""
