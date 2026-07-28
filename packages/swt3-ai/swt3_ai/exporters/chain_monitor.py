"""SWT3 AI Witness SDK -- Exploit Chain Monitor Exporter.

Reads WAL entries and chain enforcer violation history to produce
forensic timelines for incident response and auditor review.

Usage:
    swt3 audit --format html
    swt3 audit --format json --wal-path /tmp/swt3-wal
"""

from __future__ import annotations

import html
import json
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class TimelineEntry:
    seq: int = 0
    timestamp: int = 0
    fingerprint: str = ""
    procedure_id: str = "unknown"
    tool_name: Optional[str] = None
    model_id: Optional[str] = None
    tokens: Optional[int] = None
    is_violation: bool = False
    violation_reason: Optional[str] = None


@dataclass
class AuditReportMetadata:
    generated_at: str = ""
    sdk_version: str = "0.6.1"
    tenant_id: str = "UNKNOWN"
    agent_id: str = "UNKNOWN"
    model_id: str = "UNKNOWN"
    clearing_level: int = 1
    entry_count: int = 0
    violation_count: int = 0
    merkle_root: Optional[str] = None


@dataclass
class AuditReport:
    metadata: AuditReportMetadata = field(default_factory=AuditReportMetadata)
    timeline: List[TimelineEntry] = field(default_factory=list)
    violations: List[Dict[str, Any]] = field(default_factory=list)


class ChainMonitorExporter:
    """Exploit Chain Monitor -- forensic timeline exporter."""

    def __init__(
        self,
        *,
        wal_dir: Optional[str] = None,
        tenant_id: str = "UNKNOWN",
        agent_id: str = "UNKNOWN",
        model_id: str = "UNKNOWN",
        clearing_level: int = 1,
        violations: Optional[list] = None,
        merkle_root: Optional[str] = None,
    ) -> None:
        self._wal_dir = wal_dir
        self._tenant_id = tenant_id
        self._agent_id = agent_id
        self._model_id = model_id
        self._clearing_level = clearing_level
        self._violations = violations or []
        self._merkle_root = merkle_root

    def _read_wal(self) -> list:
        wal_dir = Path(self._wal_dir or Path(tempfile.gettempdir()) / "swt3-wal")
        import re
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", self._tenant_id)
        wal_path = wal_dir / f"{safe}.wal"
        if not wal_path.is_file():
            return []
        entries = []
        for line in wal_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries

    def build_report(self) -> AuditReport:
        entries = self._read_wal()
        violations = [
            asdict(v) if hasattr(v, "__dataclass_fields__") else v
            for v in self._violations
        ]

        timeline: List[TimelineEntry] = []
        for e in entries:
            p = e.get("payload", {})
            is_chain = p.get("provider") == "chain-enforcer"
            tokens_val = (p.get("ai_input_tokens") or 0) + (p.get("ai_output_tokens") or 0)
            timeline.append(TimelineEntry(
                seq=e.get("seq", 0),
                timestamp=p.get("fingerprint_timestamp_ms", 0),
                fingerprint=e.get("fingerprint", ""),
                procedure_id=p.get("procedure_id", "unknown"),
                tool_name=p.get("ai_model_id") if not is_chain else p.get("ai_model_id"),
                model_id=None if is_chain else p.get("ai_model_id"),
                tokens=tokens_val if tokens_val > 0 else None,
                is_violation=is_chain,
                violation_reason="Chain policy violation" if is_chain else None,
            ))

        timeline.sort(key=lambda t: t.timestamp)

        violation_count = len(violations) + sum(1 for t in timeline if t.is_violation)

        return AuditReport(
            metadata=AuditReportMetadata(
                generated_at=datetime.now(timezone.utc).isoformat(),
                tenant_id=self._tenant_id,
                agent_id=self._agent_id,
                model_id=self._model_id,
                clearing_level=self._clearing_level,
                entry_count=len(timeline),
                violation_count=violation_count,
                merkle_root=self._merkle_root,
            ),
            timeline=timeline,
            violations=violations,
        )

    def export_json(self) -> str:
        report = self.build_report()
        return json.dumps({
            "metadata": asdict(report.metadata),
            "timeline": [asdict(t) for t in report.timeline],
            "violations": report.violations,
        }, indent=2)

    def export_html(self) -> str:
        report = self.build_report()
        m = report.metadata
        ts = m.generated_at.replace("T", " ")[:19]
        esc = html.escape

        timeline_rows = []
        for t in report.timeline:
            time_str = datetime.fromtimestamp(t.timestamp / 1000, tz=timezone.utc).strftime("%H:%M:%S.%f")[:12] if t.timestamp else "--"
            status = '<span style="color:#EF4444">VIOLATION</span>' if t.is_violation else '<span style="color:#4ADE80">OK</span>'
            tool = esc(t.tool_name) if t.tool_name else "--"
            tokens = str(t.tokens) if t.tokens else "--"
            reason = f'<br><span style="color:#EF4444;font-size:.75rem">{esc(t.violation_reason)}</span>' if t.violation_reason else ""
            timeline_rows.append(
                f"<tr><td>{t.seq}</td><td>{time_str}</td><td>{esc(t.procedure_id)}</td>"
                f"<td>{tool}</td><td style=\"font-family:monospace;font-size:.8rem\">{esc(t.fingerprint[:12])}</td>"
                f"<td>{tokens}</td><td>{status}{reason}</td></tr>"
            )

        violation_rows = []
        for v in report.violations:
            time_str = "--"
            violation_rows.append(
                f'<tr style="color:#EF4444"><td>{esc(str(v.get("rule", "")))}</td>'
                f'<td>{esc(str(v.get("tool_name", "")))}</td>'
                f'<td>{esc(str(v.get("reason", "")))}</td>'
                f'<td>{time_str}</td><td>{esc(str(v.get("action", "")))}</td></tr>'
            )

        merkle_section = f'<h2>Cryptographic Seal</h2><pre>Merkle Root: {esc(m.merkle_root)}</pre>' if m.merkle_root else ""

        timeline_html = (
            "<table>\n<tr><th>#</th><th>Time</th><th>Procedure</th><th>Tool</th>"
            "<th>Fingerprint</th><th>Tokens</th><th>Status</th></tr>\n"
            + "\n".join(timeline_rows) + "\n</table>"
        ) if timeline_rows else '<p style="color:#6B7280">No WAL entries found.</p>'

        violations_html = ""
        if violation_rows:
            violations_html = (
                '<hr class="sep">\n<h2>Chain Density Violations</h2>\n<table>\n'
                '<tr><th>Rule</th><th>Tool</th><th>Reason</th><th>Time</th><th>Action</th></tr>\n'
                + "\n".join(violation_rows) + "\n</table>"
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SWT3 Exploit Chain Monitor</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#070504;color:#E0D9D1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:2.5rem;line-height:1.6}}
.c{{max-width:960px;margin:0 auto}}
h1{{color:#E8A87C;font-size:1.5rem;margin-bottom:.25rem}}
h2{{color:#E8A87C;font-size:1.1rem;margin:1.5rem 0 .75rem}}
.meta{{color:#6B7280;font-size:.8rem;margin-bottom:1.5rem}}
.stats{{display:flex;gap:2rem;margin:1rem 0}}
.stat{{text-align:center}}
.stat .num{{font-size:2rem;font-weight:800}}
.stat .label{{font-size:.75rem;color:#6B7280;text-transform:uppercase;letter-spacing:.1em}}
.pass{{color:#4ADE80}}
.fail{{color:#EF4444}}
table{{width:100%;border-collapse:collapse;margin:.75rem 0;font-size:.85rem}}
th{{text-align:left;padding:.5rem .75rem;color:#E8A87C;border-bottom:1px solid #222;font-size:.7rem;text-transform:uppercase;letter-spacing:.1em}}
td{{padding:.5rem .75rem;border-bottom:1px solid #151312}}
pre{{background:#111;padding:1rem;border-radius:8px;overflow-x:auto;font-size:.8rem;color:#9CA3AF;margin:.75rem 0;border:1px solid #222}}
.sep{{border:none;border-top:1px solid #222;margin:1.5rem 0}}
.watermark{{color:#6B7280;font-size:.75rem;margin-top:2.5rem;padding-top:1.5rem;border-top:1px solid #222;text-align:center}}
.watermark .badge{{display:inline-block;padding:.25rem .75rem;border:1px solid #FBBF24;color:#FBBF24;border-radius:4px;font-size:.7rem;font-weight:600;letter-spacing:.05em;margin-bottom:.5rem}}
</style>
</head>
<body>
<div class="c">
<h1>SWT3 Exploit Chain Monitor</h1>
<p class="meta">Generated {ts} UTC | SWT3 SDK v{esc(m.sdk_version)} | Clearing Level {m.clearing_level}</p>

<div class="stats">
<div class="stat"><div class="num pass">{m.entry_count}</div><div class="label">Events</div></div>
<div class="stat"><div class="num {"fail" if m.violation_count > 0 else "pass"}">{m.violation_count}</div><div class="label">Violations</div></div>
</div>

<h2>Session</h2>
<table>
<tr><td style="color:#6B7280">Tenant</td><td>{esc(m.tenant_id)}</td></tr>
<tr><td style="color:#6B7280">Agent</td><td>{esc(m.agent_id)}</td></tr>
<tr><td style="color:#6B7280">Model</td><td>{esc(m.model_id)}</td></tr>
</table>

<h2>Timeline</h2>
{timeline_html}

{violations_html}

{merkle_section}

<div class="watermark">
<div class="badge">Self-Signed / Unnotarized</div>
<p>SWT3 Protocol | Patent Pending | Apache 2.0</p>
<p>TeNova: Defining the AI Accountability Standard.</p>
<p style="margin-top:.5rem">This report was generated locally. No data was transmitted to external services.</p>
</div>
</div>
</body>
</html>"""
