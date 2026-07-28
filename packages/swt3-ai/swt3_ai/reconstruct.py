"""SWT3 Reconstruct -- forensic timeline reconstruction.

Reconstructs a chronological narrative of AI system activity from
witness anchors. Every claim is backed by a verifiable fingerprint.

Run with:
    swt3 reconstruct --cycle CYCLE_ID
    swt3 reconstruct --agent AGENT_ID --last 1h
    swt3 reconstruct --fingerprint abc123def456
    swt3 reconstruct --chain LC-abc123def4567890
    swt3 reconstruct --last 1h
    swt3 reconstruct --json
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

# ── Colors ──

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
AMBER = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[37m"
BG_RED = "\033[41m"

if not sys.stdout.isatty():
    RESET = BOLD = DIM = RED = GREEN = AMBER = CYAN = WHITE = BG_RED = ""


# ── Procedure display names ──

PROC_LABELS: Dict[str, str] = {
    "AI-INF.1": "Inference",
    "AI-INF.2": "Latency Check",
    "AI-INF.3": "Volume Track",
    "AI-MDL.1": "Model Identity",
    "AI-MDL.2": "Model Version",
    "AI-MDL.5": "Weight Integrity",
    "AI-MDL.6": "Adapter Stack",
    "AI-MDL.7": "Quantization",
    "AI-GRD.1": "Guardrail Check",
    "AI-GRD.2": "Content Filter",
    "AI-GRD.3": "Gatekeeper Gate",
    "AI-SEC.1": "Adversarial Detection",
    "AI-SEC.2": "Input Validation",
    "AI-TOOL.1": "Tool Call",
    "AI-ID.1": "Agent Identity",
    "AI-ACC.1": "Resource Access",
    "AI-REV.1": "Revocation",
    "AI-DEL.1": "Delegation",
    "AI-COST.1": "Cost Witness",
    "AI-DRIFT.2": "Drift Detection",
    "AI-EMRG.1": "Emergency Override",
    "AI-ASSESS.1": "Assessment",
    "AI-CHAIN.1": "Chain Witness",
    "AI-FAIR.1": "Bias Detection",
    "AI-DATA.1": "Data Provenance",
    "AI-HITL.1": "Human Override",
    "AI-RAG.1": "RAG Provenance",
    "AI-RAG.2": "RAG Relevance",
    "AI-EXPL.1": "Explainability",
    "AI-GOV.1": "Governance Framework",
    "AI-RISK.1": "Risk Register",
    "AI-IMPACT.1": "Impact Assessment",
    "AI-LOG.1": "Logging Attestation",
    "AI-IR.1": "Incident Response",
    "AI-MULTI.1": "Multi-Agent Delegation",
}

# ── Agent colors (deterministic by hash) ──

AGENT_COLORS = [CYAN, AMBER, GREEN, "\033[35m", "\033[34m", "\033[91m"]


def _agent_color(agent_id: str) -> str:
    if not agent_id or not sys.stdout.isatty():
        return ""
    idx = sum(ord(c) for c in agent_id) % len(AGENT_COLORS)
    return AGENT_COLORS[idx]


def _fmt_time(iso: str) -> str:
    """Extract HH:MM:SS from ISO timestamp."""
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%H:%M:%S")
    except (ValueError, AttributeError):
        return iso[:8] if len(iso) >= 8 else iso


def _fmt_duration(ms: int) -> str:
    if ms < 1000:
        return f"{ms}ms"
    s = ms / 1000
    if s < 60:
        return f"{s:.1f}s"
    m = int(s // 60)
    remaining = int(s % 60)
    return f"{m}m {remaining}s"


def _fmt_cost(cents: int) -> str:
    if cents < 0:
        return "unknown"
    if cents == 0:
        return "$0.00"
    return f"${cents / 100:.2f}"


def _verdict_color(verdict: str) -> str:
    if verdict == "PASS":
        return GREEN
    if verdict == "FAIL":
        return RED
    return AMBER


# ── Data structures ──

@dataclass
class TimelineEntry:
    timestamp_server: str
    timestamp_client: int
    clock_skew_ms: int
    agent_id: Optional[str]
    procedure_id: str
    verdict: str
    fingerprint: str
    swt3_anchor: str
    clearing_level: int
    detail: Dict[str, Any]
    lifecycle_stage: Optional[str] = None
    lifecycle_chain_id: Optional[str] = None
    lifecycle_parent: Optional[str] = None
    is_drift: bool = False
    is_override: bool = False
    is_delegation: bool = False
    is_cost: bool = False
    is_violation: bool = False


@dataclass
class DelegationGrant:
    delegator: str
    scope_hash: str
    depth: int
    cascade: bool
    time_bound_minutes: int
    fingerprint: str
    witnessed_at: str


@dataclass
class Reconstruction:
    query_type: str
    query_id: str
    anchor_count: int = 0
    agent_count: int = 0
    agents: List[str] = field(default_factory=list)
    duration_ms: int = 0
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    total_tokens: int = 0
    total_cost_cents: int = 0
    has_failures: bool = False
    has_drift: bool = False
    has_override: bool = False
    cycle_complete: bool = False
    procedures_used: List[str] = field(default_factory=list)
    delegation_grants: List[DelegationGrant] = field(default_factory=list)
    timeline: List[TimelineEntry] = field(default_factory=list)
    source: str = "api"  # "local" (WAL) or "api" (server-verified)


# ── Local WAL reconstruction ──

def _reconstruct_from_wal(
    tenant_id: str,
    cycle_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    fingerprint: Optional[str] = None,
    last_seconds: Optional[int] = None,
) -> Reconstruction:
    """Reconstruct from local Write-Ahead Log."""
    wal_path = Path(f"/tmp/swt3-wal/{tenant_id}.wal")
    r = Reconstruction(
        query_type="cycle" if cycle_id else "agent" if agent_id else "fingerprint" if fingerprint else "range",
        query_id=cycle_id or agent_id or fingerprint or "local",
        source="local",
    )

    if not wal_path.exists():
        return r

    cutoff_ms = (time.time() - last_seconds) * 1000 if last_seconds else 0
    entries = []

    for line in wal_path.read_text().strip().split("\n"):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        ts_ms = entry.get("fingerprint_timestamp_ms", 0)
        if last_seconds and ts_ms < cutoff_ms:
            continue

        e_cycle = entry.get("cycle_id")
        e_agent = entry.get("agent_id")
        e_fp = entry.get("anchor_fingerprint", "")

        if cycle_id and e_cycle != cycle_id:
            continue
        if agent_id and e_agent != agent_id:
            continue
        if fingerprint and fingerprint not in e_fp:
            continue

        entries.append(entry)

    entries.sort(key=lambda e: e.get("fingerprint_timestamp_ms", 0))

    agents = set()
    procedures = set()

    for entry in entries:
        proc = entry.get("procedure_id", "")
        verdict = entry.get("verdict", "PASS")
        fp = entry.get("anchor_fingerprint", "")
        ts_ms = entry.get("fingerprint_timestamp_ms", 0)
        ag = entry.get("agent_id")
        cl = entry.get("clearing_level", 1)

        if ag:
            agents.add(ag)
        procedures.add(proc)

        if verdict == "FAIL":
            r.has_failures = True
        if proc == "AI-DRIFT.2":
            r.has_drift = True
        if proc == "AI-EMRG.1":
            r.has_override = True

        iso = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).isoformat()

        te = TimelineEntry(
            timestamp_server=iso,
            timestamp_client=ts_ms,
            clock_skew_ms=0,
            agent_id=ag,
            procedure_id=proc,
            verdict=verdict,
            fingerprint=fp,
            swt3_anchor=entry.get("swt3_anchor", ""),
            clearing_level=cl,
            detail={},
            is_drift=proc == "AI-DRIFT.2",
            is_override=proc == "AI-EMRG.1",
            is_delegation=proc == "AI-DEL.1",
            is_cost=proc == "AI-COST.1",
        )
        r.timeline.append(te)

    r.anchor_count = len(r.timeline)
    r.agents = sorted(agents)
    r.agent_count = len(agents)
    r.procedures_used = sorted(procedures)

    if r.timeline:
        r.start_time = r.timeline[0].timestamp_server
        r.end_time = r.timeline[-1].timestamp_server
        r.duration_ms = r.timeline[-1].timestamp_client - r.timeline[0].timestamp_client

    return r


# ── Remote API reconstruction ──

def _reconstruct_from_api(
    endpoint: str,
    api_key: str,
    cycle_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    fingerprint: Optional[str] = None,
    chain_id: Optional[str] = None,
    last_seconds: Optional[int] = None,
) -> Reconstruction:
    """Reconstruct via the server API."""
    params = []
    if cycle_id:
        params.append(f"cycle_id={cycle_id}")
    if agent_id:
        params.append(f"agent_id={agent_id}")
    if fingerprint:
        params.append(f"fingerprint={fingerprint}")
    if chain_id:
        params.append(f"chain_id={chain_id}")
    if last_seconds:
        from_time = datetime.now(timezone.utc) - timedelta(seconds=last_seconds)
        params.append(f"from={from_time.isoformat()}")

    url = f"{endpoint.rstrip('/')}/api/v1/reconstruct?{'&'.join(params)}"
    req = Request(url, headers={
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    })

    try:
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except (URLError, json.JSONDecodeError) as e:
        print(f"{RED}Error: Could not reach reconstruction API: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

    q = data.get("query", {})
    s = data.get("summary", {})
    r = Reconstruction(
        query_type=q.get("type", "unknown"),
        query_id=q.get("id", ""),
        anchor_count=s.get("anchor_count", 0),
        agent_count=s.get("agent_count", 0),
        agents=s.get("agents", []),
        duration_ms=s.get("duration_ms", 0),
        start_time=s.get("start_time"),
        end_time=s.get("end_time"),
        total_tokens=s.get("total_tokens", 0),
        total_cost_cents=s.get("total_cost_cents", 0),
        has_failures=s.get("has_failures", False),
        has_drift=s.get("has_drift", False),
        has_override=s.get("has_override", False),
        cycle_complete=s.get("cycle_complete", False),
        procedures_used=s.get("procedures_used", []),
    )

    dt = data.get("delegation_tree")
    if dt and dt.get("grants"):
        for g in dt["grants"]:
            r.delegation_grants.append(DelegationGrant(
                delegator=g.get("delegator", ""),
                scope_hash=g.get("scope_hash", ""),
                depth=g.get("depth", 0),
                cascade=g.get("cascade", False),
                time_bound_minutes=g.get("time_bound_minutes", 0),
                fingerprint=g.get("fingerprint", ""),
                witnessed_at=g.get("witnessed_at", ""),
            ))

    for t in data.get("timeline", []):
        r.timeline.append(TimelineEntry(
            timestamp_server=t.get("timestamp_server", ""),
            timestamp_client=t.get("timestamp_client", 0),
            clock_skew_ms=t.get("clock_skew_ms", 0),
            agent_id=t.get("agent_id"),
            procedure_id=t.get("procedure_id", ""),
            verdict=t.get("verdict", ""),
            fingerprint=t.get("fingerprint", ""),
            swt3_anchor=t.get("swt3_anchor", ""),
            clearing_level=t.get("clearing_level", 1),
            detail=t.get("detail", {}),
            lifecycle_stage=t.get("lifecycle_stage"),
            lifecycle_chain_id=t.get("lifecycle_chain_id"),
            lifecycle_parent=t.get("lifecycle_parent"),
            is_drift=t.get("is_drift", False),
            is_override=t.get("is_override", False),
            is_delegation=t.get("is_delegation", False),
            is_cost=t.get("is_cost", False),
            is_violation=t.get("is_violation", False),
        ))

    return r


# ── Render: text ──

def _render_text(r: Reconstruction) -> str:
    lines: List[str] = []

    # Header
    lines.append("")
    lines.append(f"  {BOLD}RECONSTRUCTION:{RESET} {r.query_id}")
    if r.start_time and r.end_time:
        lines.append(f"  {DIM}Duration: {_fmt_duration(r.duration_ms)} | "
                      f"Agents: {r.agent_count} | Anchors: {r.anchor_count} | "
                      f"Cost: {_fmt_cost(r.total_cost_cents)}{RESET}")
        if r.has_drift or r.has_override or r.has_failures:
            flags = []
            if r.has_failures:
                flags.append(f"{RED}FAILURES{RESET}")
            if r.has_drift:
                flags.append(f"{AMBER}DRIFT{RESET}")
            if r.has_override:
                flags.append(f"{RED}OVERRIDE{RESET}")
            lines.append(f"  {DIM}Flags:{RESET} {' | '.join(flags)}")
    lines.append("")

    # Delegation tree
    if r.delegation_grants:
        lines.append(f"  {BOLD}Delegation Tree:{RESET}")
        root = r.delegation_grants[0].delegator
        lines.append(f"    {_agent_color(root)}{root}{RESET} {DIM}(root){RESET}")
        for g in r.delegation_grants:
            cascade_str = f"{GREEN}cascade{RESET}" if g.cascade else f"{DIM}no-cascade{RESET}"
            time_str = f" {DIM}ttl={g.time_bound_minutes}m{RESET}" if g.time_bound_minutes else ""
            lines.append(f"    +-- {DIM}scope={g.scope_hash[:8]}...{RESET} "
                          f"depth={g.depth} {cascade_str}{time_str}")
        lines.append("")

    # Timeline
    for entry in r.timeline:
        ts = _fmt_time(entry.timestamp_server)
        proc = entry.procedure_id
        label = PROC_LABELS.get(proc, proc)
        vc = _verdict_color(entry.verdict)
        agent_str = ""
        if entry.agent_id:
            ac = _agent_color(entry.agent_id)
            short_agent = entry.agent_id[:20]
            agent_str = f"{ac}{short_agent:20s}{RESET} "
        else:
            agent_str = f"{DIM}{'':20s}{RESET} "

        verdict_str = f"{vc}{entry.verdict:4s}{RESET}"
        proc_str = f"{CYAN}{proc:14s}{RESET}"

        # Build detail string
        detail_parts: List[str] = []
        d = entry.detail
        if entry.is_delegation:
            scope = d.get("scope_hash", "")
            depth = d.get("cascade_revocation", "")
            detail_parts.append(f"scope={scope[:8] if scope else '?'}... depth={entry.detail.get('depth', '?')}")
            if d.get("cascade_revocation"):
                detail_parts.append("cascade")
        elif entry.is_cost:
            tok_in = d.get("tokens_in", "?")
            tok_out = d.get("tokens_out", "?")
            cost = d.get("cost_cents")
            detail_parts.append(f"{tok_in} in + {tok_out} out")
            if cost is not None and cost >= 0:
                detail_parts.append(f"${cost/100:.2f}")
        elif entry.is_drift:
            metric = d.get("drift_metric", "?")
            value = d.get("drift_value", "?")
            threshold = d.get("threshold", "?")
            consequence = d.get("consequence_category", "")
            detail_parts.append(f"{metric} {value} > {threshold}")
            if consequence:
                detail_parts.append(f"consequence: {consequence}")
        elif entry.is_override:
            trigger = d.get("override_trigger", "?")
            auth = d.get("authorization_level", "?")
            state = d.get("fallback_state", "?")
            detail_parts.append(f"trigger: {trigger} | auth: {auth} | state: {state}")
        else:
            model = d.get("model_id")
            if model:
                tok_in = d.get("tokens_in", "")
                tok_out = d.get("tokens_out", "")
                latency = d.get("latency_ms", "")
                parts = [model]
                if tok_in:
                    parts.append(f"{tok_in}+{tok_out} tok")
                if latency:
                    parts.append(f"{latency}ms")
                detail_parts.append(" ".join(parts))
            tool = d.get("tool_name")
            if tool:
                detail_parts.append(f"tool: {tool}")

        detail_str = f" {DIM}({', '.join(detail_parts)}){RESET}" if detail_parts else ""

        # Skew indicator
        skew_str = ""
        if entry.clock_skew_ms > 2000:
            skew_str = f" {AMBER}[skew {entry.clock_skew_ms}ms]{RESET}"

        # Main line
        line = f"  {DIM}{ts}{RESET}  {agent_str}{proc_str} {verdict_str}  {label}{detail_str}{skew_str}"
        lines.append(line)

        # Drift/override markers
        if entry.is_drift:
            lines.append(f"  {'':10s}{'':20s}{AMBER}{'':14s} ^^^^ DRIFT DETECTED{RESET}")
        if entry.is_override:
            lines.append(f"  {'':10s}{'':20s}{RED}{'':14s} ^^^^ OVERRIDE: cycle terminated{RESET}")
        if entry.is_violation:
            lines.append(f"  {'':10s}{'':20s}{RED}{'':14s} ^^^^ POLICY VIOLATION{RESET}")

    lines.append("")

    # Footer
    if not r.cycle_complete and r.anchor_count > 0:
        lines.append(f"  {AMBER}CYCLE INCOMPLETE{RESET} {DIM}-- last anchor {_fmt_time(r.end_time or '')}, "
                      f"no terminal event recorded{RESET}")
        lines.append("")

    lines.append(f"  {DIM}Verify any anchor: swt3 verify <fingerprint>{RESET}")
    lines.append("")

    return "\n".join(lines)


# ── Render: JSON ──

def _render_json(r: Reconstruction) -> str:
    return json.dumps({
        "query": {"type": r.query_type, "id": r.query_id},
        "summary": {
            "anchor_count": r.anchor_count,
            "agent_count": r.agent_count,
            "agents": r.agents,
            "duration_ms": r.duration_ms,
            "start_time": r.start_time,
            "end_time": r.end_time,
            "total_tokens": r.total_tokens,
            "total_cost_cents": r.total_cost_cents,
            "has_failures": r.has_failures,
            "has_drift": r.has_drift,
            "has_override": r.has_override,
            "cycle_complete": r.cycle_complete,
            "procedures_used": r.procedures_used,
        },
        "delegation_tree": {
            "root_agent": r.delegation_grants[0].delegator if r.delegation_grants else None,
            "grants": [
                {
                    "delegator": g.delegator,
                    "scope_hash": g.scope_hash,
                    "depth": g.depth,
                    "cascade": g.cascade,
                    "time_bound_minutes": g.time_bound_minutes,
                    "fingerprint": g.fingerprint,
                    "witnessed_at": g.witnessed_at,
                }
                for g in r.delegation_grants
            ],
        } if r.delegation_grants else None,
        "timeline": [
            {
                "timestamp_server": e.timestamp_server,
                "timestamp_client": e.timestamp_client,
                "clock_skew_ms": e.clock_skew_ms,
                "agent_id": e.agent_id,
                "procedure_id": e.procedure_id,
                "verdict": e.verdict,
                "fingerprint": e.fingerprint,
                "swt3_anchor": e.swt3_anchor,
                "clearing_level": e.clearing_level,
                "detail": e.detail,
                "is_drift": e.is_drift,
                "is_override": e.is_override,
                "is_delegation": e.is_delegation,
                "is_cost": e.is_cost,
                "is_violation": e.is_violation,
            }
            for e in r.timeline
        ],
    }, indent=2)


# ── Render: HTML ──

def _esc(s: str) -> str:
    """HTML-escape a string."""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


_CL_LABELS = {0: "L0 Analytics", 1: "L1 Standard", 2: "L2 Sensitive", 3: "L3 Classified"}
_CL_COLORS = {0: "#6b6b80", 1: "#00d4aa", 2: "#f0ad4e", 3: "#ff3b3b"}
_AGENT_HTML_COLORS = ["#22d3ee", "#fbbf24", "#34d399", "#a78bfa", "#60a5fa", "#fb7185"]


def _agent_html_color(agent_id: str) -> str:
    if not agent_id:
        return "#6b6b80"
    idx = sum(ord(c) for c in agent_id) % len(_AGENT_HTML_COLORS)
    return _AGENT_HTML_COLORS[idx]


def _render_html(r: Reconstruction) -> str:
    from hashlib import sha256

    parts: List[str] = []
    p = parts.append

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── CSS ──
    css = """
:root {
  --bg: #060611; --surface: #0d0d1f; --border: rgba(0,212,170,0.12);
  --accent: #00d4aa; --accent-dim: rgba(0,212,170,0.6);
  --fail: #ff3b3b; --fail-dim: rgba(255,59,59,0.15);
  --warn: #f0ad4e; --pass: #22c55e;
  --text: #e0e0e8; --text-muted: #6b6b80;
  --mono: 'SF Mono','Cascadia Code','Fira Code','Consolas',monospace;
  --sans: -apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:var(--sans); background:var(--bg); color:var(--text); line-height:1.5; padding:40px; max-width:1000px; margin:0 auto; }
h1 { font-size:22px; font-weight:700; color:var(--accent); letter-spacing:-0.5px; margin-bottom:4px; }
.subtitle { font-size:13px; color:var(--text-muted); font-family:var(--mono); }
.kpi-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:12px; margin:24px 0; }
.kpi { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:14px; text-align:center; }
.kpi-value { font-size:20px; font-weight:700; font-family:var(--mono); color:var(--accent); }
.kpi-label { font-size:9px; color:var(--text-muted); text-transform:uppercase; letter-spacing:1.5px; margin-top:2px; }
.section { margin:28px 0; }
.section-title { font-size:13px; font-weight:700; color:var(--accent); text-transform:uppercase; letter-spacing:1px; margin-bottom:12px; padding-bottom:6px; border-bottom:1px solid var(--border); }
.delegation { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:16px; font-family:var(--mono); font-size:12px; line-height:2; }
.del-root { color:var(--text); }
.del-grant { margin-left:20px; color:var(--text-muted); }
.timeline-row { display:grid; grid-template-columns:70px 1fr; gap:0; border-left:2px solid rgba(255,255,255,0.08); padding:0; position:relative; }
.timeline-row.drift { border-left-color:var(--warn); background:rgba(240,173,78,0.04); }
.timeline-row.override { border-left-color:var(--fail); background:rgba(255,59,59,0.04); }
.timeline-row.violation { background:rgba(255,59,59,0.03); }
.tl-time { font-family:var(--mono); font-size:11px; color:var(--text-muted); padding:10px 8px 10px 12px; }
.tl-body { padding:10px 12px 10px 0; border-bottom:1px solid rgba(255,255,255,0.04); }
.tl-main { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.tl-agent { font-size:11px; font-family:var(--mono); max-width:160px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.tl-proc { font-size:11px; font-family:var(--mono); color:var(--accent); font-weight:600; }
.tl-verdict { font-size:9px; font-weight:700; padding:2px 6px; border-radius:3px; letter-spacing:0.5px; }
.tl-verdict.pass { background:rgba(34,197,94,0.12); color:var(--pass); }
.tl-verdict.fail { background:rgba(255,59,59,0.12); color:var(--fail); }
.tl-label { font-size:11px; color:var(--text-muted); }
.tl-detail { font-size:10px; color:var(--text-muted); opacity:0.7; }
.tl-skew { font-size:9px; color:var(--warn); margin-left:auto; }
.tl-marker { font-size:10px; font-weight:600; margin-top:4px; padding:2px 0; }
.tl-marker.drift-marker { color:var(--warn); }
.tl-marker.override-marker { color:var(--fail); }
.tl-marker.violation-marker { color:var(--fail); }
.tl-expand { margin-top:8px; background:rgba(255,255,255,0.02); border:1px solid rgba(255,255,255,0.06); border-radius:6px; padding:10px 12px; font-size:10px; font-family:var(--mono); }
.tl-expand div { display:flex; gap:12px; padding:2px 0; }
.tl-expand .exp-label { color:var(--text-muted); min-width:100px; }
.tl-expand .exp-value { color:var(--text); word-break:break-all; }
.tl-expand a { color:var(--accent-dim); text-decoration:none; }
.tl-expand a:hover { color:var(--accent); }
.cl-badge { font-size:9px; font-family:var(--mono); padding:1px 5px; border-radius:3px; border:1px solid; }
.warning-box { background:rgba(240,173,78,0.08); border:1px solid rgba(240,173,78,0.3); border-radius:6px; padding:10px 14px; font-size:11px; color:var(--warn); margin-top:16px; }
.flag-badges { display:flex; gap:8px; margin:12px 0; }
.flag-badge { font-size:10px; font-weight:600; padding:3px 8px; border-radius:4px; }
.flag-badge.failures { background:var(--fail-dim); color:var(--fail); }
.flag-badge.drift-flag { background:rgba(240,173,78,0.15); color:var(--warn); }
.flag-badge.override-flag { background:var(--fail-dim); color:var(--fail); }
.legend { display:flex; flex-wrap:wrap; gap:12px; margin:12px 0; }
.legend-item { display:flex; align-items:center; gap:5px; font-size:11px; }
.legend-dot { width:8px; height:8px; border-radius:50%; }
.footer { margin-top:40px; padding-top:16px; border-top:1px solid var(--border); font-size:10px; color:var(--text-muted); font-family:var(--mono); text-align:center; }
.attestation-banner { background:rgba(240,173,78,0.08); border:1px solid rgba(240,173,78,0.3); border-radius:6px; padding:12px 16px; margin-bottom:24px; font-size:11px; line-height:1.6; }
.attestation-banner strong { color:var(--warn); }
.attestation-banner .attest-note { color:var(--text-muted); font-size:10px; margin-top:4px; }
.dot { width:10px; height:10px; border-radius:50%; position:absolute; left:-6px; top:14px; border:2px solid; }
.dot.pass-dot { background:rgba(34,197,94,0.2); border-color:rgba(34,197,94,0.5); }
.dot.fail-dot { background:rgba(255,59,59,0.2); border-color:rgba(255,59,59,0.5); }
.dot.drift-dot { background:rgba(240,173,78,0.2); border-color:rgba(240,173,78,0.5); }
.dot.override-dot { background:rgba(255,59,59,0.3); border-color:rgba(255,59,59,0.6); }
@media print {
  body { background:#fff; color:#111; padding:20px; }
  :root { --bg:#fff; --surface:#f8f8f8; --border:#ddd; --text:#111; --text-muted:#666; --accent:#007a5e; --accent-dim:#007a5e; --fail:#cc0000; --warn:#b87900; --pass:#1a7a3a; }
  .tl-expand { background:#f5f5f5; border-color:#ddd; }
  .timeline-row.drift { background:rgba(240,173,78,0.08); }
  .timeline-row.override { background:rgba(255,59,59,0.06); }
}
"""

    p("<!DOCTYPE html>")
    p(f'<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    p(f"<title>SWT3 Reconstruction: {_esc(r.query_id)}</title>")
    p(f"<style>{css}</style></head><body>")

    # ── Header ──
    p(f"<h1>Forensic Timeline Reconstruction</h1>")
    p(f'<div class="subtitle">{_esc(r.query_type)}: {_esc(r.query_id)}</div>')
    p(f'<div class="subtitle">Generated {generated}</div>')

    # ── Attestation Banner ──
    if r.source == "local":
        p('<div class="attestation-banner">')
        p('<strong>Self-Attested Export</strong> -- This report was generated from data stored on the developer\'s machine. ')
        p('These anchors have not been verified against the SWT3 compliance ledger. ')
        p('To verify individual anchors, visit <a href="https://sovereign.tenova.io/verify" style="color:var(--accent)">sovereign.tenova.io/verify</a>. ')
        p('For a verified audit-ready timeline, request an Audit Portal share link from the system owner.')
        p('</div>')
    else:
        p('<div class="attestation-banner">')
        p('<strong>Client-Generated Export</strong> -- Each anchor in this report was retrieved from the SWT3 compliance ledger and can be independently verified. ')
        p('This HTML document is a convenience export generated by the system owner -- it is not a signed audit artifact. ')
        p('For an interactive, auditor-authenticated timeline, request an <a href="https://sovereign.tenova.io" style="color:var(--accent)">Audit Portal</a> share link from the system owner.')
        p('</div>')

    # ── Flags ──
    if r.has_failures or r.has_drift or r.has_override:
        p('<div class="flag-badges">')
        if r.has_failures:
            p('<span class="flag-badge failures">FAILURES</span>')
        if r.has_drift:
            p('<span class="flag-badge drift-flag">DRIFT</span>')
        if r.has_override:
            p('<span class="flag-badge override-flag">OVERRIDE</span>')
        p("</div>")

    # ── KPIs ──
    status_text = "OVERRIDE" if r.has_override else "DRIFT" if r.has_drift else "COMPLETE" if r.cycle_complete else "INCOMPLETE"
    status_color = "var(--fail)" if r.has_override else "var(--warn)" if r.has_drift else "var(--pass)" if r.cycle_complete else "var(--warn)"

    p('<div class="kpi-grid">')
    p(f'<div class="kpi"><div class="kpi-value">{_fmt_duration(r.duration_ms)}</div><div class="kpi-label">Duration</div></div>')
    p(f'<div class="kpi"><div class="kpi-value">{r.anchor_count}</div><div class="kpi-label">Anchors</div></div>')
    p(f'<div class="kpi"><div class="kpi-value">{r.agent_count}</div><div class="kpi-label">Agents</div></div>')
    p(f'<div class="kpi"><div class="kpi-value">{r.total_tokens:,}</div><div class="kpi-label">Tokens</div></div>')
    p(f'<div class="kpi"><div class="kpi-value">{_fmt_cost(r.total_cost_cents)}</div><div class="kpi-label">Cost</div></div>')
    p(f'<div class="kpi"><div class="kpi-value" style="color:{status_color}">{status_text}</div><div class="kpi-label">Status</div></div>')
    p("</div>")

    # ── Agent Legend ──
    if r.agents:
        p('<div class="legend">')
        for ag in r.agents:
            color = _agent_html_color(ag)
            short = ag[:24] + "..." if len(ag) > 24 else ag
            p(f'<span class="legend-item"><span class="legend-dot" style="background:{color}"></span><span style="color:{color}">{_esc(short)}</span></span>')
        p("</div>")

    # ── Delegation Tree ──
    if r.delegation_grants:
        p('<div class="section">')
        p('<div class="section-title">Delegation Tree</div>')
        p('<div class="delegation">')
        root = r.delegation_grants[0].delegator
        root_color = _agent_html_color(root)
        p(f'<div class="del-root"><span style="color:{root_color}">{_esc(root)}</span> <span style="color:var(--text-muted)">(root)</span></div>')
        for g in r.delegation_grants:
            cas = '<span style="color:var(--pass)">cascade</span>' if g.cascade else '<span style="color:var(--text-muted)">no-cascade</span>'
            ttl = f' <span style="color:var(--text-muted)">ttl={g.time_bound_minutes}m</span>' if g.time_bound_minutes else ""
            p(f'<div class="del-grant">+-- scope={_esc(g.scope_hash[:8])}... depth={g.depth} {cas}{ttl}</div>')
        p("</div></div>")

    # ── Timeline ──
    p('<div class="section">')
    p('<div class="section-title">Timeline</div>')

    for entry in r.timeline:
        ts = _fmt_time(entry.timestamp_server)
        proc = entry.procedure_id
        label = PROC_LABELS.get(proc, proc)
        d = entry.detail

        row_class = "timeline-row"
        if entry.is_override:
            row_class += " override"
        elif entry.is_drift:
            row_class += " drift"
        elif entry.is_violation:
            row_class += " violation"

        dot_class = "dot"
        if entry.verdict == "PASS":
            dot_class += " pass-dot"
        elif entry.verdict == "FAIL":
            dot_class += " fail-dot"
        if entry.is_drift:
            dot_class += " drift-dot"
        if entry.is_override:
            dot_class += " override-dot"

        verdict_class = "pass" if entry.verdict == "PASS" else "fail" if entry.verdict == "FAIL" else ""

        # Build detail string
        detail_parts: List[str] = []
        if entry.is_delegation:
            scope = d.get("scope_hash", "")
            detail_parts.append(f"scope={_esc(scope[:8] if scope else '?')}... depth={d.get('depth', '?')}")
            if d.get("cascade_revocation"):
                detail_parts.append("cascade")
        elif entry.is_cost:
            detail_parts.append(f"{d.get('tokens_in', '?')}+{d.get('tokens_out', '?')} tok")
            cost = d.get("cost_cents")
            if cost is not None and cost >= 0:
                detail_parts.append(f"${cost/100:.2f}")
        elif entry.is_drift:
            detail_parts.append(f"{d.get('drift_metric', '?')} {d.get('drift_value', '?')} &gt; {d.get('threshold', '?')}")
            if d.get("consequence_category"):
                detail_parts.append(f"consequence: {_esc(str(d['consequence_category']))}")
        elif entry.is_override:
            detail_parts.append(f"trigger: {_esc(str(d.get('override_trigger', '?')))}")
            detail_parts.append(f"auth: {_esc(str(d.get('authorization_level', '?')))}")
            detail_parts.append(f"state: {_esc(str(d.get('fallback_state', '?')))}")
        else:
            model = d.get("model_id")
            if model:
                mp = [_esc(str(model))]
                if d.get("tokens_in"):
                    mp.append(f"{d['tokens_in']}+{d.get('tokens_out', 0)} tok")
                if d.get("latency_ms"):
                    mp.append(f"{d['latency_ms']}ms")
                detail_parts.append(" ".join(mp))
            tool = d.get("tool_name")
            if tool:
                detail_parts.append(f"tool: {_esc(str(tool))}")

        detail_str = f'<span class="tl-detail">({", ".join(detail_parts)})</span>' if detail_parts else ""
        skew_str = f'<span class="tl-skew">[skew {entry.clock_skew_ms}ms]</span>' if entry.clock_skew_ms > 2000 else ""

        agent_str = ""
        if entry.agent_id:
            ac = _agent_html_color(entry.agent_id)
            short_ag = entry.agent_id[:20]
            agent_str = f'<span class="tl-agent" style="color:{ac}">{_esc(short_ag)}</span>'

        cl = entry.clearing_level
        cl_color = _CL_COLORS.get(cl, "#6b6b80")
        cl_label = _CL_LABELS.get(cl, f"L{cl}")

        p(f'<div class="{row_class}">')
        p(f'  <div class="{dot_class}"></div>')
        p(f'  <div class="tl-time">{_esc(ts)}</div>')
        p(f'  <div class="tl-body">')
        p(f'    <div class="tl-main">')
        p(f'      {agent_str}')
        p(f'      <span class="tl-proc">{_esc(proc)}</span>')
        p(f'      <span class="tl-verdict {verdict_class}">{_esc(entry.verdict)}</span>')
        p(f'      <span class="tl-label">{_esc(label)}</span>')
        p(f'      {detail_str}')
        p(f'      <span class="cl-badge" style="color:{cl_color};border-color:{cl_color}">{cl_label}</span>')
        p(f'      {skew_str}')
        p(f'    </div>')

        # Markers
        if entry.is_drift:
            p('    <div class="tl-marker drift-marker">&#9650; DRIFT DETECTED</div>')
        if entry.is_override:
            p('    <div class="tl-marker override-marker">&#9650; OVERRIDE: cycle terminated</div>')
        if entry.is_violation:
            p('    <div class="tl-marker violation-marker">&#9650; POLICY VIOLATION</div>')

        # Expanded detail (always visible in HTML export)
        p('    <div class="tl-expand">')
        p(f'      <div><span class="exp-label">Anchor:</span><span class="exp-value">{_esc(entry.swt3_anchor)}</span></div>')
        p(f'      <div><span class="exp-label">Fingerprint:</span><span class="exp-value" style="color:var(--accent)">{_esc(entry.fingerprint)}</span></div>')
        p(f'      <div><span class="exp-label">Clearing:</span><span class="exp-value">{cl_label}</span></div>')
        if entry.lifecycle_stage:
            p(f'      <div><span class="exp-label">Lifecycle:</span><span class="exp-value">{_esc(entry.lifecycle_stage)}</span></div>')
        if entry.detail:
            for k, v in entry.detail.items():
                p(f'      <div><span class="exp-label">{_esc(k)}:</span><span class="exp-value">{_esc(str(v))}</span></div>')
        verify_url = f"https://sovereign.tenova.io/verify?fp={entry.fingerprint}"
        p(f'      <div><a href="{verify_url}" target="_blank" rel="noopener">Verify independently &#8594;</a></div>')
        p("    </div>")

        p("  </div>")
        p("</div>")

    # ── Incomplete cycle warning ──
    if not r.cycle_complete and r.anchor_count > 0:
        p(f'<div class="warning-box">CYCLE INCOMPLETE -- last anchor {_fmt_time(r.end_time or "")}, no terminal event recorded</div>')

    p("</div>")  # end section

    # ── Footer ──
    body_for_hash = "\n".join(parts)
    content_hash = sha256(body_for_hash.encode()).hexdigest()[:12]

    source_label = "Local WAL (self-attested)" if r.source == "local" else "Ledger API (server-verified anchors)"
    p('<div class="footer">')
    p(f'{r.anchor_count} anchors, {len(r.procedures_used)} procedures<br>')
    p(f'Data source: {source_label}<br>')
    p(f'Content hash: {content_hash}<br>')
    p(f'SWT3 Sovereign Engine -- sovereign.tenova.io')
    p("</div>")

    p("</body></html>")
    return "\n".join(parts)


# ── Parse duration shorthand ──

def _parse_duration(s: str) -> int:
    """Parse '1h', '30m', '2d' into seconds."""
    s = s.strip().lower()
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("d"):
        return int(s[:-1]) * 86400
    if s.endswith("s"):
        return int(s[:-1])
    return int(s)


# ── CLI entry point ──

def _get_flag(args: List[str], flag: str) -> Optional[str]:
    for i, a in enumerate(args):
        if a == flag and i + 1 < len(args):
            return args[i + 1]
    return None


def handle_reconstruct(args: List[str]) -> None:
    """Handle `swt3 reconstruct` command."""
    cycle_id = _get_flag(args, "--cycle")
    agent_id = _get_flag(args, "--agent")
    fingerprint = _get_flag(args, "--fingerprint")
    chain_id = _get_flag(args, "--chain")
    last_str = _get_flag(args, "--last")
    output_json = "--json" in args
    output_html = "--html" in args
    output_path = _get_flag(args, "--output")
    local_mode = "--local" in args

    last_seconds = _parse_duration(last_str) if last_str else None

    if not any([cycle_id, agent_id, fingerprint, chain_id, last_str]):
        print(f"{RED}Error: Specify --cycle, --agent, --fingerprint, --chain, or --last{RESET}")
        print(f"{DIM}Examples:{RESET}")
        print(f"  swt3 reconstruct --cycle cycle-2026-07-21-001")
        print(f"  swt3 reconstruct --agent orchestrator-main --last 1h")
        print(f"  swt3 reconstruct --fingerprint a1b2c3d4e5f6")
        print(f"  swt3 reconstruct --chain LC-abc123def4567890")
        print(f"  swt3 reconstruct --last 30m")
        print(f"  swt3 reconstruct --cycle CYCLE_ID --html")
        print(f"  swt3 reconstruct --cycle CYCLE_ID --html --output report.html")
        sys.exit(1)

    # Resolve config
    endpoint = os.environ.get("SWT3_ENDPOINT", "")
    api_key = os.environ.get("SWT3_API_KEY", "")
    tenant_id = os.environ.get("SWT3_TENANT_ID", "")

    # Try loading from swt3.yaml
    config_path = Path("swt3.yaml")
    if config_path.exists():
        try:
            import importlib
            yaml_mod = importlib.import_module("yaml")
            with open(config_path) as f:
                cfg = yaml_mod.safe_load(f)
            if cfg:
                endpoint = endpoint or cfg.get("endpoint", "")
                api_key = api_key or cfg.get("api_key", "")
                tenant_id = tenant_id or cfg.get("tenant_id", "")
        except (ImportError, Exception):
            pass

    # Choose data source
    if local_mode or (not endpoint and not api_key):
        if not tenant_id:
            print(f"{RED}Error: SWT3_TENANT_ID or swt3.yaml tenant_id required for local mode{RESET}")
            sys.exit(1)
        r = _reconstruct_from_wal(tenant_id, cycle_id, agent_id, fingerprint, last_seconds)
    else:
        if not endpoint or not api_key:
            print(f"{RED}Error: SWT3_ENDPOINT and SWT3_API_KEY required (or use --local){RESET}")
            sys.exit(1)
        r = _reconstruct_from_api(endpoint, api_key, cycle_id, agent_id, fingerprint, chain_id, last_seconds)

    # Render output
    if r.anchor_count == 0:
        print(f"\n  {DIM}No anchors found for query: {r.query_id}{RESET}\n")
        sys.exit(0)

    if output_html:
        html = _render_html(r)
        if output_path:
            Path(output_path).write_text(html, encoding="utf-8")
            print(f"  {GREEN}HTML written to {output_path}{RESET}")
        else:
            default_name = f"reconstruct-{r.query_id.replace('/', '-')}-{int(time.time())}.html"
            Path(default_name).write_text(html, encoding="utf-8")
            print(f"  {GREEN}HTML written to {default_name}{RESET}")
    elif output_json:
        print(_render_json(r))
    else:
        print(_render_text(r))
