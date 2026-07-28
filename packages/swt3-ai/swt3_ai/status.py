"""SWT3 Status -- compliance posture at a glance.

Run with:
    swt3 status
    swt3 status --framework EU-AI-ACT
    swt3 status --coverage
    swt3 status --json
    swt3 status --compact
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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

# ── Profile-to-Framework Map ──

PROFILE_FRAMEWORK: Dict[str, Optional[str]] = {
    "eu-ai-act-high-risk": "EU-AI-ACT",
    "nist-ai-rmf": "NIST-AI-RMF",
    "defense-govcon": "NIST-800-53",
    "fintech-model-risk": "SR-11-7",
    "healthcare-clinical": "NIST-AI-RMF",
    "owasp-agentic-top10": "OWASP-AGENTIC-10",
    "content-platform": "EU-AI-ACT",
    "autonomous-systems": "EU-AI-ACT",
    "insurance-underwriting": "SR-11-7",
    "microsoft-foundry": "NIST-AI-RMF",
    "microsoft-agt": "NIST-AI-RMF",
    "telecom-compliance": "EU-AI-ACT",
    "granite-sovereign": "NIST-AI-RMF",
    "mythos-defense": "NIST-AI-RMF",
    "cost-conscious": "NIST-AI-RMF",
    "minimal": None,
}

# ── SDK Method Hints ──

PROCEDURE_HINTS: Dict[str, str] = {
    # Core witness methods (wrap-based)
    "AI-INF.1": "wrap",
    "AI-INF.2": "wrap",
    "AI-INF.3": "wrap",
    "AI-GRD.1": "wrap",
    "AI-GRD.2": "wrap",
    "AI-CHAIN.1": "wrap",
    "AI-VIO.1": "wrap",
    "AI-TOOL.1": "wrap_tool",
    "AI-TOOL.2": "witness_tool_permissions",
    "AI-ACC.1": "wrap_access",
    "AI-ID.1": "Witness(agent_id='...')",
    "AI-REV.1": "revoke",
    # Explainability
    "AI-EXPL.1": "witness_explanation",
    "AI-EXPL.2": "witness_explanation",
    # Data governance
    "AI-DATA.1": "witness_data_provenance",
    "AI-DATA.2": "witness_data_quality",
    "AI-DATA.3": "witness_data_provenance",
    "AI-DATA.4": "witness_training_pii_lifecycle",
    # Fairness
    "AI-FAIR.1": "witness_fairness",
    "AI-FAIR.2": "witness_fairness",
    "AI-FAIR.3": "witness_bias_assessment",
    # Human oversight
    "AI-HITL.1": "witness_human_oversight",
    "AI-HITL.2": "witness_human_oversight",
    "AI-HITL.3": "witness_reviewer_identity",
    # Model integrity
    "AI-MDL.1": "witness_model_weights",
    "AI-MDL.5": "witness_model_weights",
    "AI-MDL.6": "witness_adapter_stack",
    "AI-MDL.7": "witness_quantization",
    # RAG
    "AI-RAG.1": "witness_rag_context",
    "AI-RAG.2": "witness_rag_context",
    # Skills
    "AI-SKILL.1": "witness_skill_manifest",
    "AI-SKILL.2": "witness_memory_context",
    "AI-SKILL.3": "witness_reward_model",
    # Drift
    "AI-DRIFT.1": "witness_drift",
    "AI-DRIFT.2": "witness_drift",
    # Delegation + cost
    "AI-DEL.1": "witness_delegation_tree",
    "AI-COST.1": "witness_resource_consumption",
    # Security
    "AI-SEC.1": "witness_security_scan",
    "AI-SEC.2": "witness_security_scan",
    "AI-CYBER.1": "witness_cybersecurity",
    # Hardware + trust
    "AI-HW.1": "witness_hardware",
    "AI-HW.3": "witness_tpm_attestation",
    "AI-TRUST.1": "verify_trust",
    "AI-TRUST.2": "present_credential",
    # Audit + compliance
    "AI-AUDIT.1": "witness_audit_integrity",
    "AI-AUDIT.2": "witness_timestamp_attestation",
    "AI-CONSENT.1": "witness_consent",
    "AI-DPIA.1": "witness_dpia",
    "AI-SBOM.1": "witness_sbom",
    # Transparency + marking
    "AI-TRANS.1": "witness_transparency",
    "AI-MARK.1": "witness_content_mark",
    "AI-WATERMARK.1": "witness_watermark_verification",
    # Automation
    "AI-AUTO.1": "witness_automated_decision",
    "AI-AUTO.2": "witness_generation_depth",
    # Lifecycle + operational
    "AI-EMRG.1": "witness_emergency_override",
    "AI-ASSESS.1": "witness_assessment",
    "AI-LCM.1": "witness_lifecycle",
    "AI-INCIDENT.1": "witness_incident",
    "AI-PMM.1": "witness_post_market_monitoring",
    # Environment
    "AI-ENV.1": "witness_environment",
    "AI-ENV.2": "witness_energy_draw",
    # Governance
    "AI-BASE.1": "witness_agent_baseline",
    "AI-CHR.1": "witness_charter",
    "AI-DUALUSE.1": "witness_dual_use",
    "AI-SAFE.1": "witness_safe_state",
    "AI-REDTEAM.1": "witness_red_team",
    "AI-SUPPLY.1": "witness_supply_chain_risk",
    "AI-MULTI.1": "witness_multi_agent_delegation",
    "AI-ROBUST.1": "witness_robustness",
    "AI-PERF.1": "witness_performance",
    "AI-LIC.1": "witness_license_provenance",
    "AI-JUR.1": "witness_routing",
    "AI-FIN.1": "witness_transaction",
    # Engineering (safety-critical domains)
    "AI-ENG.1": "witness_design_provenance",
    "AI-ENG.2": "witness_simulation_validation",
    "AI-ENG.3": "witness_safety_review",
    "AI-ENG.4": "witness_material_compliance",
    "AI-ENG.5": "witness_design_chain",
    "AI-ENG.6": "witness_fabrication_release",
    # Meta-governance
    "AI-METAGOV.1": "witness_governance_config",
    # New procedures (Part 2)
    "AI-RISK.1": "witness_risk_assessment",
    "AI-GOV.1": "witness_governance_framework",
    "AI-GOV.2": "witness_governance_review",
    "AI-GOV.3": "witness_governance_escalation",
    "AI-GOV.4": "witness_governance_update",
    "AI-GOV.5": "witness_governance_accountability",
    "AI-GOV.6": "witness_risk_scope",
    "AI-IMPACT.1": "witness_impact_assessment",
    "AI-LOG.1": "witness_log_completeness",
    "AI-IR.1": "witness_incident_response",
}


# ── Data Types ──

@dataclass
class WalEntry:
    procedure_id: str
    count: int = 0
    last_ts_ms: int = 0
    last_verdict: str = ""
    last_fingerprint: str = ""


@dataclass
class ArticleRow:
    ref: str
    procedures: List[str]
    covered: List[str]
    missing: List[str]
    is_covered: bool = False
    last_ts_ms: int = 0
    verdict: str = ""


@dataclass
class StatusResult:
    agent_id: str = ""
    tenant_id: str = ""
    profile: str = ""
    framework_id: str = ""
    framework_name: str = ""
    total_articles: int = 0
    covered_articles: int = 0
    articles: List[ArticleRow] = field(default_factory=list)
    gaps: List[Dict[str, str]] = field(default_factory=list)
    anchors_total: int = 0
    last_anchor_ts: int = 0
    last_anchor_fp: str = ""
    extra_procedures: List[str] = field(default_factory=list)
    findings: List[Dict[str, str]] = field(default_factory=list)
    findings_count: int = 0


# ── WAL Scanner ──

def scan_wal(tenant_id: str, wal_dir: Optional[str] = None) -> Dict[str, WalEntry]:
    """Scan local WAL for procedure attestation summary."""
    if not wal_dir:
        wal_dir = os.path.join(tempfile.gettempdir(), "swt3-wal")

    safe_tenant = "".join(c if c.isalnum() or c in "-_" else "_" for c in tenant_id)
    wal_path = Path(wal_dir) / f"{safe_tenant}.wal"

    entries: Dict[str, WalEntry] = {}

    if not wal_path.is_file():
        return entries

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

                    ts = payload.get("timestamp_ms", 0)
                    verdict = payload.get("verdict", "")
                    fp = row.get("fingerprint", "")

                    if proc_id not in entries:
                        entries[proc_id] = WalEntry(procedure_id=proc_id)

                    e = entries[proc_id]
                    e.count += 1
                    if ts > e.last_ts_ms:
                        e.last_ts_ms = ts
                        e.last_verdict = verdict
                        e.last_fingerprint = fp
                except (json.JSONDecodeError, KeyError):
                    continue
    except OSError:
        pass

    return entries


# ── Config Loader (lightweight) ──

def _load_config_light() -> Optional[Dict]:
    """Load swt3.yaml without resolving secrets."""
    try:
        import yaml
    except ImportError:
        return None

    for name in ("swt3.yaml", ".swt3.yaml"):
        p = Path(name)
        if p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    raw = yaml.safe_load(f)
                if isinstance(raw, dict):
                    return raw
            except Exception:
                pass
    return None


# ── Procedure Name Lookup ──

def _proc_name(proc_id: str) -> str:
    """Get human name for a procedure ID."""
    try:
        from .procedures import PROCEDURE_CATALOG
        for p in PROCEDURE_CATALOG:
            if p["id"] == proc_id:
                return p["name"]
    except Exception:
        pass
    return proc_id


# ── Framework Metadata ──

def _framework_name(fw_id: str) -> str:
    """Get human name for a framework ID."""
    try:
        from .crosswalk import frameworks
        fw_meta = frameworks()
        if fw_id in fw_meta:
            return fw_meta[fw_id].get("name", fw_id)
    except Exception:
        pass
    names = {
        "EU-AI-ACT": "EU AI Act",
        "NIST-AI-RMF": "NIST AI RMF",
        "NIST-800-53": "NIST 800-53",
        "SR-11-7": "SR 11-7",
        "CMMC": "CMMC Level 2",
        "ISO-42001": "ISO 42001",
    }
    return names.get(fw_id, fw_id)


def _available_frameworks() -> List[str]:
    """List available framework IDs from bundled crosswalks."""
    try:
        from .crosswalk import frameworks
        return sorted(frameworks().keys())
    except Exception:
        return []


# ── Core Computation ──

def compute_status(
    tenant_id: str,
    agent_id: str = "",
    profile: str = "",
    framework_id: Optional[str] = None,
    wal_dir: Optional[str] = None,
) -> StatusResult:
    """Compute compliance status from local config + WAL."""
    result = StatusResult(
        agent_id=agent_id or "unknown",
        tenant_id=tenant_id,
        profile=profile or "none",
    )

    # Scan WAL
    wal_entries = scan_wal(tenant_id, wal_dir)
    witnessed_procs = set(wal_entries.keys())
    result.anchors_total = sum(e.count for e in wal_entries.values())

    if wal_entries:
        latest = max(wal_entries.values(), key=lambda e: e.last_ts_ms)
        result.last_anchor_ts = latest.last_ts_ms
        result.last_anchor_fp = latest.last_fingerprint

    # Determine framework
    if not framework_id and profile:
        framework_id = PROFILE_FRAMEWORK.get(profile)

    if not framework_id:
        # No framework: show raw WAL
        result.framework_id = ""
        result.framework_name = ""
        return result

    result.framework_id = framework_id
    result.framework_name = _framework_name(framework_id)

    # Resolve framework articles
    try:
        from .crosswalk import resolve_framework
        article_map = resolve_framework(framework_id)
    except Exception:
        article_map = {}

    if not article_map:
        return result

    # Build article rows
    all_framework_procs = set()
    for ref, procs in sorted(article_map.items()):
        covered = [p for p in procs if p in witnessed_procs]
        missing = [p for p in procs if p not in witnessed_procs]
        is_covered = len(missing) == 0

        last_ts = 0
        verdict = ""
        for p in covered:
            e = wal_entries[p]
            if e.last_ts_ms > last_ts:
                last_ts = e.last_ts_ms
                verdict = e.last_verdict

        row = ArticleRow(
            ref=ref,
            procedures=procs,
            covered=covered,
            missing=missing,
            is_covered=is_covered,
            last_ts_ms=last_ts,
            verdict=verdict,
        )
        result.articles.append(row)
        all_framework_procs.update(procs)

    result.total_articles = len(result.articles)
    result.covered_articles = sum(1 for a in result.articles if a.is_covered)

    # Gaps: unique missing procedures across all articles
    seen_gaps = set()
    for art in result.articles:
        for proc_id in art.missing:
            if proc_id not in seen_gaps:
                seen_gaps.add(proc_id)
                hint = PROCEDURE_HINTS.get(proc_id, "See docs")
                result.gaps.append({
                    "procedure_id": proc_id,
                    "name": _proc_name(proc_id),
                    "hint": f"witness.{hint}()" if not hint.startswith("Witness") and hint != "See docs" else hint,
                })

    # Extra procedures (in WAL but not in this framework)
    extra = witnessed_procs - all_framework_procs
    if extra:
        result.extra_procedures = sorted(extra)

    return result


# ── Time Formatting ──

def _time_ago(ts_ms: int) -> str:
    if not ts_ms:
        return ""
    now_ms = int(time.time() * 1000)
    diff_s = (now_ms - ts_ms) / 1000
    if diff_s < 0:
        return "just now"
    if diff_s < 60:
        return "just now"
    if diff_s < 3600:
        return f"{int(diff_s / 60)}m ago"
    if diff_s < 86400:
        return f"{int(diff_s / 3600)}h ago"
    if diff_s < 604800:
        return f"{int(diff_s / 86400)}d ago"
    return f"{int(diff_s / 604800)}w ago"


# ── Renderers ──

def render_status_brief(result: StatusResult) -> str:
    """Render brief status -- fits on one screen. Default output."""
    lines: List[str] = []

    # Header
    lines.append("")
    lines.append(f"  {BOLD}SWT3 Status{RESET}")
    lines.append(f"  {'─' * 55}")
    lines.append(f"  Agent: {CYAN}{result.agent_id}{RESET}    Tenant: {CYAN}{result.tenant_id}{RESET}")
    lines.append("")

    if not result.framework_id:
        if not result.anchors_total:
            lines.append(f"  {DIM}No anchors found. Get started:{RESET}")
            lines.append(f"    {WHITE}from swt3_ai import Witness{RESET}")
            lines.append(f"    {WHITE}witness = Witness(tenant_id='{result.tenant_id}'){RESET}")
            lines.append(f"    {WHITE}witness.wrap(prompt=..., response=..., model_id=..., provider=...){RESET}")
            lines.append(f"    {WHITE}witness.flush(){RESET}")
        else:
            lines.append(f"  {DIM}No framework target. Use --framework or set a profile.{RESET}")
            lines.append(f"  {result.anchors_total} anchors across {len(scan_wal(result.tenant_id))} procedures")
        lines.append("")
        return "\n".join(lines)

    # Progress bar
    pct = (result.covered_articles / result.total_articles * 100) if result.total_articles else 0
    bar_width = 20
    filled = int(bar_width * pct / 100)
    bar_chars = "\u2588" * filled + "\u2591" * (bar_width - filled)

    if pct >= 80:
        bar_color = GREEN
    elif pct >= 40:
        bar_color = AMBER
    else:
        bar_color = RED

    fw_display = result.framework_name or result.framework_id
    lines.append(f"  {fw_display:<28} {bar_color}{bar_chars}{RESET}  {pct:.0f}% ({result.covered_articles}/{result.total_articles})")
    lines.append("")

    # Covered articles (show what's working)
    covered_arts = [a for a in result.articles if a.is_covered]
    if covered_arts:
        lines.append(f"  {GREEN}Covered:{RESET}")
        for art in covered_arts:
            proc_display = art.covered[0] if art.covered else ""
            time_str = _time_ago(art.last_ts_ms)
            lines.append(
                f"    {GREEN}\u2713{RESET} {art.ref:<14} {WHITE}{proc_display}{RESET}  {DIM}{time_str}{RESET}"
            )
        lines.append("")

    # Next steps (top 5 actionable gaps -- only show ones with real SDK hints)
    actionable_gaps = [g for g in result.gaps if g["hint"] != "See docs"]
    if actionable_gaps:
        show_count = min(5, len(actionable_gaps))
        lines.append(f"  {BOLD}Next steps:{RESET}")
        for gap in actionable_gaps[:show_count]:
            lines.append(f"    {AMBER}{gap['procedure_id']:<12}{RESET} {DIM}{gap['hint']}{RESET}")
        remaining = len(result.gaps) - show_count
        if remaining > 0:
            lines.append(f"    {DIM}+{remaining} more (swt3 status --full){RESET}")
    elif result.gaps:
        lines.append(f"  {DIM}{len(result.gaps)} remaining articles need coverage (swt3 status --full){RESET}")

    # Findings (from API, if available)
    if result.findings_count > 0:
        lines.append("")
        lines.append(f"  {RED}! {result.findings_count} Open Assessment Finding{'s' if result.findings_count != 1 else ''}{RESET}")
        for f in result.findings[:5]:
            proc = f.get("procedure", "") or ""
            sev = f.get("severity", "")
            obs = f.get("observation", "")
            if len(obs) > 60:
                obs = obs[:57] + "..."
            lines.append(f"    {RED}#{f.get('id', '')}{RESET}  {WHITE}{proc:<12}{RESET} {AMBER}{sev:<8}{RESET} {DIM}{obs}{RESET}")
        if result.findings_count > 5:
            lines.append(f"    {DIM}+{result.findings_count - 5} more (resolve via audit portal){RESET}")

    # Footer
    lines.append("")
    lines.append(f"  {'─' * 55}")
    if result.last_anchor_fp:
        lines.append(f"  {DIM}Last: ...{result.last_anchor_fp}  ({_time_ago(result.last_anchor_ts)}){RESET}")
    lines.append(f"  {DIM}Prep: sovereign.tenova.io/guides/assessor-hot-sheet.html{RESET}")
    lines.append("")

    return "\n".join(lines)


def render_status_full(result: StatusResult) -> str:
    """Render full article-by-article breakdown."""
    lines: List[str] = []

    # Header
    lines.append("")
    lines.append(f"  {BOLD}SWT3 Status{RESET} {DIM}(full){RESET}")
    lines.append(f"  {'─' * 55}")
    lines.append(f"  Agent: {CYAN}{result.agent_id}{RESET}    Tenant: {CYAN}{result.tenant_id}{RESET}")
    if result.profile and result.profile != "none":
        lines.append(f"  Profile: {CYAN}{result.profile}{RESET}")
    lines.append("")

    if not result.framework_id:
        lines.append(f"  {DIM}No framework target.{RESET}")
        lines.append("")
        return "\n".join(lines)

    # Progress bar
    pct = (result.covered_articles / result.total_articles * 100) if result.total_articles else 0
    bar_width = 16
    filled = int(bar_width * pct / 100)
    bar_chars = "\u2588" * filled + "\u2591" * (bar_width - filled)

    if pct >= 80:
        bar_color = GREEN
    elif pct >= 40:
        bar_color = AMBER
    else:
        bar_color = RED

    fw_display = result.framework_name or result.framework_id
    lines.append(f"  {fw_display:<30} {bar_color}{bar_chars}{RESET}  {pct:.0f}% ({result.covered_articles}/{result.total_articles})")
    lines.append(f"  {'─' * 55}")

    # All articles -- covered first, then gaps
    covered_arts = [a for a in result.articles if a.is_covered]
    missing_arts = [a for a in result.articles if not a.is_covered]

    for art in covered_arts:
        icon = f"{GREEN}\u2713{RESET}"
        proc_display = art.covered[0] if art.covered else ""
        name = _proc_name(proc_display) if proc_display else ""
        time_str = _time_ago(art.last_ts_ms)
        lines.append(
            f"  {icon} {art.ref:<14} {WHITE}{proc_display:<12}{RESET} {name:<28} {DIM}{time_str}{RESET}"
        )

    if covered_arts and missing_arts:
        lines.append(f"  {'─' * 55}")

    for art in missing_arts:
        icon = f"{RED}\u2717{RESET}"
        proc_display = art.missing[0] if art.missing else art.procedures[0]
        name = _proc_name(proc_display)
        lines.append(
            f"  {icon} {art.ref:<14} {DIM}{proc_display:<12} {name}{RESET}"
        )

    # All gaps with hints
    if result.gaps:
        lines.append("")
        lines.append(f"  {BOLD}{len(result.gaps)} gap{'s' if len(result.gaps) != 1 else ''}:{RESET}")
        for gap in result.gaps:
            lines.append(f"    {AMBER}{gap['procedure_id']:<14}{RESET} {DIM}{gap['hint']}{RESET}")

    # Extra coverage
    if result.extra_procedures:
        lines.append(f"\n  {DIM}+{len(result.extra_procedures)} procedures beyond {result.framework_id} scope{RESET}")

    # Findings (full list in --full mode)
    if result.findings_count > 0:
        lines.append("")
        lines.append(f"  {RED}! {result.findings_count} Open Assessment Finding{'s' if result.findings_count != 1 else ''}{RESET}")
        for f in result.findings:
            proc = f.get("procedure", "") or ""
            sev = f.get("severity", "")
            obs = f.get("observation", "")
            lines.append(f"    {RED}#{f.get('id', '')}{RESET}  {WHITE}{proc:<12}{RESET} {AMBER}{sev:<8}{RESET} {DIM}{obs}{RESET}")

    # Footer
    lines.append("")
    lines.append(f"  {'─' * 55}")
    if result.last_anchor_fp:
        lines.append(f"  {DIM}Last: ...{result.last_anchor_fp}  ({_time_ago(result.last_anchor_ts)}){RESET}")
    lines.append(f"  {DIM}Prep: sovereign.tenova.io/guides/assessor-hot-sheet.html{RESET}")
    lines.append("")

    return "\n".join(lines)


def render_coverage(result: StatusResult) -> str:
    """Render visual procedure coverage bars by namespace."""
    lines: List[str] = []

    wal_entries = scan_wal(result.tenant_id)
    if not wal_entries:
        lines.append(f"\n  {DIM}No anchors found. Coverage requires witnessed procedures.{RESET}\n")
        return "\n".join(lines)

    # Group procedures by namespace
    ns_counts: Dict[str, Dict[str, int]] = {}
    for proc_id, entry in wal_entries.items():
        if "-" in proc_id:
            parts = proc_id.split("-")
            if len(parts) >= 2:
                ns = parts[1].split(".")[0]
            else:
                ns = "OTHER"
        else:
            ns = "OTHER"

        if ns not in ns_counts:
            ns_counts[ns] = {"witnessed": 0, "anchors": 0}
        ns_counts[ns]["witnessed"] += 1
        ns_counts[ns]["anchors"] += entry.count

    if not ns_counts:
        return ""

    lines.append("")
    lines.append(f"  {BOLD}Procedure Coverage{RESET}")
    lines.append(f"  {'─' * 50}")

    # Sort by namespace name, render two columns where possible
    sorted_ns = sorted(ns_counts.keys())
    bar_width = 10

    # Render in two-column layout
    rows: List[str] = []
    for ns in sorted_ns:
        data = ns_counts[ns]
        count = data["witnessed"]
        # Bar: use anchor count relative to max for visual weight
        # But show procedure count as the number
        filled = min(bar_width, max(1, count))
        bar = "\u2588" * filled + "\u2591" * (bar_width - filled)

        if count >= 5:
            color = GREEN
        elif count >= 2:
            color = AMBER
        else:
            color = WHITE

        rows.append(f"{ns:<6} {color}{bar}{RESET}  {count} proc{'s' if count != 1 else ''}")

    # Two-column layout
    mid = (len(rows) + 1) // 2
    left = rows[:mid]
    right = rows[mid:] if len(rows) > 1 else []

    for i in range(mid):
        l = left[i] if i < len(left) else ""
        r = right[i] if i < len(right) else ""
        if r:
            lines.append(f"  {l}     {r}")
        else:
            lines.append(f"  {l}")

    # Overall
    total_procs = sum(d["witnessed"] for d in ns_counts.values())
    total_anchors = sum(d["anchors"] for d in ns_counts.values())
    lines.append("")
    lines.append(f"  {DIM}Total: {total_procs} procedures across {len(ns_counts)} namespaces ({total_anchors} anchors){RESET}")
    lines.append(f"  {DIM}Details: https://sovereign.tenova.io/ai-witness{RESET}")
    lines.append("")

    return "\n".join(lines)


def render_status_json(result: StatusResult) -> str:
    """Render machine-readable JSON."""
    data = {
        "agent_id": result.agent_id,
        "tenant_id": result.tenant_id,
        "profile": result.profile,
        "framework": result.framework_id,
        "framework_name": result.framework_name,
        "coverage_pct": round(
            (result.covered_articles / result.total_articles * 100) if result.total_articles else 0, 1
        ),
        "covered": result.covered_articles,
        "total": result.total_articles,
        "articles": [
            {
                "ref": a.ref,
                "procedures": a.procedures,
                "covered": a.is_covered,
                "last_ts": a.last_ts_ms or None,
            }
            for a in result.articles
        ],
        "gaps": result.gaps,
        "anchors_total": result.anchors_total,
        "last_anchor_ts": result.last_anchor_ts or None,
        "findings": {
            "count": result.findings_count,
            "items": result.findings,
        },
    }
    return json.dumps(data, indent=2)


def render_status_compact(result: StatusResult) -> str:
    """Render one-line summary."""
    if not result.framework_id:
        return f"no-framework | {result.anchors_total} anchors"

    pct = (result.covered_articles / result.total_articles * 100) if result.total_articles else 0
    time_str = _time_ago(result.last_anchor_ts) if result.last_anchor_ts else "never"
    gap_ids = ",".join(g["procedure_id"] for g in result.gaps[:5])
    gap_str = f" | gaps: {gap_ids}" if gap_ids else ""

    findings_str = f" | findings:{result.findings_count}" if result.findings_count > 0 else ""
    return f"{result.framework_id} {pct:.0f}% ({result.covered_articles}/{result.total_articles}) | {result.anchors_total} anchors | last: {time_str}{gap_str}{findings_str}"


# ── CLI Entry Point ──

def _fetch_findings_from_api() -> Tuple[int, List[Dict[str, str]]]:
    """Fetch open findings from status API. Returns (count, items). Skips silently on failure."""
    api_key = os.environ.get("SWT3_API_KEY", "")
    endpoint = os.environ.get("SWT3_ENDPOINT", "https://sovereign.tenova.io")

    if not api_key:
        try:
            from .config import load_full_config
            loaded = load_full_config()
            kw = loaded.witness_kwargs
            api_key = kw.get("api_key", "")
            endpoint = kw.get("endpoint", endpoint)
        except Exception:
            pass

    if not api_key:
        return 0, []

    try:
        from urllib.request import Request, urlopen
        url = f"{endpoint.rstrip('/')}/api/v1/status?include=findings"
        req = Request(url, headers={"Authorization": f"Bearer {api_key}"})
        with urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        findings = data.get("findings", {})
        count = findings.get("open", 0)
        items = findings.get("items", [])
        return count, items
    except Exception:
        return 0, []


def _fetch_findings_threaded(result: StatusResult) -> None:
    """Fetch findings in a thread and attach to result."""
    count, items = _fetch_findings_from_api()
    result.findings_count = count
    result.findings = items


def handle_status(args: List[str]) -> None:
    """CLI handler for `swt3 status`."""
    # Parse flags
    use_json = "--json" in args
    use_compact = "--compact" in args
    use_full = "--full" in args
    use_coverage = "--coverage" in args
    wal_dir = None

    framework_override = None
    for i, arg in enumerate(args):
        if arg == "--framework" and i + 1 < len(args):
            framework_override = args[i + 1]
        elif arg == "--wal-path" and i + 1 < len(args):
            wal_dir = args[i + 1]

    # Load config
    config = _load_config_light()

    if config is None:
        if use_json:
            print(json.dumps({"error": "no config found"}))
        elif use_compact:
            print("no-config | Run: swt3 init")
        else:
            print(f"\n  {BOLD}SWT3 Status{RESET}")
            print(f"  {'─' * 55}")
            print(f"  {AMBER}No config found.{RESET}")
            print(f"  Run: {WHITE}swt3 init{RESET}")
            print(f"  Docs: {DIM}https://sovereign.tenova.io/docs/{RESET}\n")
        return

    tenant_id = config.get("tenant_id", "")
    agent_id = config.get("agent_id", "")
    profile = config.get("profile", "")

    if not tenant_id:
        print(f"\n  {RED}tenant_id not set in swt3.yaml{RESET}\n")
        return

    # Validate framework override
    if framework_override:
        available = _available_frameworks()
        if available and framework_override not in available:
            print(f"\n  {RED}Unknown framework: {framework_override}{RESET}")
            print(f"  Available:")
            for fw in available[:15]:
                print(f"    {fw}")
            if len(available) > 15:
                print(f"    ... and {len(available) - 15} more")
            print()
            sys.exit(1)

    # Compute (findings fetch in parallel)
    import threading
    findings_holder: List[Tuple[int, List[Dict[str, str]]]] = []

    def _bg_findings() -> None:
        findings_holder.append(_fetch_findings_from_api())

    findings_thread = threading.Thread(target=_bg_findings, daemon=True)
    findings_thread.start()

    result = compute_status(
        tenant_id=tenant_id,
        agent_id=agent_id,
        profile=profile,
        framework_id=framework_override,
        wal_dir=wal_dir,
    )

    # Wait for findings (max 2s, already started in parallel)
    findings_thread.join(timeout=2.0)
    if findings_holder:
        result.findings_count, result.findings = findings_holder[0]

    # Render
    if use_json:
        print(render_status_json(result))
    elif use_compact:
        print(render_status_compact(result))
    elif use_full:
        output = render_status_full(result)
        if use_coverage:
            output += render_coverage(result)
        print(output)
    else:
        output = render_status_brief(result)
        if use_coverage:
            output += render_coverage(result)
        print(output)
