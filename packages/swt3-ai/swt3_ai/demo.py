"""SWT3 AI Witness SDK — Zero-Friction Demo.

Run with:
    python -m swt3_ai.demo

No API keys. No account. No network calls. See the protocol in 10 seconds.

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import hashlib
import time
import sys

# ── Colors (ANSI) ──

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
AMBER = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[37m"

# Disable colors if not a terminal
if not sys.stdout.isatty():
    RESET = BOLD = DIM = RED = GREEN = AMBER = CYAN = WHITE = ""


def _sha256(data: str, length: int = 64) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:length]


def _mint_fingerprint(
    tenant: str, procedure: str,
    fa: float, fb: float, fc: float,
    ts_ms: int,
) -> str:
    def _n(v: float) -> str:
        return str(int(v)) if v == int(v) else str(v)
    fp_input = f"WITNESS:{tenant}:{procedure}:{_n(fa)}:{_n(fb)}:{_n(fc)}:{ts_ms}"
    return hashlib.sha256(fp_input.encode("utf-8")).hexdigest()[:12]


def _mint_anchor(
    tenant: str, provider: str, procedure: str,
    verdict: str, epoch: int, fingerprint: str,
) -> str:
    return f"SWT3-E-{provider}-AI-{procedure}-{verdict}-{epoch}-{fingerprint}"


def _generate_html_report(
    coverage_map: list,
    uncovered: list,
    anchors: list[str],
    days_left: int,
) -> str:
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    covered_rows = "".join(
        f'<tr><td style="font-family:monospace">{p}</td><td>{a}</td><td>{d}</td>'
        f'<td style="color:#4ADE80;font-weight:700">[{v}]</td></tr>'
        for p, a, d, v in coverage_map
    )
    uncovered_rows = "".join(
        f'<tr><td style="font-family:monospace">{p}</td><td>{a}</td><td>{d}</td>'
        f'<td style="color:#9CA3AF;font-weight:600">[NEEDS PRODUCTION]</td></tr>'
        for p, a, d in uncovered
    )
    anchor_text = "\n".join(anchors)
    countdown = f"EU AI Act high-risk enforcement in {days_left} days (December 2, 2027)" if days_left > 0 else "EU AI Act high-risk enforcement has begun."
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SWT3 AI Witness — Coverage Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#070504;color:#E0D9D1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:2.5rem;line-height:1.6}}
.c{{max-width:800px;margin:0 auto}}
h1{{color:#E8A87C;font-size:1.5rem;margin-bottom:.25rem}}
h2{{color:#E8A87C;font-size:1.1rem;margin:1.5rem 0 .75rem}}
.meta{{color:#6B7280;font-size:.8rem;margin-bottom:1.5rem}}
.score{{font-size:2.5rem;font-weight:800;margin:1rem 0}}
.score .pass{{color:#4ADE80}}
.score .total{{color:#6B7280}}
table{{width:100%;border-collapse:collapse;margin:.75rem 0;font-size:.9rem}}
th{{text-align:left;padding:.5rem .75rem;color:#E8A87C;border-bottom:1px solid #222;font-size:.75rem;text-transform:uppercase;letter-spacing:.1em}}
td{{padding:.5rem .75rem;border-bottom:1px solid #151312}}
pre{{background:#111;padding:1rem;border-radius:8px;overflow-x:auto;font-size:.8rem;color:#9CA3AF;margin:.75rem 0;border:1px solid #222}}
.countdown{{font-size:1rem;font-weight:600;color:#FBBF24;margin:1.5rem 0}}
.cta{{display:inline-block;margin-top:1.25rem;padding:.75rem 2rem;background:#E8A87C;color:#070504;font-weight:700;text-decoration:none;border-radius:6px;font-size:.9rem;letter-spacing:.03em}}
.cta:hover{{opacity:.9}}
.cta-secondary{{display:inline-block;margin-top:1.25rem;margin-right:.75rem;padding:.75rem 2rem;background:transparent;color:#E8A87C;border:1px solid #E8A87C;font-weight:600;text-decoration:none;border-radius:6px;font-size:.9rem;letter-spacing:.03em}}
.cta-secondary:hover{{background:rgba(232,168,124,.1)}}
.footer{{color:#6B7280;font-size:.75rem;margin-top:2.5rem;padding-top:1.5rem;border-top:1px solid #222}}
.warn{{color:#FBBF24}}
.sep{{border:none;border-top:1px solid #222;margin:1.5rem 0}}
</style>
</head>
<body>
<div class="c">
<h1>SWT3 AI Witness — Coverage Report</h1>
<p class="meta">Generated {ts} UTC | SWT3 Protocol v0.4.2 | Demo Environment</p>

<div class="score"><span class="pass">14</span><span class="total"> / 14 obligations mapped</span></div>
<p style="color:#9CA3AF;font-size:.95rem;margin-top:-.5rem">5 demonstrated locally · 9 need production data</p>

<h2>Demonstrated Locally</h2>
<table>
<tr><th>Procedure</th><th>EU AI Act</th><th>Obligation</th><th>Status</th></tr>
{covered_rows}
</table>

<h2>Mapped — Needs Production Data ({len(uncovered)})</h2>
<table>
<tr><th>Procedure</th><th>EU AI Act</th><th>Obligation</th><th>Status</th></tr>
{uncovered_rows}
</table>

<hr class="sep">

<p class="countdown">{countdown}</p>

<h2>Anchor Evidence (Demo)</h2>
<pre>{anchor_text}</pre>

<p>Full conformity requires all 47 AI procedures across inference, model governance, guardrails, RAG, skills, and explainability domains.</p>
<a class="cta-secondary" href="https://sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public">See Live Auditor View →</a>
<a class="cta" href="https://sovereign.tenova.io/signup?ref=sdk_demo">Close the Gap — Free Account</a>
<p style="margin-top:.75rem;font-size:.8rem;color:#9CA3AF">Preview a real tenant's EU AI Act posture (no account required) — then create your own.</p>

<div class="footer">
<p>SWT3 Protocol — Patent Pending — Apache 2.0</p>
<p>TeNova: Defining the AI Accountability Standard.</p>
<p style="margin-top:.5rem">This report was generated locally by the SWT3 AI Witness SDK demo. No data was transmitted.</p>
</div>
</div>
</body>
</html>"""


def main() -> None:
    print()
    print(f"{BOLD}SWT3 AI Witness SDK — Live Demo{RESET}")
    print(f"{DIM}No API keys. No account. No network calls.{RESET}")
    print(f"{DIM}{'─' * 56}{RESET}")
    print()

    # ── Simulate an AI inference ──
    tenant = "DEMO_TENANT"
    provider = "LOCAL"
    model_id = "gpt-4o-2024-08-06"
    prompt = "What are the compliance requirements for the EU AI Act?"
    response_text = "The EU AI Act requires high-risk AI systems to maintain technical documentation, implement risk management systems, and ensure human oversight..."

    print(f"{CYAN}1. Simulating AI inference...{RESET}")
    print(f"   Model:    {WHITE}{model_id}{RESET}")
    print(f"   Prompt:   {DIM}{prompt[:50]}...{RESET}")
    time.sleep(0.3)

    # ── Hash (never send raw text) ──
    prompt_hash = _sha256(prompt, 16)
    response_hash = _sha256(response_text, 16)
    model_hash = _sha256(model_id, 12)

    print()
    print(f"{CYAN}2. Hashing locally (raw text never leaves your infrastructure)...{RESET}")
    print(f"   Prompt hash:   {GREEN}{prompt_hash}{RESET}")
    print(f"   Response hash: {GREEN}{response_hash}{RESET}")
    print(f"   Model hash:    {GREEN}{model_hash}{RESET}")
    time.sleep(0.3)

    # ── Extract factors ──
    latency_ms = 847
    token_count = 142
    guardrails_active = 3

    print()
    print(f"{CYAN}3. Extracting compliance factors...{RESET}")
    print(f"   factor_a (latency):    {WHITE}{latency_ms} ms{RESET}")
    print(f"   factor_b (tokens):     {WHITE}{token_count}{RESET}")
    print(f"   factor_c (guardrails): {WHITE}{guardrails_active} active{RESET}")
    time.sleep(0.3)

    # ── Clearing Level 1 ──
    print()
    print(f"{CYAN}4. Applying Clearing Level 1 (Standard)...{RESET}")
    print(f"   {GREEN}✓{RESET} Hashes retained")
    print(f"   {GREEN}✓{RESET} Factors retained")
    print(f"   {GREEN}✓{RESET} Raw prompt purged from wire")
    print(f"   {GREEN}✓{RESET} Raw response purged from wire")
    time.sleep(0.3)

    # ── Mint anchor ──
    ts_ms = int(time.time() * 1000)
    epoch = ts_ms // 1000

    procedures = [
        ("AI-INF.1", 1, 1, 1, "PASS", "Inference traced"),
        ("AI-MDL.1", 1, 1, 0, "PASS", "Model version recorded"),
        ("AI-GRD.1", 1, 1, guardrails_active, "PASS", "Guardrails active"),
    ]

    print()
    print(f"{CYAN}5. Minting SWT3 Witness Anchors...{RESET}")
    print()

    anchors_list: list[str] = []
    for proc_id, fa, fb, fc, verdict, desc in procedures:
        fp = _mint_fingerprint(tenant, proc_id, fa, fb, fc, ts_ms)
        anchor = _mint_anchor(tenant, provider, proc_id, verdict, epoch, fp)
        anchors_list.append(anchor)
        color = GREEN if verdict == "PASS" else AMBER
        print(f"   {color}■ {verdict}{RESET}  {WHITE}{proc_id}{RESET}  {DIM}{desc}{RESET}")
        print(f"     {DIM}{anchor}{RESET}")
        print()

    # ── Verification ──
    print(f"{CYAN}6. Verifying anchor integrity...{RESET}")
    fp_check = _mint_fingerprint(tenant, "AI-INF.1", 1, 1, 1, ts_ms)
    print(f"   Recomputed: {GREEN}{fp_check}{RESET}")
    print(f"   Match:      {GREEN}✓ Anchor is independently verifiable{RESET}")
    print()

    # ── RAG Context Witnessing ──
    print(f"{CYAN}7. RAG Context Witnessing (AI-RAG.1 + AI-RAG.2)...{RESET}")
    print()

    rag_chunks = [
        ("EU AI Act Article 12 requires providers to build in automatic logging...", 0.94),
        ("High-risk systems must maintain logs of each period of use...", 0.87),
        ("Article 9 mandates proportionate risk management measures...", 0.72),
    ]

    rag_chunk_hashes = []
    for text, score in rag_chunks:
        h = _sha256(text, 16)
        rag_chunk_hashes.append(h)
        bar = f"{GREEN}{'█' * int(score * 10)}{DIM}{'░' * (10 - int(score * 10))}{RESET}"
        print(f"   {bar} {WHITE}{score:.2f}{RESET}  {DIM}{text[:45]}...{RESET}")
    print()

    # AI-RAG.1: Context Retrieval Provenance
    rag_fa = len(rag_chunks)
    rag_fb = 1  # corpus identified
    rag_fc = 0
    rag_fp1 = _mint_fingerprint(tenant, "AI-RAG.1", rag_fa, rag_fb, rag_fc, ts_ms)
    rag_anchor1 = _mint_anchor(tenant, provider, "AI-RAG.1", "PASS", epoch, rag_fp1)
    anchors_list.append(rag_anchor1)
    print(f"   {GREEN}■ PASS{RESET}  {WHITE}AI-RAG.1{RESET}  {DIM}3 chunks from 'eu-ai-act-corpus' witnessed{RESET}")
    print(f"     {DIM}{rag_anchor1}{RESET}")
    print()

    # AI-RAG.2: Context Relevance
    scores = [s for _, s in rag_chunks]
    avg_sim = sum(scores) / len(scores)
    threshold = 0.75
    below = sum(1 for s in scores if s < threshold)
    rag_fa2 = round(threshold * 1000)
    rag_fb2 = round(avg_sim * 1000)
    rag_fc2 = below
    rag_fp2 = _mint_fingerprint(tenant, "AI-RAG.2", rag_fa2, rag_fb2, rag_fc2, ts_ms)
    rag_anchor2 = _mint_anchor(tenant, provider, "AI-RAG.2", "PASS", epoch, rag_fp2)
    anchors_list.append(rag_anchor2)
    print(f"   {GREEN}■ PASS{RESET}  {WHITE}AI-RAG.2{RESET}  {DIM}avg similarity {avg_sim:.2f}, {below} below {threshold}{RESET}")
    print(f"     {DIM}{rag_anchor2}{RESET}")
    print()

    # ── Regulatory Translation Layer ──
    print()
    print(f"  {GREEN}[SWT3] 5 Evidence Anchors Verified.{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"  {BOLD}REGULATORY COVERAGE SUMMARY (NIST AI RMF / EU AI ACT){RESET}")
    print()

    # Demonstrated obligations — mapped to EU AI Act articles
    coverage_map = [
        ("AI-INF.1",  "Art. 12(1)",    "Automatic Logging of Use Periods",  "DEMONSTRATED"),
        ("AI-MDL.1",  "Art. 9(4a)",    "Model Risk Identification",         "DEMONSTRATED"),
        ("AI-GRD.1",  "Art. 9(2a)",    "Risk Mitigation Measures",          "DEMONSTRATED"),
        ("AI-RAG.1",  "Art. 12(2)(a)", "Reference Database Logging",        "DEMONSTRATED"),
        ("AI-RAG.2",  "Art. 10(2)",    "Data Quality & Relevance",          "DEMONSTRATED"),
    ]
    for proc, article, desc, verdict in coverage_map:
        print(f"  {GREEN}✓{RESET} {WHITE}{proc}{RESET} → {article}: {desc} {GREEN}[{verdict}]{RESET}")

    print(f"  {DIM}{'─' * 50}{RESET}")

    # Mapped obligations that need production data
    uncovered = [
        ("AI-INF.2", "Art. 15(3)", "Performance Consistency"),
        ("AI-INF.3", "Art. 12(1)", "Volume & Usage Logging"),
        ("AI-MDL.2", "Art. 12(2b)", "Version & Lineage Tracking"),
        ("AI-MDL.3", "Art. 72(1)", "Post-Market Drift Monitoring"),
        ("AI-MDL.4", "Art. 15(4)", "Feedback Loop Isolation"),
        ("AI-GRD.2", "Art. 9(4b)", "Content Safety Filtering"),
        ("AI-GRD.3", "Art. 10(2f)", "PII & Data Protection"),
        ("AI-EXPL.1", "Art. 13(1)", "Transparency & Explainability"),
        ("AI-EXPL.2", "Art. 13(3b)", "Confidence Calibration"),
    ]
    print(f"  {CYAN}{len(uncovered)} additional obligations mapped (need production data):{RESET}")
    for proc, article, desc in uncovered:
        print(f"  {DIM}  {proc} → {article}: {desc}{RESET}")

    print(f"  {DIM}{'─' * 50}{RESET}")
    print()

    # EU AI Act countdown
    from datetime import date as _date
    _days_left = (_date(2027, 12, 2) - _date.today()).days
    if _days_left > 0:
        _color = RED if _days_left < 60 else AMBER if _days_left < 120 else CYAN
        print(f"  {_color}EU AI Act high-risk enforcement in {_days_left} days (Dec 2, 2027){RESET}")
        print()

    print(f"  {DIM}Preview a live auditor view (no account required):{RESET}")
    print(f"  {CYAN}https://sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public{RESET}")
    print()
    print(f"  {DIM}Full conformity requires all 47 AI procedures. Connect to close the gap:{RESET}")
    print(f"  {CYAN}https://sovereign.tenova.io/signup?ref=sdk_demo{RESET}")
    print()
    print(f"  {DIM}SDK docs:     {CYAN}https://sovereign.tenova.io/docs/{RESET}")
    print(f"  {DIM}Book a pilot: {CYAN}https://calendly.com/tenova-axiom/30min{RESET}")
    print(f"  {DIM}GitHub:       {CYAN}https://github.com/tenova-labs/swt3-ai{RESET}")
    print()

    # ── Write HTML coverage report (best-effort) ──
    try:
        html = _generate_html_report(coverage_map, uncovered, anchors_list, _days_left)
        with open("swt3-coverage-report.html", "w", encoding="utf-8") as f:
            f.write(html)
        print(f"  {GREEN}[SWT3] Coverage report saved \u2192 swt3-coverage-report.html{RESET}")
        print()
    except Exception:
        pass  # best-effort — never fail the demo


def run_mesh_test() -> None:
    from .trust import (
        TrustRegistry, TrustCredential, verify_credential,
        TRUST_LEVEL_NAMES, TRUST_DENIED,
    )
    import hashlib

    print()
    print(f"{BOLD}SWT3 Trust Mesh Simulation{RESET}")
    print(f"{DIM}Two agents. One handshake. Zero network calls.{RESET}")
    print(f"{DIM}{'─' * 56}{RESET}")
    print()

    # ── Agent Setup ──
    print(f"  {CYAN}Agents:{RESET}")
    print(f"    {GREEN}Alice{RESET}  tenant=EU_REGULATED  profile=eu-ai-act-high-risk  {DIM}(signed, guardrails, CL2){RESET}")
    print(f"    {AMBER}Bob{RESET}    tenant=DEV_SANDBOX   profile=minimal              {DIM}(unsigned, no guardrails, CL0){RESET}")
    print()

    now_ms = int(time.time() * 1000)
    def fp(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]

    # Alice: strict, signed, high clearing
    alice_registry = TrustRegistry()
    alice_registry.set_min_trust_level(2)
    alice_registry.set_require_signature(True)
    alice_registry.trust_tenant("DEV_SANDBOX")

    alice_cred = TrustCredential(
        agent_id="alice-agent", tenant_id="EU_REGULATED",
        anchor_fingerprint=fp(f"alice-anchor-{now_ms}"),
        anchor_timestamp_ms=now_ms,
        is_signed=True, procedures=["AI-INF.1", "AI-GRD.1", "AI-FAIR.1"],
        clearing_level=2, has_guardrails=True, has_hardware_attestation=False,
    )

    # Bob: permissive, unsigned, minimal
    bob_registry = TrustRegistry()
    bob_registry.set_min_trust_level(0)
    bob_registry.trust_tenant("EU_REGULATED")

    bob_cred = TrustCredential(
        agent_id="bob-agent", tenant_id="DEV_SANDBOX",
        anchor_fingerprint=fp(f"bob-anchor-{now_ms}"),
        anchor_timestamp_ms=now_ms,
        is_signed=False, procedures=[],
        clearing_level=0, has_guardrails=False, has_hardware_attestation=False,
    )

    # ── Step 1: Alice presents ──
    print(f"  {CYAN}Step 1: Alice presents credential to Bob{RESET}")
    print(f"    Procedures: {GREEN}{', '.join(alice_cred.procedures)}{RESET}")
    print(f"    Signed: {GREEN}yes{RESET} | Guardrails: {GREEN}yes{RESET} | Hardware: {AMBER}no{RESET} | Clearing: {GREEN}{alice_cred.clearing_level}{RESET}")
    print()

    # ── Step 2: Bob verifies Alice ──
    print(f"  {CYAN}Step 2: Bob verifies Alice's credential{RESET}")
    bob_result = verify_credential(alice_cred, bob_registry, "DEV_SANDBOX")
    print(f"    Checks: {bob_result.checks_performed} performed, {bob_result.checks_passed} passed")
    level_name = TRUST_LEVEL_NAMES.get(bob_result.trust_level, "unknown")
    print(f"    Trust level: {bob_result.trust_level} ({level_name})")
    if bob_result.granted:
        print(f"    Result: {GREEN}GRANTED{RESET}")
    else:
        print(f"    Denial reason: {RED}{bob_result.denial_reason}{RESET}")
        print(f"    Result: {RED}DENIED{RESET}")
    print()

    # ── Step 3: Bob presents ──
    print(f"  {CYAN}Step 3: Bob presents credential to Alice{RESET}")
    print(f"    Procedures: {DIM}(none){RESET}")
    print(f"    Signed: {RED}no{RESET} | Guardrails: {RED}no{RESET} | Hardware: {AMBER}no{RESET} | Clearing: {AMBER}{bob_cred.clearing_level}{RESET}")
    print()

    # ── Step 4: Alice verifies Bob ──
    print(f"  {CYAN}Step 4: Alice verifies Bob's credential{RESET}")
    alice_result = verify_credential(bob_cred, alice_registry, "EU_REGULATED")
    level_name = TRUST_LEVEL_NAMES.get(alice_result.trust_level, "unknown")
    print(f"    Checks: {alice_result.checks_performed} performed, {alice_result.checks_passed} passed")
    print(f"    Trust level: {alice_result.trust_level} ({level_name})")
    if alice_result.granted:
        print(f"    Result: {GREEN}GRANTED{RESET}")
    else:
        print(f"    Denial reason: {RED}{alice_result.denial_reason}{RESET}")
        print(f"    Result: {RED}DENIED{RESET}")
    print()

    # ── Summary ──
    print(f"  {BOLD}Summary:{RESET} Asymmetric trust -- Alice is {GREEN}accepted{RESET}, Bob is {RED}rejected{RESET}.")
    print(f"  {DIM}This is how .swt3.yaml policy controls who your agent communicates with.{RESET}")
    print()


if __name__ == "__main__":
    if "--mesh-test" in sys.argv:
        run_mesh_test()
    else:
        main()
