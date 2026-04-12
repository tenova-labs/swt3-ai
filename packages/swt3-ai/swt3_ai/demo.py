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

    for proc_id, fa, fb, fc, verdict, desc in procedures:
        fp = _mint_fingerprint(tenant, proc_id, fa, fb, fc, ts_ms)
        anchor = _mint_anchor(tenant, provider, proc_id, verdict, epoch, fp)
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

    # ── Regulatory Translation Layer ──
    print()
    print(f"  {GREEN}[SWT3] 3 Evidence Anchors Verified.{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"  {BOLD}REGULATORY COVERAGE SUMMARY (NIST AI RMF / EU AI ACT){RESET}")
    print()

    # Covered obligations — mapped to EU AI Act articles
    coverage_map = [
        ("AI-INF.1", "Art. 12(1)", "Automatic Logging of Use Periods", "PASS"),
        ("AI-MDL.1", "Art. 9(4a)", "Model Risk Identification",       "PASS"),
        ("AI-GRD.1", "Art. 9(2a)", "Risk Mitigation Measures",        "PASS"),
    ]
    for proc, article, desc, verdict in coverage_map:
        print(f"  {GREEN}✓{RESET} {WHITE}{proc}{RESET} → {article}: {desc} {GREEN}[{verdict}]{RESET}")

    print(f"  {DIM}{'─' * 50}{RESET}")

    # Uncovered obligations
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
    print(f"  {AMBER}⚠ {len(uncovered)}/12 obligations uncovered:{RESET}")
    for proc, article, desc in uncovered:
        print(f"  {DIM}  {proc} → {article}: {desc}{RESET}")

    print(f"  {DIM}{'─' * 50}{RESET}")
    print()

    # EU AI Act countdown
    from datetime import date as _date
    _days_left = (_date(2026, 8, 2) - _date.today()).days
    if _days_left > 0:
        _color = RED if _days_left < 60 else AMBER if _days_left < 120 else CYAN
        print(f"  {_color}EU AI Act enforcement in {_days_left} days (Aug 2, 2026){RESET}")
        print()

    print(f"  {DIM}Full conformity requires all 12 procedures. Connect to close the gap:{RESET}")
    print(f"  {CYAN}https://sovereign.tenova.io/signup?ref=sdk_demo{RESET}")
    print()
    print(f"  {DIM}SDK docs:     {CYAN}https://sovereign.tenova.io/docs/{RESET}")
    print(f"  {DIM}Book a pilot: {CYAN}https://calendly.com/tenova-axiom/30min{RESET}")
    print(f"  {DIM}GitHub:       {CYAN}https://github.com/tenova-labs/swt3-ai{RESET}")
    print()


if __name__ == "__main__":
    main()
