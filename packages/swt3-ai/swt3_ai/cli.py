"""SWT3 CLI -- governance tooling for AI systems.

Commands:
    swt3 init              Interactive governance setup
    swt3 init --profile X  Non-interactive (CI/CD friendly)
    swt3 demo              Run the zero-friction demo
    swt3 doctor            Diagnose config health
    swt3 help              Show usage
"""

from __future__ import annotations

import sys
from pathlib import Path

VERSION = "8.1.0"

PROFILES = {
    "eu-ai-act-high-risk": "EU AI Act Article 6, Annex III (strict, signing required)",
    "granite-sovereign": "IBM Granite 4.1 + air-gap sovereign (strict, TPM required)",
    "mythos-defense": "Exploit chain containment (strict, rate limiting, tool blocklist)",
    "nist-ai-rmf": "NIST AI RMF + 800-53 GovCon (permissive, gradual adoption)",
    "owasp-agentic-top10": "OWASP Agentic AI Top 10 (runtime containment, fail closed)",
    "cost-conscious": "Agent token budget governance (cost attribution + audit trail)",
    "telecom-compliance": "Telecom AI governance (FCC + EU AI Act + fraud/network models)",
    "healthcare-clinical": "Clinical AI governance (HIPAA + FDA AI/ML + EU MDR)",
    "fintech-model-risk": "Model risk governance (SR 11-7 + GDPR + Basel III/IV)",
    "defense-govcon": "Defense/IC AI governance (CMMC + NIST 800-171 + FedRAMP)",
    "autonomous-systems": "Autonomous AI governance (EU Machinery Reg + EO 14110 + ISO 26262)",
    "insurance-underwriting": "Insurance AI governance (NAIC guidelines + state regs + GDPR)",
    "content-platform": "Content platform AI governance (DSA + Art. 50 + GPAI Code)",
    "microsoft-foundry": "Microsoft Foundry agent governance (AGT + OWASP Agentic + SOC 2)",
    "microsoft-agt": "Microsoft AGT policy engine governance (independent witness for AGT decisions)",
    "energy-grid": "Energy grid AI governance (NERC CIP + FERC 2222 + IEEE 1547)",
    "si-accord-2026": "White House SI Accord 2026 (4-layer frontier AI governance)",
    "minimal": "Development / evaluation (no enforcement)",
}

PROFILE_NAMES = list(PROFILES.keys())

# ── Colors (TTY-aware) ──

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


def _print_help() -> None:
    v = VERSION
    lines = [
        f"\n  {CYAN}{BOLD}SWT3 CLI{RESET} {DIM}v{v}{RESET}\n",
        f"  {BOLD}Setup{RESET}",
        f"    {GREEN}init{RESET}              {DIM}Interactive governance setup{RESET}",
        f"    {GREEN}init --profile X{RESET}  {DIM}Non-interactive (CI/CD){RESET}",
        f"    {GREEN}quickstart{RESET}        {DIM}Generate a working example script{RESET}",
        f"    {GREEN}demo{RESET}              {DIM}Run the zero-friction demo{RESET}",
        f"    {GREEN}doctor{RESET}            {DIM}Diagnose config health{RESET}",
        "",
        f"  {BOLD}Observe{RESET}",
        f"    {GREEN}status{RESET}            {DIM}Compliance posture at a glance{RESET}",
        f"    {GREEN}diff --since 7d{RESET}   {DIM}Posture delta over time{RESET}",
        f"    {GREEN}watch{RESET}             {DIM}Live tail of witness anchors{RESET}",
        "",
        f"  {BOLD}Verify{RESET}",
        f"    {GREEN}verify{RESET}            {DIM}Offline anchor fingerprint verification{RESET}",
        f"    {GREEN}crosswalk <proc>{RESET}  {DIM}Framework mappings for a procedure{RESET}",
        f"    {GREEN}procedures{RESET}        {DIM}List all UCT procedures{RESET}",
        f"    {GREEN}gate{RESET}              {DIM}Evaluate compliance gate{RESET}",
        "",
        f"  {BOLD}Export{RESET}",
        f"    {GREEN}audit{RESET}             {DIM}Forensic chain timeline (html/json){RESET}",
        f"    {GREEN}reconstruct{RESET}       {DIM}Forensic timeline reconstruction{RESET}",
        "",
        f"  {BOLD}Assess{RESET}",
        f"    {GREEN}exposure{RESET}          {DIM}Regulatory exposure calculator{RESET}",
        "",
        f"  {BOLD}Test{RESET}",
        f"    {GREEN}test{RESET}              {DIM}End-to-end pipeline smoke test{RESET}",
        "",
        f"  {DIM}Run{RESET} {WHITE}swt3 help <command>{RESET} {DIM}for flags and examples.{RESET}",
        "",
        f"  {BOLD}Quick Start{RESET}",
        f"    {WHITE}pip install swt3-ai && swt3 init && swt3 demo{RESET}",
        "",
        f"  {DIM}Docs: https://sovereign.tenova.io/docs/{RESET}",
        "",
    ]
    print("\n".join(lines))


# ── Per-command help ──

_COMMAND_HELP = {
    "init": {
        "desc": "Interactive governance setup. Creates swt3.yaml in the current directory.",
        "usage": "swt3 init [flags]",
        "flags": [
            ("--profile <name>", "Use a named profile (non-interactive)"),
            ("--expand", "Include full profile template in output"),
            ("--ci-template", "Dump GitHub Action workflow to stdout"),
            ("--tenant <id>", "Set tenant ID"),
            ("--agent <id>", "Set agent ID"),
            ("--force", "Overwrite existing swt3.yaml"),
        ],
        "examples": [
            "swt3 init",
            "swt3 init --profile eu-ai-act-high-risk",
            "swt3 init --profile defense-govcon --tenant my-org --agent my-agent",
            "swt3 init --ci-template > .github/workflows/swt3.yml",
        ],
        "profiles": True,
    },
    "status": {
        "desc": "Compliance posture at a glance. Reads local WAL + optional API.",
        "usage": "swt3 status [flags]",
        "flags": [
            ("--full", "Show all articles and all gaps"),
            ("--coverage", "Visual procedure coverage bars"),
            ("--framework <id>", "Override target framework (e.g. EU-AI-ACT)"),
            ("--json", "Machine-readable output (CI/CD)"),
            ("--compact", "One-line summary"),
        ],
        "examples": [
            "swt3 status",
            "swt3 status --coverage",
            "swt3 status --framework EU-AI-ACT --full",
            "swt3 status --json | jq .score",
        ],
    },
    "diff": {
        "desc": "Compliance posture delta over time.",
        "usage": "swt3 diff --since <duration> [flags]",
        "flags": [
            ("--since <dur>", "Time window: 1h, 7d, 30d (required)"),
            ("--json", "Machine-readable output"),
            ("--compact", "One-line diff for CI/CD"),
        ],
        "examples": [
            "swt3 diff --since 7d",
            "swt3 diff --since 30d --json",
            "swt3 diff --since 1h --compact",
        ],
    },
    "watch": {
        "desc": "Live tail of witness anchors as they are minted.",
        "usage": "swt3 watch [flags]",
        "flags": [
            ("--filter <proc>", "Filter by procedure (prefix match, e.g. AI-INF)"),
            ("--agent <id>", "Filter by agent ID"),
            ("--json", "NDJSON output (pipe to jq)"),
            ("--tenant <id>", "Override tenant (default: from swt3.yaml)"),
            ("--tail <n>", "Lines to show on start (default: 10, 0 = none)"),
        ],
        "examples": [
            "swt3 watch",
            "swt3 watch --filter AI-INF.1",
            "swt3 watch --json | jq .verdict",
            "swt3 watch --agent orchestrator --tail 0",
        ],
    },
    "exposure": {
        "desc": "Regulatory exposure calculator. Shows which frameworks apply to a jurisdiction and industry.",
        "usage": "swt3 exposure [flags]",
        "flags": [
            ("--jurisdiction <code>", "ISO country or region (EU, US, UK, CN, JP, ...)"),
            ("-j <code>", "Short form for --jurisdiction"),
            ("--industry <name>", "Industry filter (ai, fintech, defense, healthcare, ...)"),
            ("-i <name>", "Short form for --industry"),
            ("--all", "Show all frameworks"),
            ("--binding <type>", "Filter: mandatory or advisory"),
            ("--json", "Machine-readable JSON output"),
            ("--markdown", "Markdown table output"),
        ],
        "examples": [
            "swt3 exposure --jurisdiction EU",
            "swt3 exposure --jurisdiction US --industry fintech",
            "swt3 exposure --jurisdiction EU --binding mandatory",
            "swt3 exposure --all --json",
        ],
    },
    "test": {
        "desc": "End-to-end pipeline smoke test. Mints a real anchor and verifies it.",
        "usage": "swt3 test [flags]",
        "flags": [
            ("--json", "Machine-readable output"),
        ],
        "examples": [
            "swt3 test",
            "swt3 test --json",
        ],
    },
    "demo": {
        "desc": "Run the zero-friction demo. No API keys, no account, no network.",
        "usage": "swt3 demo",
        "flags": [
            ("--mesh-test", "Run trust mesh connectivity test"),
        ],
        "examples": [
            "swt3 demo",
        ],
    },
    "doctor": {
        "desc": "Diagnose config health. Checks YAML, env vars, profile, TPM, MCP.",
        "usage": "swt3 doctor [flags]",
        "flags": [
            ("--ci", "Strict mode (exit 1 on warnings)"),
            ("--json", "Machine-readable output"),
            ("--friction-test", "Run end-to-end friction test"),
        ],
        "examples": [
            "swt3 doctor",
            "swt3 doctor --ci",
            "swt3 doctor --friction-test",
        ],
    },
    "procedures": {
        "desc": "List all UCT procedures in the registry.",
        "usage": "swt3 procedures [flags]",
        "flags": [
            ("--namespace <ns>", "Filter by namespace (e.g. MDL, GRD, INF)"),
            ("--json", "Machine-readable output"),
        ],
        "examples": [
            "swt3 procedures",
            "swt3 procedures --namespace AI",
            "swt3 procedures --json | jq '.[].id'",
        ],
    },
    "gate": {
        "desc": "Compliance gate for CI/CD pipelines.",
        "usage": "swt3 gate [flags]",
        "flags": [
            ("--init", "Generate .swt3-gate.yml (list frameworks if no --framework)"),
            ("--framework <id>", "Target framework for gate init"),
            ("--validate", "Validate gate config offline"),
        ],
        "examples": [
            "swt3 gate --init --framework EU-AI-ACT",
            "swt3 gate --validate",
            "swt3 gate",
        ],
    },
    "crosswalk": {
        "desc": "Framework mappings for a procedure (or all procedures for a framework).",
        "usage": "swt3 crosswalk <procedure> | --framework <id> [flags]",
        "flags": [
            ("--framework <id>", "Show all procedures for a framework"),
            ("--json", "Machine-readable output"),
        ],
        "examples": [
            "swt3 crosswalk AI-INF.1",
            "swt3 crosswalk --framework EU-AI-ACT",
            "swt3 crosswalk --framework CMMC --json",
        ],
    },
    "verify": {
        "desc": "Offline anchor fingerprint verification. Zero network calls.",
        "usage": "swt3 verify --anchor <token> --tenant <id> --procedure <id> --fa <n> --fb <n> --fc <n> --ts <ms>",
        "flags": [
            ("--anchor <token>", "Full SWT3 anchor token"),
            ("--tenant <id>", "Tenant ID"),
            ("--procedure <id>", "Procedure ID (e.g. AI-INF.1)"),
            ("--fa/--fb/--fc <n>", "Factor values"),
            ("--ts <ms>", "Timestamp in milliseconds"),
        ],
        "examples": [
            "swt3 verify --anchor SWT3-E-AWS-AI-AIINF1-PASS-1773316622-a1b2c3d4e5f6 "
            "--tenant MY_TENANT --procedure AI-INF.1 --fa 1 --fb 1 --fc 0 --ts 1773316622000",
        ],
    },
    "audit": {
        "desc": "Forensic chain timeline. Generates self-contained HTML or JSON.",
        "usage": "swt3 audit [flags]",
        "flags": [
            ("--format <fmt>", "Output format: html (default) or json"),
            ("--wal-path <dir>", "Override WAL directory"),
        ],
        "examples": [
            "swt3 audit",
            "swt3 audit --format json",
        ],
    },
    "reconstruct": {
        "desc": "Forensic timeline reconstruction from server or local WAL.",
        "usage": "swt3 reconstruct <query> [flags]",
        "flags": [
            ("--cycle <id>", "Reconstruct by cycle ID"),
            ("--agent <id>", "Reconstruct by agent ID"),
            ("--fingerprint <fp>", "Reconstruct by fingerprint"),
            ("--chain <id>", "Reconstruct by lifecycle chain ID"),
            ("--last <dur>", "Time window: 1h, 30m, 2d"),
            ("--json", "JSON output"),
            ("--html", "HTML report"),
            ("--output <path>", "Output file path"),
            ("--local", "Force local WAL (skip API)"),
        ],
        "examples": [
            "swt3 reconstruct --last 1h",
            "swt3 reconstruct --agent orchestrator --last 30m --html",
            "swt3 reconstruct --cycle cycle-001 --json",
        ],
    },
    "quickstart": {
        "desc": "Generate a working example script (swt3_quickstart.py).",
        "usage": "swt3 quickstart",
        "flags": [],
        "examples": [
            "swt3 quickstart && python swt3_quickstart.py",
        ],
    },
}


def _print_command_help(cmd: str) -> None:
    info = _COMMAND_HELP.get(cmd)
    if not info:
        print(f"\n  {RED}Unknown command: {cmd}{RESET}")
        print(f"  {DIM}Run: swt3 help{RESET}\n")
        sys.exit(1)

    print(f"\n  {CYAN}{BOLD}swt3 {cmd}{RESET}")
    print(f"  {info['desc']}")
    print(f"\n  {BOLD}Usage:{RESET} {WHITE}{info['usage']}{RESET}")

    if info["flags"]:
        print(f"\n  {BOLD}Flags:{RESET}")
        for flag, desc in info["flags"]:
            print(f"    {GREEN}{flag:<22}{RESET} {DIM}{desc}{RESET}")

    if info.get("examples"):
        print(f"\n  {BOLD}Examples:{RESET}")
        for ex in info["examples"]:
            print(f"    {WHITE}{ex}{RESET}")

    if info.get("profiles"):
        print(f"\n  {BOLD}Profiles:{RESET}")
        for i, name in enumerate(PROFILE_NAMES):
            print(f"    {AMBER}{i + 1:2d}. {name:<26}{RESET} {DIM}{PROFILES[name]}{RESET}")

    print(f"\n  {DIM}Docs: https://sovereign.tenova.io/docs/{RESET}\n")


def _resolve_template_path(profile: str) -> Path:
    return Path(__file__).parent / "templates" / f"{profile}.yaml"


def generate_expanded_yaml(profile: str, tenant_id: str, agent_id: str) -> str:
    template_path = _resolve_template_path(profile)
    if not template_path.is_file():
        raise FileNotFoundError(f"Template not found: {profile}")
    template = template_path.read_text(encoding="utf-8")
    header = "\n".join([
        f"# Generated by: swt3 init --profile {profile} --expand",
        "# Docs: https://sovereign.tenova.io/docs/",
        "",
        f"profile: {profile}",
        "",
        f"tenant_id: {tenant_id or 'YOUR_TENANT_ID'}",
        "api_key_env: SWT3_API_KEY",
        f"agent_id: {agent_id or 'your-agent-name'}",
        "",
    ])
    body = "\n".join(
        line for line in template.split("\n")
        if not line.startswith("# ") and not line.startswith("#!") and line.strip() != "#"
    ).lstrip("\n")
    return header + body


def generate_init_yaml(profile: str, tenant_id: str, agent_id: str) -> str:
    lines = [
        f"# Generated by: swt3 init --profile {profile}",
        "# Docs: https://sovereign.tenova.io/docs/",
        "",
        f"profile: {profile}",
        "",
        "# Required:",
        f"tenant_id: {tenant_id or 'YOUR_TENANT_ID'}",
        "api_key_env: SWT3_API_KEY",
        f"agent_id: {agent_id or 'your-agent-name'}",
        "",
        "# Optional overrides (uncomment to customize):",
        "# endpoint: https://sovereign.tenova.io",
        "# clearing_level: 2",
        "# jurisdiction: US",
        "# signing_key_env: SWT3_SIGNING_KEY",
        "",
    ]
    return "\n".join(lines)


def _get_flag(args: list, flag: str) -> str:
    try:
        idx = args.index(flag)
        return args[idx + 1]
    except (ValueError, IndexError):
        return ""


def _handle_ci_template() -> None:
    template_path = Path(__file__).parent / "templates" / "github-action.yml"
    if not template_path.is_file():
        print("GitHub Action template not found in package.", file=sys.stderr)
        sys.exit(1)
    print(template_path.read_text(encoding="utf-8"))


def handle_init(args: list) -> None:
    if "--ci-template" in args:
        _handle_ci_template()
        return

    output_path = Path.cwd() / "swt3.yaml"

    force = "--force" in args
    if output_path.exists() and not force:
        print("swt3.yaml already exists. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)

    profile = _get_flag(args, "--profile")
    tenant_id = _get_flag(args, "--tenant")
    agent_id = _get_flag(args, "--agent")

    if profile and profile not in PROFILE_NAMES:
        print(f"Unknown profile: '{profile}'", file=sys.stderr)
        print(f"Valid profiles: {', '.join(PROFILE_NAMES)}", file=sys.stderr)
        sys.exit(1)

    if not profile:
        print("\n  SWT3 Governance Setup\n")
        print("  Choose a compliance profile:")
        for i, name in enumerate(PROFILE_NAMES):
            print(f"    {i + 1}. {name:<24} {PROFILES[name]}")

        try:
            choice = input(f"\n  Profile [1-{len(PROFILE_NAMES)}]: ")
            idx = int(choice) - 1
            if idx < 0 or idx >= len(PROFILE_NAMES):
                raise ValueError
            profile = PROFILE_NAMES[idx]
        except (ValueError, EOFError):
            print("  Invalid selection.", file=sys.stderr)
            sys.exit(1)

        if not tenant_id:
            tenant_id = input("  Tenant ID: ")
        if not agent_id:
            agent_id = input("  Agent ID [optional]: ")

    expand = "--expand" in args
    content = (
        generate_expanded_yaml(profile, tenant_id, agent_id)
        if expand
        else generate_init_yaml(profile, tenant_id, agent_id)
    )
    output_path.write_text(content, encoding="utf-8")

    suffix = " (expanded profile)" if expand else ""
    print(f"\n  Created: swt3.yaml{suffix}\n")
    print("  Next: set SWT3_API_KEY in your environment, then:")
    print("    from swt3_ai import Witness")
    print("    witness = Witness.from_config()  # done.\n")


_QUICKSTART_PY = '''\
"""SWT3 AI Witness quickstart -- generated by `swt3 quickstart`."""

from pathlib import Path
from swt3_ai import Witness

# Auto-detect swt3.yaml if present, otherwise use defaults
if Path("swt3.yaml").is_file() or Path(".swt3.yaml").is_file():
    witness = Witness.from_config()
    print("Loaded config from swt3.yaml")
else:
    witness = Witness(
        tenant_id="QUICKSTART_TENANT",
        clearing_level=1,
    )
    print("No swt3.yaml found -- using defaults. Run: swt3 init")

# Wrap an inference call -- the SDK hashes inputs/outputs and mints anchors
response = witness.wrap(
    prompt="What are the three laws of robotics?",
    response="1. A robot may not injure a human being...",
    model_id="quickstart-model",
    provider="local",
)

print(f"Response: {response.response[:60]}...")
print(f"Anchors minted: {len(witness.pending)}")

# Flush anchors (prints to console in local mode)
results = witness.flush()
for r in results:
    print(f"  {r.procedure_id}: {r.anchor_fingerprint}")

print("\\nDone. See https://sovereign.tenova.io/docs/ for full documentation.")
'''


def _handle_crosswalk(args: list) -> None:
    """Look up framework mappings for a procedure."""
    from .crosswalk import resolve, resolve_framework, frameworks

    _tty = sys.stdout.isatty()
    _bold = "\033[1m" if _tty else ""
    _dim = "\033[2m" if _tty else ""
    _cyan = "\033[36m" if _tty else ""
    _green = "\033[32m" if _tty else ""
    _rst = "\033[0m" if _tty else ""

    use_json = "--json" in args
    procedure = ""
    framework = ""

    framework = _get_flag(args, "--framework")

    # Collect positional args (skip flags and their values)
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a in ("--framework",):
            skip_next = True
            continue
        if a.startswith("--"):
            continue
        if not procedure:
            procedure = a.upper()

    if framework and not procedure:
        # Framework lookup: show all procedures mapped to this framework
        fw_id = framework.upper()
        mappings = resolve_framework(fw_id)
        if not mappings:
            print(f"  No crosswalk found for framework: {fw_id}", file=sys.stderr)
            sys.exit(1)

        if use_json:
            import json
            print(json.dumps({"framework": fw_id, "mappings": mappings}, indent=2))
            return

        print(f"\n  {_bold}Framework Crosswalk: {_cyan}{fw_id}{_rst}\n")
        for req, procs in sorted(mappings.items()):
            proc_list = ", ".join(procs)
            print(f"    {_green}{req:<20}{_rst} {proc_list}")
        print(f"\n  {_dim}{len(mappings)} requirements mapped.{_rst}\n")
        return

    if not procedure:
        print(
            "\nUsage:\n"
            "  swt3 crosswalk <procedure>                Show framework mappings\n"
            "  swt3 crosswalk <procedure> --json          Machine-readable\n"
            "  swt3 crosswalk --framework <id>            Show all procedures for a framework\n"
            "  swt3 crosswalk --framework <id> --json     Machine-readable\n\n"
            "Examples:\n"
            "  swt3 crosswalk AI-A2A.1\n"
            "  swt3 crosswalk AI-MCP.5\n"
            "  swt3 crosswalk --framework EU-AI-ACT\n"
        )
        return

    # Procedure lookup
    mapping = resolve(procedure)
    if not mapping:
        print(f"  No crosswalk found for procedure: {procedure}", file=sys.stderr)
        print(f"  {_dim}Check: swt3 procedures --json | grep {procedure}{_rst}", file=sys.stderr)
        sys.exit(1)

    if use_json:
        import json
        print(json.dumps({"procedure": procedure, "frameworks": mapping}, indent=2))
        return

    # Procedure name lookup
    proc_name = ""
    try:
        from .procedures import PROCEDURE_CATALOG
        for p in PROCEDURE_CATALOG:
            if p["id"] == procedure:
                proc_name = p["name"]
                break
    except Exception:
        pass

    sep = "\u2500" * 50
    print(f"\n  {_bold}Crosswalk: {_cyan}{procedure}{_rst}")
    if proc_name:
        print(f"  {_dim}{proc_name}{_rst}")
    print(f"  {sep}")
    for fw, ref in sorted(mapping.items()):
        print(f"    {_green}{fw:<24}{_rst} {ref}")
    print(f"  {sep}")
    print(f"  {_dim}{len(mapping)} framework(s) mapped. Zero network calls.{_rst}\n")


def _handle_quickstart() -> None:
    """Generate a quickstart example script in the current directory."""
    out = Path("swt3_quickstart.py")
    if out.exists():
        print(f"  {out} already exists. Remove it first.", file=sys.stderr)
        sys.exit(1)
    out.write_text(_QUICKSTART_PY, encoding="utf-8")
    print(f"\n  Created: {out}")
    print("  Run it:  python swt3_quickstart.py\n")


def main() -> None:
    args = sys.argv[1:]
    cmd = args[0] if args else None

    # Intercept --help on any command: swt3 status --help -> swt3 help status
    if cmd and cmd not in ("help", "--help", "-h") and "--help" in args[1:]:
        _print_command_help(cmd)
        return

    # swt3 help <command>
    if cmd == "help" and len(args) > 1 and not args[1].startswith("-"):
        _print_command_help(args[1])
        return

    if cmd == "status":
        from .status import handle_status
        handle_status(args[1:])
    elif cmd == "diff":
        from .diff import handle_diff
        handle_diff(args[1:])
    elif cmd == "init":
        handle_init(args[1:])
    elif cmd == "demo":
        if "--mesh-test" in args[1:]:
            from .demo import run_mesh_test
            run_mesh_test()
        else:
            from .demo import main as demo_main
            demo_main()
    elif cmd == "doctor":
        if "--friction-test" in args[1:]:
            from .doctor import run_friction_test, print_friction_results
            steps = run_friction_test()
            print_friction_results(steps)
            if any(s.status == "fail" for s in steps):
                sys.exit(1)
        else:
            from .doctor import run_doctor_checks, print_doctor_results
            checks = run_doctor_checks()
            use_json = "--json" in args[1:]
            ci_mode = "--ci" in args[1:] or "--strict" in args[1:]
            print_doctor_results(checks, use_json=use_json, ci_mode=ci_mode)
            has_fail = any(c.status == "fail" for c in checks)
            has_warn = any(c.status == "warn" for c in checks)
            if has_fail or (ci_mode and has_warn):
                sys.exit(1)
    elif cmd == "audit":
        from .exporters.chain_monitor import ChainMonitorExporter
        fmt = _get_flag(args[1:], "--format") or "html"
        wal_dir = _get_flag(args[1:], "--wal-path")
        tenant_id, agent_id, clearing_level = "UNKNOWN", "UNKNOWN", 1
        try:
            from .config import load_full_config
            loaded = load_full_config()
            tenant_id = loaded.witness_kwargs.get("tenant_id", tenant_id)
            agent_id = loaded.witness_kwargs.get("agent_id", agent_id)
            clearing_level = loaded.witness_kwargs.get("clearing_level", clearing_level)
        except Exception:
            pass
        kw = {"tenant_id": tenant_id, "agent_id": agent_id, "clearing_level": clearing_level}
        if wal_dir:
            kw["wal_dir"] = wal_dir
        exporter = ChainMonitorExporter(**kw)
        if fmt == "json":
            print(exporter.export_json())
        else:
            html_out = exporter.export_html()
            out_path = "swt3-audit-report.html"
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(html_out)
            print(f"Audit report saved: {out_path}")
    elif cmd == "verify":
        sub = args[1:]
        anchor = _get_flag(sub, "--anchor")
        tenant = _get_flag(sub, "--tenant")
        procedure = _get_flag(sub, "--procedure")
        fa = _get_flag(sub, "--fa")
        fb = _get_flag(sub, "--fb")
        fc = _get_flag(sub, "--fc")
        ts = _get_flag(sub, "--ts")

        if not all([anchor, tenant, procedure, fa, fb, fc, ts]):
            print(
                "\nUsage:\n"
                "  swt3 verify --anchor <token> --tenant <id> --procedure <id> "
                "--fa <n> --fb <n> --fc <n> --ts <ms>\n\n"
                "Example:\n"
                "  swt3 verify --anchor SWT3-E-AWS-AI-AIINF1-PASS-1773316622-a1b2c3d4e5f6 \\\n"
                "    --tenant <YOUR_TENANT_ID> --procedure AI-INF.1 --fa 1 --fb 1 --fc 0 --ts 1773316622000\n\n"
                "Zero network calls. Recomputes the SHA-256 fingerprint locally."
            )
        else:
            from .fingerprint import mint_fingerprint
            import datetime
            import time as _time

            _fa, _fb, _fc, _ts = float(fa), float(fb), float(fc), int(ts)

            # Consistent number formatting (match fingerprint.py)
            def _num_str(v: float) -> str:
                return str(int(v)) if v == int(v) else str(v)

            recomputed = mint_fingerprint(tenant, procedure, _fa, _fb, _fc, _ts)
            claimed = anchor.rsplit("-", 1)[-1] if anchor else ""
            match = recomputed == claimed

            # Colors (respect non-TTY)
            _tty = sys.stdout.isatty()
            _green = "\033[32m" if _tty else ""
            _red = "\033[31m" if _tty else ""
            _bold = "\033[1m" if _tty else ""
            _dim = "\033[2m" if _tty else ""
            _cyan = "\033[36m" if _tty else ""
            _rst = "\033[0m" if _tty else ""

            # Parse anchor: SWT3-{TIER}-{PROVIDER}-...-{VERDICT}-{EPOCH}-{FP}
            anchor_parts = anchor.split("-") if anchor else []
            tier_code = anchor_parts[1] if len(anchor_parts) >= 3 else ""
            tier_map = {"E": "Enclave", "S": "SaaS", "H": "Hybrid"}
            tier_name = tier_map.get(tier_code, tier_code)
            verdict = ""
            for p in anchor_parts:
                if p in ("PASS", "FAIL"):
                    verdict = p

            # Procedure name lookup
            proc_name = ""
            try:
                from .procedures import PROCEDURE_CATALOG
                for p in PROCEDURE_CATALOG:
                    if p["id"] == procedure:
                        proc_name = p["name"]
                        break
            except Exception:
                pass

            # Human-readable timestamp + age
            ts_sec = _ts / 1000 if _ts > 1e12 else _ts
            try:
                ts_human = datetime.datetime.fromtimestamp(ts_sec, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            except (OSError, ValueError):
                ts_human = "invalid"

            age_str = ""
            try:
                diff_s = _time.time() - ts_sec
                if diff_s < 0:
                    age_str = "just now"
                elif diff_s < 60:
                    age_str = "just now"
                elif diff_s < 3600:
                    age_str = f"{int(diff_s / 60)}m ago"
                elif diff_s < 86400:
                    age_str = f"{int(diff_s / 3600)}h ago"
                elif diff_s < 2592000:
                    age_str = f"{int(diff_s / 86400)}d ago"
                else:
                    age_str = f"{int(diff_s / 2592000)}mo ago"
            except Exception:
                pass

            # Formula preimage
            formula = f'WITNESS:{tenant}:{procedure}:{_num_str(_fa)}:{_num_str(_fb)}:{_num_str(_fc)}:{_ts}'

            sep = "\u2500" * 55

            print(f"\n  {_bold}SWT3 Verify{_rst}")
            print(f"  {sep}")
            print(f"  Anchor:     {_cyan}{anchor}{_rst}")
            print(f"  Tenant:     {tenant}")
            proc_line = f"  Procedure:  {procedure}"
            if proc_name:
                proc_line += f"  {_dim}({proc_name}){_rst}"
            print(proc_line)
            if tier_name:
                print(f"  Tier:       {tier_name}")
            if verdict:
                v_color = _green if verdict == "PASS" else _red
                print(f"  Verdict:    {v_color}{_bold}{verdict}{_rst}")
            ts_line = f"  Timestamp:  {_ts} ({ts_human})"
            if age_str:
                ts_line += f"  {_dim}[{age_str}]{_rst}"
            print(ts_line)
            print(f"  Formula:    {_dim}SHA256(\"{formula}\")[:12]{_rst}")
            print(f"  {sep}")
            print()

            if match:
                print(f"  {_green}{_bold}CERTIFIED TRUTH{_rst}")
                print(f"    Fingerprint: {_green}{recomputed}{_rst}")
                print(f"    {_dim}The claimed fingerprint matches the recomputed SHA-256.{_rst}")
            else:
                print(f"  {_red}{_bold}TAMPERED{_rst}")
                print(f"    Claimed:    {_red}{claimed}{_rst}")
                print(f"    Recomputed: {recomputed}")
                print(f"    {_dim}The fingerprint does not match. This anchor may have been altered.{_rst}")

            print(f"\n  {_dim}Zero network calls. Offline verification complete.{_rst}\n")
    elif cmd == "procedures":
        from .procedures import handle_procedures
        namespace = _get_flag(args[1:], "--namespace")
        use_json = "--json" in args[1:]
        handle_procedures(namespace=namespace, use_json=use_json)
    elif cmd == "reconstruct":
        from .reconstruct import handle_reconstruct
        handle_reconstruct(args[1:])
    elif cmd == "gate":
        from .gate import handle_gate
        handle_gate(args[1:])
    elif cmd == "crosswalk":
        _handle_crosswalk(args[1:])
    elif cmd == "quickstart":
        _handle_quickstart()
    elif cmd == "exposure":
        from .exposure import handle_exposure
        handle_exposure(args[1:])
    elif cmd == "watch":
        from .watch import handle_watch
        handle_watch(args[1:])
    elif cmd == "test":
        from .test_pipeline import handle_test
        handle_test(args[1:])
    elif cmd in ("help", "--help", "-h", None):
        _print_help()
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        _print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
