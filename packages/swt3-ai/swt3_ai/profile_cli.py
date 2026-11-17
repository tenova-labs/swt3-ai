"""SWT3 CLI -- Profile management subcommands.

Usage:
    swt3 profile list                  List all available profiles
    swt3 profile show <name>           Show full YAML of a profile
    swt3 profile compare <a> <b>       Colored diff of two profiles

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# ANSI
_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_DIM = "\033[90m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

TEMPLATES_DIR = Path(__file__).parent / "templates"

# Key sections to compare (order matters for display)
_COMPARE_SECTIONS = [
    "clearing_level",
    "policy",
    "trust_mesh",
    "density_policy",
    "hardware",
    "mcp_policy",
    "skill_card",
    "merkle",
]


def _get_profiles() -> List[Dict[str, str]]:
    """Scan templates dir for .yaml profiles. Returns list of {name, desc, path}."""
    profiles = []
    for f in sorted(TEMPLATES_DIR.glob("*.yaml")):
        name = f.stem
        desc = ""
        try:
            first_line = f.read_text(encoding="utf-8").split("\n", 1)[0]
            if first_line.startswith("#"):
                # Strip "# SWT3 Profile: " prefix
                desc = first_line.lstrip("# ").strip()
                if desc.startswith("SWT3 Profile: "):
                    desc = desc[len("SWT3 Profile: "):]
        except OSError:
            pass
        profiles.append({"name": name, "desc": desc, "path": str(f)})
    return profiles


def _load_yaml(path: str) -> Dict[str, Any]:
    """Load a YAML file into a dict."""
    try:
        import yaml
    except ImportError:
        print("PyYAML is required for profile commands. Install: pip install pyyaml", file=sys.stderr)
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def handle_profile_list(args: List[str]) -> None:
    """List all available config profiles."""
    use_json = "--json" in args
    profiles = _get_profiles()

    if use_json:
        import json
        print(json.dumps([{"name": p["name"], "description": p["desc"]} for p in profiles], indent=2))
        return

    max_name = max(len(p["name"]) for p in profiles) if profiles else 10

    print(f"\n  {_BOLD}SWT3 Config Profiles{_RESET} ({len(profiles)} available)\n")
    for p in profiles:
        print(f"    {_GREEN}{p['name']:<{max_name}}{_RESET}  {_DIM}{p['desc']}{_RESET}")

    print(f"\n  {_DIM}Usage: swt3 profile show <name>{_RESET}")
    print(f"  {_DIM}       swt3 init --profile <name>{_RESET}\n")


def handle_profile_show(args: List[str]) -> None:
    """Show the full YAML content of a named profile."""
    if not args or args[0].startswith("-"):
        print(f"\n  {_RED}Missing profile name.{_RESET}", file=sys.stderr)
        print(f"  Usage: {_BOLD}swt3 profile show <name>{_RESET}", file=sys.stderr)
        print(f"  {_DIM}Run 'swt3 profile list' to see available profiles.{_RESET}\n", file=sys.stderr)
        sys.exit(1)

    name = args[0]
    profiles = {p["name"]: p for p in _get_profiles()}

    if name not in profiles:
        print(f"\n  {_RED}Unknown profile:{_RESET} {_BOLD}{name}{_RESET}", file=sys.stderr)
        print(f"  {_DIM}Available: {', '.join(sorted(profiles.keys()))}{_RESET}\n", file=sys.stderr)
        sys.exit(1)

    path = profiles[name]["path"]
    content = Path(path).read_text(encoding="utf-8")

    # Simple syntax highlighting
    lines = content.split("\n")
    print(f"\n  {_BOLD}Profile: {name}{_RESET}\n")
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("#"):
            print(f"  {_DIM}{line}{_RESET}")
        elif ":" in line and not stripped.startswith("-"):
            key, _, val = line.partition(":")
            print(f"  {_CYAN}{key}{_RESET}:{val}")
        else:
            print(f"  {line}")
    print()


def handle_profile_compare(args: List[str]) -> None:
    """Compare two profiles side-by-side."""
    non_flag = [a for a in args if not a.startswith("-")]
    if len(non_flag) < 2:
        print(f"\n  {_RED}Two profile names required.{_RESET}", file=sys.stderr)
        print(f"  Usage: {_BOLD}swt3 profile compare <profile_a> <profile_b>{_RESET}", file=sys.stderr)
        print(f"  {_DIM}Run 'swt3 profile list' to see available profiles.{_RESET}\n", file=sys.stderr)
        sys.exit(1)

    name_a, name_b = non_flag[0], non_flag[1]
    profiles = {p["name"]: p for p in _get_profiles()}

    for name in (name_a, name_b):
        if name not in profiles:
            print(f"\n  {_RED}Unknown profile:{_RESET} {_BOLD}{name}{_RESET}", file=sys.stderr)
            print(f"  {_DIM}Available: {', '.join(sorted(profiles.keys()))}{_RESET}\n", file=sys.stderr)
            sys.exit(1)

    data_a = _load_yaml(profiles[name_a]["path"])
    data_b = _load_yaml(profiles[name_b]["path"])

    print(f"\n  {_BOLD}Compare: {_GREEN}{name_a}{_RESET} vs {_CYAN}{name_b}{_RESET}\n")

    any_diff = False
    for section in _COMPARE_SECTIONS:
        val_a = data_a.get(section)
        val_b = data_b.get(section)

        if val_a == val_b:
            if val_a is not None:
                _print_same(section, val_a)
            continue

        any_diff = True
        _print_diff(section, val_a, val_b, name_a, name_b)

    # Check for keys in either profile not in _COMPARE_SECTIONS
    extra_keys = set()
    for k in data_a:
        if k not in _COMPARE_SECTIONS and not k.startswith("#") and k not in ("profile", "api_key_env", "signing_key_env", "tenant_id", "agent_id"):
            extra_keys.add(k)
    for k in data_b:
        if k not in _COMPARE_SECTIONS and not k.startswith("#") and k not in ("profile", "api_key_env", "signing_key_env", "tenant_id", "agent_id"):
            extra_keys.add(k)

    for k in sorted(extra_keys):
        val_a = data_a.get(k)
        val_b = data_b.get(k)
        if val_a != val_b:
            any_diff = True
            _print_diff(k, val_a, val_b, name_a, name_b)

    if not any_diff:
        print(f"  {_DIM}Profiles are identical.{_RESET}")

    print()


def _print_same(section: str, value: Any) -> None:
    """Print a section that's the same in both profiles."""
    if isinstance(value, dict):
        print(f"  {_DIM}  {section}: (identical){_RESET}")
    else:
        print(f"  {_DIM}  {section}: {value}{_RESET}")


def _print_diff(section: str, val_a: Any, val_b: Any, name_a: str, name_b: str) -> None:
    """Print a colored diff for one section."""
    print(f"  {_BOLD}{section}:{_RESET}")

    if isinstance(val_a, dict) and isinstance(val_b, dict):
        all_keys = sorted(set(list(val_a.keys()) + list(val_b.keys())))
        for k in all_keys:
            a = val_a.get(k)
            b = val_b.get(k)
            if a == b:
                print(f"    {_DIM}{k}: {a}{_RESET}")
            elif a is None:
                print(f"    {_CYAN}+ {k}: {b}{_RESET}  {_DIM}({name_b} only){_RESET}")
            elif b is None:
                print(f"    {_GREEN}- {k}: {a}{_RESET}  {_DIM}({name_a} only){_RESET}")
            else:
                print(f"    {_GREEN}  {k}: {a}{_RESET}  {_DIM}({name_a}){_RESET}")
                print(f"    {_CYAN}  {k}: {b}{_RESET}  {_DIM}({name_b}){_RESET}")
    else:
        if val_a is not None:
            print(f"    {_GREEN}{name_a}: {val_a}{_RESET}")
        else:
            print(f"    {_GREEN}{name_a}: {_DIM}(not set){_RESET}")
        if val_b is not None:
            print(f"    {_CYAN}{name_b}: {val_b}{_RESET}")
        else:
            print(f"    {_CYAN}{name_b}: {_DIM}(not set){_RESET}")


def handle_profile(args: List[str]) -> None:
    """Dispatch for `swt3 profile <subcommand>`."""
    subcmd = args[0] if args else "list"

    if subcmd == "list":
        handle_profile_list(args[1:])
    elif subcmd == "show":
        handle_profile_show(args[1:])
    elif subcmd == "compare":
        handle_profile_compare(args[1:])
    elif subcmd in ("--help", "-h", "help"):
        print(f"\n  {_BOLD}swt3 profile{_RESET}\n")
        print(f"    {_GREEN}list{_RESET}                  {_DIM}List all available profiles{_RESET}")
        print(f"    {_GREEN}show <name>{_RESET}            {_DIM}Show full YAML of a profile{_RESET}")
        print(f"    {_GREEN}compare <a> <b>{_RESET}        {_DIM}Colored diff of two profiles{_RESET}")
        print()
    else:
        # Maybe they meant "show <name>"
        profiles = {p["name"]: p for p in _get_profiles()}
        if subcmd in profiles:
            handle_profile_show(args)
        else:
            print(f"\n  {_RED}Unknown subcommand:{_RESET} {_BOLD}{subcmd}{_RESET}", file=sys.stderr)
            print(f"  Usage: {_BOLD}swt3 profile [list|show|compare]{_RESET}\n", file=sys.stderr)
            sys.exit(1)
