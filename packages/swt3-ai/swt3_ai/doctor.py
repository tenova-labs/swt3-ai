"""SWT3 Doctor -- diagnostic checks for config health."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .schema import validate_schema

VERSION = "0.5.2"


@dataclass
class DoctorCheck:
    name: str
    status: str  # "pass" | "warn" | "fail"
    message: str
    tip: str = ""


def _find_config_path() -> Optional[str]:
    for name in ("swt3.yaml", ".swt3.yaml"):
        if Path(name).is_file():
            return name
    return None


def _check_yaml_found() -> DoctorCheck:
    path = _find_config_path()
    if path:
        return DoctorCheck("Config file", "pass", f"./{path}")
    return DoctorCheck("Config file", "fail", "not found", tip="Run: swt3 init")


def _check_yaml_valid(path: str) -> DoctorCheck:
    try:
        import yaml
        with open(path, "r") as f:
            raw = yaml.safe_load(f)
        if not isinstance(raw, dict):
            return DoctorCheck("YAML syntax", "fail", "not a valid YAML mapping")
        return DoctorCheck("YAML syntax", "pass", "valid")
    except Exception as e:
        return DoctorCheck("YAML syntax", "fail", str(e))


def _check_env_vars(path: str) -> DoctorCheck:
    try:
        import yaml
        with open(path, "r") as f:
            raw = yaml.safe_load(f)
        missing = []
        if raw.get("api_key_env"):
            var_name = raw["api_key_env"]
            if not os.environ.get(var_name):
                missing.append(var_name)
        if raw.get("signing_key_env"):
            var_name = raw["signing_key_env"]
            if not os.environ.get(var_name):
                missing.append(var_name)

        if not missing and not raw.get("api_key_env") and not raw.get("api_key"):
            return DoctorCheck("Environment", "pass", "local mode (no api_key configured)")
        if missing:
            return DoctorCheck(
                "Environment", "warn",
                f"{', '.join(missing)} not set",
                tip=f"export {missing[0]}=axm_... (get a free key at https://sovereign.tenova.io/signup)",
            )
        return DoctorCheck("Environment", "pass", "all env vars resolved")
    except Exception:
        return DoctorCheck("Environment", "warn", "could not parse config")


def _check_profile(path: str) -> DoctorCheck:
    try:
        import yaml
        with open(path, "r") as f:
            raw = yaml.safe_load(f)
        profile = raw.get("profile")
        if not profile:
            return DoctorCheck("Profile", "pass", "none (custom config)")
        valid = {"eu-ai-act-high-risk", "nist-ai-rmf", "minimal"}
        if profile in valid:
            return DoctorCheck("Profile", "pass", profile)
        return DoctorCheck("Profile", "fail", f"unknown: {profile}")
    except Exception:
        return DoctorCheck("Profile", "warn", "could not parse")


def _check_sections(path: str) -> DoctorCheck:
    try:
        import yaml
        with open(path, "r") as f:
            raw = yaml.safe_load(f)
        result = validate_schema(raw)
        if result.valid:
            sections = [
                s for s in ("policy", "trust_mesh", "hardware", "density_policy", "mcp_policy", "merkle")
                if s in raw
            ]
            return DoctorCheck(
                "Sections", "pass",
                ", ".join(sections) if sections else "none configured",
            )
        first = result.errors[0]
        return DoctorCheck("Sections", "fail", f"{first.path}: {first.message}")
    except Exception:
        return DoctorCheck("Sections", "warn", "could not validate")


def _check_extends(path: str) -> DoctorCheck:
    try:
        import yaml
        with open(path, "r") as f:
            raw = yaml.safe_load(f)
        ext = raw.get("extends")
        if not ext:
            return DoctorCheck("Extends", "pass", "none")
        files = ext if isinstance(ext, list) else [ext]
        config_dir = Path(path).resolve().parent
        missing = []
        for f in files:
            resolved = Path(f) if Path(f).is_absolute() else config_dir / f
            if not resolved.is_file():
                missing.append(f)
        if missing:
            return DoctorCheck("Extends", "fail", f"missing: {', '.join(missing)}")
        return DoctorCheck("Extends", "pass", f"{len(files)} file(s) resolved")
    except Exception:
        return DoctorCheck("Extends", "warn", "could not check")


def _check_tpm(config_path: Optional[str] = None) -> DoctorCheck:
    import shutil

    require_attestation = False
    if config_path:
        try:
            import yaml as _yaml
            raw = _yaml.safe_load(Path(config_path).read_text())
            hw = raw.get("hardware") if isinstance(raw, dict) else None
            require_attestation = isinstance(hw, dict) and hw.get("require_attestation") is True
        except Exception:
            pass

    if sys.platform != "linux":
        if require_attestation:
            return DoctorCheck("Hardware", "warn", f"{sys.platform} (TPM required but not Linux)")
        return DoctorCheck("Hardware", "pass", f"{sys.platform} (TPM not required)")

    has_dev = Path("/dev/tpm0").exists()
    has_tools = shutil.which("tpm2_pcrread") is not None

    if has_dev and has_tools:
        return DoctorCheck("Hardware", "pass", "/dev/tpm0 + tpm2-tools detected")
    if not require_attestation:
        return DoctorCheck("Hardware", "pass", "not required")
    if has_dev:
        return DoctorCheck("Hardware", "warn", "/dev/tpm0 detected, tpm2-tools missing")
    return DoctorCheck("Hardware", "warn", "TPM required but /dev/tpm0 not detected")


def _check_runtime_profile(config_path: str) -> DoctorCheck:
    try:
        import yaml as _yaml
        raw = _yaml.safe_load(Path(config_path).read_text())
        hw = raw.get("hardware") if isinstance(raw, dict) else None
        if not isinstance(hw, dict) or "runtime_profile" not in hw:
            return DoctorCheck("Runtime Profile", "pass", "not configured (optional)")
        rp = hw["runtime_profile"]
        valid = {"expected_topology", "min_gpu_count", "min_memory_mb", "expected_accelerator", "max_temperature_celsius", "max_power_watts"}
        fields = [k for k in rp if k in valid]
        return DoctorCheck("Runtime Profile", "pass", f"{len(fields)} constraint(s): {', '.join(fields)}")
    except Exception:
        return DoctorCheck("Runtime Profile", "warn", "could not parse config")


def _check_mcp_config() -> DoctorCheck:
    val = os.environ.get("SWT3_CONFIG_FILE")
    if val:
        return DoctorCheck("MCP", "pass", f"SWT3_CONFIG_FILE={val}")
    return DoctorCheck("MCP", "pass", "not configured (optional)")


def run_doctor_checks(config_path: Optional[str] = None) -> List[DoctorCheck]:
    checks: List[DoctorCheck] = []

    if config_path:
        if Path(config_path).is_file():
            checks.append(DoctorCheck("Config file", "pass", config_path))
            path: Optional[str] = config_path
        else:
            checks.append(DoctorCheck("Config file", "fail", f"not found: {config_path}", tip="Run: swt3 init"))
            return checks
    else:
        yaml_check = _check_yaml_found()
        checks.append(yaml_check)
        path = yaml_check.message.replace("./", "") if yaml_check.status == "pass" else None

    if not path:
        return checks

    checks.append(_check_yaml_valid(path))
    checks.append(_check_env_vars(path))
    checks.append(_check_profile(path))
    checks.append(_check_sections(path))
    checks.append(_check_extends(path))
    checks.append(_check_tpm(path))
    checks.append(_check_runtime_profile(path))
    checks.append(_check_mcp_config())

    return checks


def print_doctor_results(checks: List[DoctorCheck], use_json: bool = False, ci_mode: bool = False) -> None:
    if use_json:
        import json as json_mod
        print(json_mod.dumps([{"name": c.name, "status": c.status, "message": c.message, "tip": c.tip} for c in checks], indent=2))
        return

    p = sum(1 for c in checks if c.status == "pass")
    w = sum(1 for c in checks if c.status == "warn")
    fl = sum(1 for c in checks if c.status == "fail")

    if ci_mode:
        for check in checks:
            tag = check.status.upper()
            print(f"[{tag}] {check.name}: {check.message}")
            if check.tip:
                print(f"  Tip: {check.tip}")
        print(f"swt3-doctor: {len(checks)} checks, {p} pass, {w} warn, {fl} fail")
        return

    print(f"\n  SWT3 Doctor v{VERSION}\n")

    icons = {"pass": "\033[32m[PASS]\033[0m", "warn": "\033[33m[WARN]\033[0m", "fail": "\033[31m[FAIL]\033[0m"}

    for check in checks:
        icon = icons.get(check.status, "[????]")
        print(f"  {icon} {check.name}: {check.message}")
        if check.tip:
            print(f"         Tip: {check.tip}")

    print(f"\n  {p} passed, {w} warnings, {fl} failures\n")

    print("  \033[33mNew in v0.5.2:\033[0m Trust Mesh -- agents verify each other before exchanging data.")
    print("  Configure: \033[36mswt3 init --profile eu-ai-act-high-risk\033[0m")
    print("  Docs: https://www.npmjs.com/package/@tenova/swt3-mcp\n")


# ── Friction Test ───────────────────────────────────────────────────────

@dataclass
class FrictionStep:
    name: str = ""
    status: str = "pass"
    duration_ms: int = 0
    error: Optional[str] = None


def run_friction_test() -> List[FrictionStep]:
    import tempfile
    import time
    import shutil

    steps: List[FrictionStep] = []
    tmp_dir = tempfile.mkdtemp(prefix="swt3-friction-")
    config_path = os.path.join(tmp_dir, "swt3.yaml")

    def step(name: str, fn):
        start = time.monotonic()
        try:
            fn()
            steps.append(FrictionStep(name=name, status="pass",
                duration_ms=int((time.monotonic() - start) * 1000)))
        except Exception as e:
            steps.append(FrictionStep(name=name, status="fail",
                duration_ms=int((time.monotonic() - start) * 1000), error=str(e)))

    # 1. Config discovery
    def _config():
        with open(config_path, "w") as f:
            f.write("\n".join([
                "clearing_level: 1",
                "tenant_id: FRICTION_TEST",
                "agent_id: test-agent",
                "api_key: test_key_friction",
                "mcp_policy:",
                "  tool_blocklist: [\"dangerous_tool\"]",
                "  max_tokens_per_session: 500",
                "  fail_secure: true",
            ]))
        if not os.path.exists(config_path):
            raise ValueError("Config file not created")
    step("Config discovery", _config)

    # 2. fromConfig loads
    def _load():
        from .config import load_full_config
        loaded = load_full_config(config_path)
        if not loaded.mcp_policy:
            raise ValueError("mcp_policy not parsed")
        if not loaded.mcp_policy.tool_blocklist:
            raise ValueError("tool_blocklist empty")
    step("from_config() loads", _load)

    # 3. ChainEnforcer created
    def _enforcer():
        from .witness import ChainEnforcer
        from .types import McpPolicyConfig
        enforcer = ChainEnforcer(McpPolicyConfig(
            tool_blocklist=["dangerous_tool"], fail_secure=True,
        ))
        result = enforcer.check("safe_tool")
        if result is not None:
            raise ValueError("Safe tool was blocked")
    step("ChainEnforcer created", _enforcer)

    # 4. Blocklist enforcement
    def _blocklist():
        from .witness import ChainEnforcer
        from .types import McpPolicyConfig
        enforcer = ChainEnforcer(McpPolicyConfig(
            tool_blocklist=["dangerous_tool"], fail_secure=True,
        ))
        v = enforcer.check("dangerous_tool")
        if not v:
            raise ValueError("Blocklist did not trigger")
        if v.action != "blocked":
            raise ValueError("Action should be blocked")
    step("Blocklist enforcement", _blocklist)

    # 5. Token budget enforcement
    def _tokens():
        from .witness import ChainEnforcer
        from .types import McpPolicyConfig
        enforcer = ChainEnforcer(McpPolicyConfig(
            max_tokens_per_session=100, fail_secure=True,
        ))
        enforcer.record_tokens(150)
        v = enforcer.check("any_tool")
        if not v:
            raise ValueError("Token budget did not trigger")
        if v.rule != "token_budget":
            raise ValueError(f"Wrong rule: {v.rule}")
    step("Token budget enforcement", _tokens)

    # 6. Audit report generation
    def _audit():
        from .exporters.chain_monitor import ChainMonitorExporter
        exporter = ChainMonitorExporter(wal_dir=tmp_dir, tenant_id="FRICTION_TEST")
        html_out = exporter.export_html()
        if "SWT3 Exploit Chain Monitor" not in html_out:
            raise ValueError("HTML missing title")
        if "Self-Signed" not in html_out:
            raise ValueError("HTML missing watermark")
    step("Audit report generation", _audit)

    # 7. Error message clarity
    def _errors():
        from .witness import PolicyViolationError
        from .types import ChainPolicyViolation
        v = ChainPolicyViolation(
            rule="blocklist", tool_name="dangerous_tool", action="blocked",
            reason='Tool "dangerous_tool" is on the blocklist', timestamp=0.0,
        )
        err = PolicyViolationError(v)
        if "dangerous_tool" not in str(err):
            raise ValueError("Error missing tool name")
        if "blocklist" not in str(err):
            raise ValueError("Error missing reason")
    step("Error message clarity", _errors)

    try:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    except Exception:
        pass

    return steps


def print_friction_results(steps: List[FrictionStep]) -> None:
    print(f"\n  SWT3 Friction Test v{VERSION}\n")
    for i, s in enumerate(steps):
        icon = "\033[32mPASS\033[0m" if s.status == "pass" else "\033[31mFAIL\033[0m"
        dots = "." * max(1, 36 - len(s.name))
        print(f"  {i + 1}. {s.name} {dots} {icon}  ({s.duration_ms}ms)")
        if s.error:
            print(f"     \033[31m{s.error}\033[0m")
    passed = sum(1 for s in steps if s.status == "pass")
    total_ms = sum(s.duration_ms for s in steps)
    print(f"\n  {passed}/{len(steps)} passed. Total: {total_ms}ms.\n")
