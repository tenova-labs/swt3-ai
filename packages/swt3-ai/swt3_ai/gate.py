"""SWT3 Governance Gate configuration parser and CLI handler.

Parses .swt3-gate.yml files into typed data structures for policy evaluation.
The gate YAML is the Rosetta Stone between developer and assessor: framework-derived
compliance policy with developer overrides, organized by regulatory article.

Spec version: 1.0 (locked after 2 red team passes, July 24 2026)
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("swt3.gate")

_GATE_FILENAMES = [".swt3-gate.yml", "swt3-gate.yml", ".swt3-gate.yaml", "swt3-gate.yaml"]

_VALID_TOP_LEVEL_KEYS = {"version", "name", "strict", "metadata", "models", "defaults", "frameworks"}

_MAX_AGE_PATTERN = re.compile(r"^(\d+)\s*(d|h|m)$", re.IGNORECASE)

_MAX_AGE_MULTIPLIERS = {"d": 86400, "h": 3600, "m": 60}


@dataclass
class GateProcedure:
    """A single procedure gate entry."""
    procedure: str
    required: bool = False
    max_age: Optional[str] = None
    max_age_seconds: Optional[int] = None
    ref: Optional[str] = None
    critical: bool = False
    description: Optional[str] = None
    hint: Optional[str] = None
    must_not_exist: bool = False


@dataclass
class GateGroup:
    """A group of procedures organized by article/control."""
    group: str
    procedures: List[GateProcedure] = field(default_factory=list)


@dataclass
class FrameworkGate:
    """Per-framework gate configuration."""
    risk_class: Optional[str] = None
    crosswalk_hash: Optional[str] = None
    gates: List[GateGroup] = field(default_factory=list)


@dataclass
class GateModel:
    """Model configuration within the gate."""
    risk: Optional[str] = None


@dataclass
class GateDefaults:
    """Default gates that apply to all listed models."""
    gates: List[GateProcedure] = field(default_factory=list)


@dataclass
class GateConfig:
    """Parsed .swt3-gate.yml configuration."""
    version: str
    name: Optional[str] = None
    strict: bool = False
    metadata: Optional[Dict[str, Any]] = None
    models: Dict[str, GateModel] = field(default_factory=dict)
    defaults: Optional[GateDefaults] = None
    frameworks: Dict[str, FrameworkGate] = field(default_factory=dict)
    source_path: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


def find_gate_file(path: Optional[str] = None) -> Optional[str]:
    """Search for a gate config file.

    If path is provided, use it directly. Otherwise search cwd and parent
    dirs for .swt3-gate.yml or swt3-gate.yml.
    """
    if path:
        p = Path(path)
        if p.is_file():
            return str(p.resolve())
        return None

    current = Path.cwd()
    for _ in range(10):  # max 10 levels up
        for name in _GATE_FILENAMES:
            candidate = current / name
            if candidate.is_file():
                return str(candidate.resolve())
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def parse_max_age(age_str: str) -> int:
    """Convert a max_age string to seconds.

    Supported formats: 1d, 7d, 14d, 30d, 90d, 24h, 1h, 30m
    """
    m = _MAX_AGE_PATTERN.match(age_str.strip())
    if not m:
        raise ValueError(f"Invalid max_age format: {age_str!r}. Use Nd, Nh, or Nm (e.g., 7d, 24h, 30m)")
    value = int(m.group(1))
    unit = m.group(2).lower()
    return value * _MAX_AGE_MULTIPLIERS[unit]


def _parse_procedure(raw: Dict[str, Any]) -> GateProcedure:
    """Parse a single procedure entry from YAML dict."""
    proc = raw.get("procedure")
    if not proc or not isinstance(proc, str):
        raise ValueError(f"Gate procedure entry missing 'procedure' field: {raw}")

    max_age_str = raw.get("max_age")
    max_age_seconds = None
    if max_age_str and isinstance(max_age_str, str):
        max_age_seconds = parse_max_age(max_age_str)

    return GateProcedure(
        procedure=proc,
        required=bool(raw.get("required", False)),
        max_age=max_age_str,
        max_age_seconds=max_age_seconds,
        ref=raw.get("ref"),
        critical=bool(raw.get("critical", False)),
        description=raw.get("description"),
        hint=raw.get("hint"),
        must_not_exist=bool(raw.get("must_not_exist", False)),
    )


def _parse_gates(raw_gates: Any, warnings: List[str]) -> List[GateGroup]:
    """Parse gates section -- supports both grouped and flat formats."""
    if not raw_gates or not isinstance(raw_gates, list):
        return []

    groups: List[GateGroup] = []
    flat_procedures: List[GateProcedure] = []

    for item in raw_gates:
        if not isinstance(item, dict):
            continue
        if "group" in item and "procedures" in item:
            # Grouped format
            procs = [_parse_procedure(p) for p in item["procedures"] if isinstance(p, dict)]
            groups.append(GateGroup(group=item["group"], procedures=procs))
        elif "procedure" in item:
            # Flat format (no group wrapper)
            flat_procedures.append(_parse_procedure(item))

    # Wrap any flat procedures in an unnamed group
    if flat_procedures:
        groups.append(GateGroup(group="", procedures=flat_procedures))

    return groups


def load_gate_config(path: Optional[str] = None) -> GateConfig:
    """Load and validate a .swt3-gate.yml file.

    Returns a typed GateConfig with any warnings collected.
    Raises FileNotFoundError if no config file found.
    Raises ValueError for schema violations.
    """
    try:
        import yaml
    except ImportError:
        raise ImportError(
            "PyYAML is required for gate config parsing. "
            "Install with: pip install swt3-ai[yaml]"
        )

    file_path = find_gate_file(path)
    if not file_path:
        searched = path or ", ".join(_GATE_FILENAMES)
        raise FileNotFoundError(f"No gate config found. Searched for: {searched}")

    with open(file_path, "r") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError(f"Gate config must be a YAML mapping, got {type(raw).__name__}")

    return parse_gate_dict(raw, source_path=file_path)


def parse_gate_dict(raw: Dict[str, Any], source_path: Optional[str] = None) -> GateConfig:
    """Parse a gate config from a dict (useful for testing without files)."""
    warnings: List[str] = []

    # Version check
    version = raw.get("version")
    if not version:
        raise ValueError("Gate config missing required 'version' field")
    version = str(version)

    # Unknown keys
    unknown = set(raw.keys()) - _VALID_TOP_LEVEL_KEYS
    for key in sorted(unknown):
        warnings.append(f"Unknown top-level key: {key!r}")

    # Models
    models: Dict[str, GateModel] = {}
    raw_models = raw.get("models")
    if isinstance(raw_models, dict):
        for name, val in raw_models.items():
            if isinstance(val, dict):
                models[name] = GateModel(risk=val.get("risk"))
            else:
                models[name] = GateModel()

    # Defaults
    defaults = None
    raw_defaults = raw.get("defaults")
    if isinstance(raw_defaults, dict):
        raw_default_gates = raw_defaults.get("gates", [])
        default_procs = []
        if isinstance(raw_default_gates, list):
            for item in raw_default_gates:
                if isinstance(item, dict) and "procedure" in item:
                    default_procs.append(_parse_procedure(item))
        defaults = GateDefaults(gates=default_procs)

    # Frameworks
    frameworks: Dict[str, FrameworkGate] = {}
    raw_frameworks = raw.get("frameworks")
    if isinstance(raw_frameworks, dict):
        for fw_name, fw_val in raw_frameworks.items():
            if not isinstance(fw_val, dict):
                continue
            raw_fw_gates = fw_val.get("gates", [])
            parsed_gates = _parse_gates(raw_fw_gates, warnings)
            if not parsed_gates:
                warnings.append(f"Framework {fw_name!r} has no gates defined")
            frameworks[fw_name] = FrameworkGate(
                risk_class=fw_val.get("risk_class"),
                crosswalk_hash=fw_val.get("crosswalk_hash"),
                gates=parsed_gates,
            )

    return GateConfig(
        version=version,
        name=raw.get("name"),
        strict=bool(raw.get("strict", False)),
        metadata=raw.get("metadata") if isinstance(raw.get("metadata"), dict) else None,
        models=models,
        defaults=defaults,
        frameworks=frameworks,
        source_path=source_path,
        warnings=warnings,
    )


def validate_procedures(config: GateConfig, known_procedures: Set[str]) -> List[str]:
    """Validate procedure IDs against a known set. Returns warnings for unknown."""
    warnings: List[str] = []

    def _check(proc_id: str, context: str) -> None:
        if proc_id not in known_procedures:
            warnings.append(f"Unknown procedure {proc_id!r} in {context}")

    # Check defaults
    if config.defaults:
        for gp in config.defaults.gates:
            _check(gp.procedure, "defaults")

    # Check frameworks
    for fw_name, fw in config.frameworks.items():
        for group in fw.gates:
            for gp in group.procedures:
                _check(gp.procedure, f"frameworks.{fw_name}")

    return warnings


def all_procedures(config: GateConfig) -> List[Tuple[str, GateProcedure]]:
    """Extract all procedure entries with their framework context.

    Returns list of (framework_name_or_"defaults", GateProcedure) tuples.
    """
    result: List[Tuple[str, GateProcedure]] = []
    if config.defaults:
        for gp in config.defaults.gates:
            result.append(("defaults", gp))
    for fw_name, fw in config.frameworks.items():
        for group in fw.gates:
            for gp in group.procedures:
                result.append((fw_name, gp))
    return result


# ---------------------------------------------------------------------------
# Gate init generator
# ---------------------------------------------------------------------------

# Procedures that are typically critical for high-risk systems
_CRITICAL_PROCEDURES = {
    "AI-FAIR.1", "AI-FAIR.2", "AI-HITL.1", "AI-EXPL.1",
    "AI-GRD.1", "AI-SEC.1", "AI-AUDIT.1", "AI-SAFE.1",
}

# Default max_age recommendations by risk tier
_MAX_AGE_DEFAULTS = {
    "critical": "24h",
    "high": "7d",
    "medium": "30d",
    "low": "90d",
}

# Framework risk class defaults
_FRAMEWORK_RISK_CLASSES: Dict[str, str] = {
    "EU-AI-ACT": "high-risk",
    "SR-11-7": "model-risk",
    "NIST-AI-RMF": "moderate",
    "NIST-800-53": "moderate",
    "ISO-42001": "conformity",
    "FIVE-EYES-AGENTIC": "agentic",
    "OWASP-AGENTIC": "agentic",
    "GDPR": "data-protection",
}


def _get_procedure_hint(proc_id: str) -> Optional[str]:
    """Get SDK method hint for a procedure."""
    # Import lazily to avoid circular imports
    try:
        from .status import PROCEDURE_HINTS
        return PROCEDURE_HINTS.get(proc_id)
    except ImportError:
        return None


def _group_key(ref: str) -> str:
    """Extract article/section grouping key from a reference string.

    Examples: 'Art. 10(2)(f)' -> 'Art. 10', 'III.A' -> 'III', 'MEASURE 2.5' -> 'MEASURE 2'
    """
    import re
    # EU AI Act: Art. X(...)
    m = re.match(r"(Art\.\s*\d+)", ref)
    if m:
        return m.group(1)
    # Roman numeral sections: III.A -> III
    m = re.match(r"^([IVX]+)\b", ref)
    if m:
        return m.group(1)
    # NIST RMF: GOVERN 1.1 -> GOVERN 1, MEASURE 2.5 -> MEASURE 2
    m = re.match(r"^([A-Z]+\s+\d+)", ref)
    if m:
        return m.group(1)
    # ISO: A.8.4 -> A.8
    m = re.match(r"^(A\.\d+)", ref)
    if m:
        return m.group(1)
    # FE-15 -> FE
    m = re.match(r"^([A-Z]+)-", ref)
    if m:
        return m.group(1)
    return ref


# Human-readable group labels for common article patterns
_ARTICLE_LABELS: Dict[str, Dict[str, str]] = {
    "EU-AI-ACT": {
        "Art. 9": "Article 9: Risk Management",
        "Art. 10": "Article 10: Data Governance",
        "Art. 11": "Article 11: Technical Documentation",
        "Art. 12": "Article 12: Record-Keeping",
        "Art. 13": "Article 13: Transparency",
        "Art. 14": "Article 14: Human Oversight",
        "Art. 15": "Article 15: Accuracy, Robustness, Cybersecurity",
        "Art. 26": "Article 26: Deployer Obligations",
        "Art. 27": "Article 27: FRIA",
        "Art. 50": "Article 50: Transparency (GPAI)",
        "Art. 52": "Article 52: Transparency (Legacy)",
        "Art. 53": "Article 53: GPAI Obligations",
        "Art. 55": "Article 55: GPAI Systemic Risk",
        "Art. 72": "Article 72: Post-Market Monitoring",
    },
    "SR-11-7": {
        "II": "II: Board and Senior Management",
        "III": "III: Model Development and Implementation",
        "IV": "IV: Model Validation",
        "V": "V: Governance, Policies, and Controls",
    },
    "NIST-AI-RMF": {
        "GOVERN 1": "GOVERN 1: Policies and Procedures",
        "GOVERN 2": "GOVERN 2: Accountability",
        "GOVERN 3": "GOVERN 3: Workforce Diversity",
        "GOVERN 4": "GOVERN 4: Organizational Practices",
        "GOVERN 5": "GOVERN 5: Processes",
        "GOVERN 6": "GOVERN 6: Policies",
        "MAP 1": "MAP 1: Context",
        "MAP 2": "MAP 2: Categorize",
        "MAP 3": "MAP 3: Benefits and Costs",
        "MAP 5": "MAP 5: Impacts",
        "MEASURE 1": "MEASURE 1: Metrics",
        "MEASURE 2": "MEASURE 2: Evaluation",
        "MEASURE 3": "MEASURE 3: Tracking",
        "MEASURE 4": "MEASURE 4: Feedback",
        "MANAGE 1": "MANAGE 1: Risk Treatment",
        "MANAGE 2": "MANAGE 2: Risk Resources",
        "MANAGE 3": "MANAGE 3: Risk Responses",
        "MANAGE 4": "MANAGE 4: Risk Communication",
    },
}


def generate_gate_yaml(
    framework_id: str,
    name: Optional[str] = None,
    strict: bool = False,
) -> str:
    """Generate a .swt3-gate.yml from bundled crosswalk data.

    Groups procedures by regulatory article, includes descriptions/hints/refs,
    and sets recommended max_age based on risk classification.

    Args:
        framework_id: Framework identifier (e.g., 'EU-AI-ACT', 'SR-11-7')
        name: Optional policy name. Defaults to '<framework> Governance Policy'.
        strict: Whether to set strict mode (fail on ungoverned models).

    Returns:
        YAML string ready to write to .swt3-gate.yml

    Raises:
        ValueError: If the framework is not found in bundled crosswalks.
    """
    from .crosswalk import resolve_framework, frameworks, procedures, crosswalk_version

    fw_meta = frameworks().get(framework_id)
    if fw_meta is None:
        available = sorted(
            k for k, v in frameworks().items()
            if v.get("procedure_count", 0) > 0
        )
        raise ValueError(
            f"Unknown framework: {framework_id!r}. "
            f"Available: {', '.join(available)}"
        )

    all_procs = procedures()
    by_req = resolve_framework(framework_id)
    if not by_req:
        raise ValueError(f"Framework {framework_id!r} has no procedure mappings in bundled crosswalks.")

    risk_class = _FRAMEWORK_RISK_CLASSES.get(framework_id)
    policy_name = name or f"{fw_meta.get('name', framework_id)} Governance Policy"
    fw_labels = _ARTICLE_LABELS.get(framework_id, {})

    # Group procedures by article/section
    groups: Dict[str, List[Tuple[str, str, str]]] = {}  # group_key -> [(ref, proc_id, title)]
    seen_procs: Set[str] = set()
    for ref, proc_ids in sorted(by_req.items()):
        gk = _group_key(ref)
        if gk not in groups:
            groups[gk] = []
        for proc_id in sorted(proc_ids):
            if proc_id in seen_procs:
                continue
            seen_procs.add(proc_id)
            title = all_procs.get(proc_id, {}).get("title", proc_id)
            groups[gk].append((ref, proc_id, title))

    # Build YAML lines
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cw_ver = crosswalk_version()

    lines: List[str] = [
        f"# Generated by: swt3 gate --init --framework {framework_id}",
        f"# Crosswalk version: {cw_ver}",
        f"# Generated at: {now}",
        f"# Docs: https://sovereign.tenova.io/guides/developer-gate-config-guide.html",
        f"#",
        f"# Review and customize thresholds before committing to your repository.",
        f"# Run: swt3 gate --validate  to check this file.",
        "",
        'version: "1.0"',
        f'name: "{policy_name}"',
        f"strict: {'true' if strict else 'false'}",
        "",
        "metadata:",
        f'  generated_at: "{now}"',
        f'  crosswalk_version: "{cw_ver}"',
        f'  framework: "{framework_id}"',
        "",
        "models:",
        "  # Add your model IDs here:",
        "  # my-model-v1:",
        '  #   risk: "high"',
        "",
        "frameworks:",
        f"  {framework_id.lower()}:",
    ]

    if risk_class:
        lines.append(f'    risk_class: "{risk_class}"')

    lines.append("    gates:")

    for gk in sorted(groups.keys()):
        items = groups[gk]
        label = fw_labels.get(gk, gk)
        lines.append(f'      - group: "{label}"')
        lines.append("        procedures:")

        for ref, proc_id, title in items:
            is_critical = proc_id in _CRITICAL_PROCEDURES
            max_age = _MAX_AGE_DEFAULTS["critical"] if is_critical else _MAX_AGE_DEFAULTS["high"]
            hint = _get_procedure_hint(proc_id)

            lines.append(f"          - procedure: {proc_id}")
            lines.append(f'            ref: "{ref}"')
            lines.append(f'            description: "{title}"')
            lines.append(f"            required: true")
            lines.append(f"            max_age: {max_age}")
            if is_critical:
                lines.append(f"            critical: true")
            if hint:
                lines.append(f'            hint: "witness.{hint}()"')

    # Defaults section
    lines.extend([
        "",
        "defaults:",
        "  gates:",
        "    - procedure: AI-LOG.1",
        "      required: true",
        '      description: "Log completeness attestation"',
        "      max_age: 7d",
        "    - procedure: AI-AUDIT.1",
        "      required: true",
        '      description: "Audit trail integrity"',
        "      max_age: 7d",
    ])
    lines.append("")

    return "\n".join(lines)


def list_frameworks() -> List[Tuple[str, str, int]]:
    """Return available frameworks with procedure counts.

    Returns list of (framework_id, name, procedure_count) tuples.
    """
    from .crosswalk import frameworks
    result = []
    for fw_id, meta in sorted(frameworks().items()):
        count = meta.get("procedure_count", 0)
        if count > 0:
            result.append((fw_id, meta.get("name", fw_id), count))
    return result


# ---------------------------------------------------------------------------
# CLI handler
# ---------------------------------------------------------------------------

def _get_flag(args: List[str], flag: str) -> str:
    try:
        idx = args.index(flag)
        return args[idx + 1]
    except (ValueError, IndexError):
        return ""


def _count_gates(fw: FrameworkGate) -> Tuple[int, int]:
    """Return (total_gates, critical_gates) for a framework."""
    total = sum(len(g.procedures) for g in fw.gates)
    critical = sum(1 for g in fw.gates for p in g.procedures if p.critical)
    return total, critical


def _render_validate_text(config: GateConfig) -> None:
    """Render validate-mode output (human-readable)."""
    name = config.name or "(unnamed)"
    strict = "true" if config.strict else "false"
    print(f"\n  SWT3 Gate Config: {name}")
    print(f"  Version: {config.version} | Strict: {strict}")

    if config.models:
        models_str = ", ".join(
            f"{m} ({v.risk or 'unspecified'})" for m, v in config.models.items()
        )
        print(f"  Models: {models_str}")

    if config.frameworks:
        print(f"\n  Frameworks:")
        for fw_name, fw in config.frameworks.items():
            total, critical = _count_gates(fw)
            risk_str = f"  risk: {fw.risk_class}" if fw.risk_class else ""
            crit_str = f" ({critical} critical)" if critical else ""
            print(f"    {fw_name:<20} {total} gates{crit_str}{risk_str}")

    default_count = len(config.defaults.gates) if config.defaults else 0
    total_fw_gates = sum(
        sum(len(g.procedures) for g in fw.gates)
        for fw in config.frameworks.values()
    )
    total = total_fw_gates + default_count
    default_str = f" + {default_count} defaults" if default_count else ""
    print(f"\n  Total: {total_fw_gates} framework gates{default_str}")

    if config.source_path:
        print(f"  Source: {config.source_path}")
    print(f"  \033[32mConfig valid.\033[0m\n")


def _render_validate_json(config: GateConfig) -> None:
    """Render validate-mode output as JSON."""
    fw_summary = {}
    for fw_name, fw in config.frameworks.items():
        total, critical = _count_gates(fw)
        fw_summary[fw_name] = {
            "gates": total,
            "critical": critical,
            "risk_class": fw.risk_class,
        }

    result = {
        "valid": True,
        "version": config.version,
        "name": config.name,
        "strict": config.strict,
        "models": {m: {"risk": v.risk} for m, v in config.models.items()},
        "frameworks": fw_summary,
        "defaults": len(config.defaults.gates) if config.defaults else 0,
        "warnings": config.warnings,
        "source": config.source_path,
    }
    print(json.dumps(result, indent=2))


def _config_to_dict(config: GateConfig) -> Dict[str, Any]:
    """Convert parsed GateConfig back to a dict for API submission."""
    d: Dict[str, Any] = {"version": config.version}
    if config.name:
        d["name"] = config.name
    if config.strict:
        d["strict"] = True
    if config.metadata:
        d["metadata"] = config.metadata
    if config.models:
        d["models"] = {m: {"risk": v.risk} for m, v in config.models.items()}
    if config.defaults:
        d["defaults"] = {
            "gates": [
                {k: v for k, v in {
                    "procedure": g.procedure,
                    "required": g.required or None,
                    "max_age": g.max_age,
                    "critical": g.critical or None,
                    "must_not_exist": g.must_not_exist or None,
                }.items() if v is not None}
                for g in config.defaults.gates
            ]
        }
    if config.frameworks:
        fws: Dict[str, Any] = {}
        for fw_name, fw in config.frameworks.items():
            fw_dict: Dict[str, Any] = {}
            if fw.risk_class:
                fw_dict["risk_class"] = fw.risk_class
            if fw.crosswalk_hash:
                fw_dict["crosswalk_hash"] = fw.crosswalk_hash
            gates_list = []
            for group in fw.gates:
                g_dict: Dict[str, Any] = {}
                if group.group:
                    g_dict["group"] = group.group
                g_dict["procedures"] = [
                    {k: v for k, v in {
                        "procedure": p.procedure,
                        "required": p.required or None,
                        "max_age": p.max_age,
                        "critical": p.critical or None,
                        "ref": p.ref,
                        "description": p.description,
                        "hint": p.hint,
                        "must_not_exist": p.must_not_exist or None,
                    }.items() if v is not None}
                    for p in group.procedures
                ]
                gates_list.append(g_dict)
            fw_dict["gates"] = gates_list
            fws[fw_name] = fw_dict
        d["frameworks"] = fws
    return d


def _resolve_api_credentials() -> Tuple[str, str]:
    """Resolve API key and endpoint from config or environment."""
    api_key = os.environ.get("SWT3_API_KEY", "")
    endpoint = os.environ.get("SWT3_ENDPOINT", "https://sovereign.tenova.io")

    try:
        from .config import load_full_config
        loaded = load_full_config()
        kw = loaded.witness_kwargs
        if kw.get("api_key"):
            api_key = kw["api_key"]
        if kw.get("endpoint"):
            endpoint = kw["endpoint"]
    except Exception:
        pass

    return api_key, endpoint


def _evaluate_live(
    config: GateConfig,
    framework: str,
    model_id: Optional[str],
    use_json: bool,
) -> None:
    """POST config to /api/v1/gate/evaluate and render results."""
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError

    api_key, endpoint = _resolve_api_credentials()
    if not api_key:
        if use_json:
            print(json.dumps({"error": "No API key. Set SWT3_API_KEY or configure swt3.yaml"}))
        else:
            print("\n  \033[31mNo API key found.\033[0m", file=sys.stderr)
            print("  Set SWT3_API_KEY or add api_key to swt3.yaml", file=sys.stderr)
            print("  Use --validate for offline config validation.\n", file=sys.stderr)
        sys.exit(1)

    url = f"{endpoint.rstrip('/')}/api/v1/gate/evaluate"
    payload: Dict[str, Any] = {
        "config": _config_to_dict(config),
        "framework": framework,
    }
    if model_id:
        payload["model_id"] = model_id

    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    try:
        req = Request(url, data=body, headers=headers, method="POST")
        with urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        try:
            err_json = json.loads(err_body)
            msg = err_json.get("error", f"HTTP {e.code}")
        except Exception:
            msg = f"HTTP {e.code}: {err_body[:200]}"
        if use_json:
            print(json.dumps({"error": msg}))
        else:
            print(f"\n  \033[31mAPI error:\033[0m {msg}\n", file=sys.stderr)
        sys.exit(1)
    except URLError as e:
        if use_json:
            print(json.dumps({"error": f"Connection failed: {e.reason}"}))
        else:
            print(f"\n  \033[31mConnection failed:\033[0m {e.reason}", file=sys.stderr)
            print(f"  Endpoint: {endpoint}\n", file=sys.stderr)
        sys.exit(1)

    if use_json:
        print(json.dumps(result, indent=2))
        gate = result.get("gate", "FAIL")
        if gate == "FAIL":
            sys.exit(1)
        return

    # Render text output
    _render_evaluate_text(result)
    gate = result.get("gate", "FAIL")
    if gate == "FAIL":
        sys.exit(1)


def _render_evaluate_text(result: Dict[str, Any]) -> None:
    """Render gate evaluation results as human-readable text."""
    gate = result.get("gate", "UNKNOWN")
    summary = result.get("summary", {})
    results = result.get("results", [])
    warnings = result.get("warnings", [])
    ungoverned = result.get("ungoverned_models", [])

    gate_color = "\033[32m" if gate == "PASS" else "\033[33m" if gate == "WARN" else "\033[31m"
    gate_icon = "PASS" if gate == "PASS" else "WARN" if gate == "WARN" else "FAIL"

    fw = result.get("framework", "")
    model = result.get("model_id")
    name = result.get("config_name", "")

    print(f"\n  {gate_color}{gate_icon}\033[0m  {name or 'Gate Evaluation'}")
    print(f"  Framework: {fw}" + (f"  Model: {model}" if model else ""))
    print(f"  {summary.get('passed', 0)} passed, {summary.get('warned', 0)} warned, {summary.get('failed', 0)} failed" +
          (f", {summary.get('missing', 0)} missing" if summary.get('missing', 0) else ""))
    print()

    # Show results
    for r in results:
        proc = r.get("procedure", "")
        rgate = r.get("gate", "")
        reason = r.get("reason", "")
        ref = r.get("ref", "")
        group = r.get("group", "")

        if rgate == "PASS":
            icon = "\033[32m+\033[0m"
        elif rgate == "WARN":
            icon = "\033[33m~\033[0m"
        else:
            icon = "\033[31m-\033[0m"

        ref_str = f" ({ref})" if ref else ""
        print(f"  {icon} {proc:<16} {rgate:<5} {reason}{ref_str}")

    if ungoverned:
        print(f"\n  \033[31mUngoverned models:\033[0m {', '.join(ungoverned)}")

    for w in warnings:
        print(f"  \033[33mwarning:\033[0m {w}")

    config_hash = result.get("config_hash", "")
    if config_hash:
        print(f"\n  Config hash: {config_hash[:16]}...")

    print(f"  Portal: https://sovereign.tenova.io/command\n")


def _handle_init(args: List[str]) -> None:
    """Handle `swt3 gate --init`."""
    fw = _get_flag(args, "--framework")
    name = _get_flag(args, "--name") or None
    output = _get_flag(args, "--output") or ".swt3-gate.yml"
    strict = "--strict" in args
    use_json = "--json" in args
    force = "--force" in args

    if not fw:
        # List available frameworks
        fws = list_frameworks()
        if use_json:
            print(json.dumps([
                {"id": f, "name": n, "procedures": c} for f, n, c in fws
            ], indent=2))
        else:
            print("\n  Available frameworks for gate --init:\n")
            for fw_id, fw_name, count in fws:
                print(f"    {fw_id:<24} {count:>3} procedures  {fw_name}")
            print(f"\n  Usage: swt3 gate --init --framework EU-AI-ACT")
            print(f"         swt3 gate --init --framework SR-11-7 --output my-gate.yml\n")
        return

    try:
        yaml_content = generate_gate_yaml(fw, name=name, strict=strict)
    except ValueError as e:
        if use_json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"\n  \033[31mError:\033[0m {e}\n", file=sys.stderr)
        sys.exit(1)

    out_path = Path(output)
    if out_path.exists() and not force:
        if use_json:
            print(json.dumps({"error": f"{output} already exists. Use --force to overwrite."}))
        else:
            print(f"\n  \033[31m{output} already exists.\033[0m Use --force to overwrite.\n", file=sys.stderr)
        sys.exit(1)

    out_path.write_text(yaml_content, encoding="utf-8")

    if use_json:
        # Count gates for JSON output
        try:
            config = parse_gate_dict(
                __import__("yaml").safe_load(yaml_content),
                source_path=str(out_path.resolve()),
            )
            total = sum(
                sum(len(g.procedures) for g in fwg.gates)
                for fwg in config.frameworks.values()
            )
            print(json.dumps({
                "created": str(out_path),
                "framework": fw,
                "gates": total,
                "defaults": len(config.defaults.gates) if config.defaults else 0,
            }))
        except Exception:
            print(json.dumps({"created": str(out_path), "framework": fw}))
    else:
        print(f"\n  \033[32mCreated:\033[0m {output}")
        print(f"  Framework: {fw}")
        print(f"\n  Next steps:")
        print(f"    1. Add your model IDs to the 'models' section")
        print(f"    2. Review and adjust max_age thresholds")
        print(f"    3. Commit to your repository")
        print(f"    4. Run: swt3 gate --validate\n")


def handle_gate(args: List[str]) -> None:
    """CLI handler for `swt3 gate`."""
    # Handle --init before config loading
    if "--init" in args:
        _handle_init(args)
        return

    config_path = _get_flag(args, "--config") or None
    validate_only = "--validate" in args
    use_json = "--json" in args

    # Load and parse
    try:
        config = load_gate_config(config_path)
    except FileNotFoundError as e:
        if use_json:
            print(json.dumps({"valid": False, "error": str(e)}))
        else:
            print(f"\n  \033[31mGate config not found.\033[0m", file=sys.stderr)
            print(f"  Searched for: .swt3-gate.yml, swt3-gate.yml", file=sys.stderr)
            print(f"  Generate one: swt3 gate --init --framework eu-ai-act\n", file=sys.stderr)
        sys.exit(1)
    except (ValueError, ImportError) as e:
        if use_json:
            print(json.dumps({"valid": False, "error": str(e)}))
        else:
            print(f"\n  \033[31mGate config error:\033[0m {e}\n", file=sys.stderr)
        sys.exit(1)

    # Show parser warnings
    if not use_json:
        for w in config.warnings:
            print(f"  \033[33mwarning:\033[0m {w}")

    # Validate procedures against bundled registry
    try:
        from .crosswalk import procedures as _crosswalk_procedures
        known = set(_crosswalk_procedures().keys())
        proc_warnings = validate_procedures(config, known)
        if not use_json:
            for w in proc_warnings:
                print(f"  \033[33mwarning:\033[0m {w}")
        config.warnings.extend(proc_warnings)
    except Exception:
        pass  # crosswalk data not available, skip validation

    if validate_only:
        if use_json:
            _render_validate_json(config)
        else:
            _render_validate_text(config)
        return

    # Live evaluation mode -- POST config to API
    framework = _get_flag(args, "--framework") or None
    model_id = _get_flag(args, "--model") or None

    # Determine framework to evaluate
    if not framework:
        fw_keys = list(config.frameworks.keys())
        if len(fw_keys) == 1:
            framework = fw_keys[0]
        elif len(fw_keys) == 0:
            if use_json:
                print(json.dumps({"error": "No frameworks in config"}))
            else:
                print("\n  \033[31mNo frameworks defined in gate config.\033[0m\n", file=sys.stderr)
            sys.exit(1)
        else:
            if use_json:
                print(json.dumps({"error": f"Multiple frameworks. Use --framework: {', '.join(fw_keys)}"}))
            else:
                print(f"\n  \033[31mMultiple frameworks in config.\033[0m Use --framework to select:", file=sys.stderr)
                for k in fw_keys:
                    print(f"    swt3 gate --framework {k}", file=sys.stderr)
                print()
            sys.exit(1)

    _evaluate_live(config, framework, model_id, use_json)
