# SA-15: AI-Assisted Development Disclosure

## Control: Development Process, Standards, and Tools (SA-15)

### AI Engineering Assistant Usage

TeNova utilizes AI language models (specifically Anthropic Claude) as engineering assistants during the Axiom Sovereign Engine development lifecycle. AI assistance is applied to:

- **Probe Development**: Drafting YAML control definitions and shell commands for evidence collection
- **Code Drafting**: Generating TypeScript and Python modules for the dashboard and CLI
- **Documentation**: Drafting compliance narratives, policy templates, and technical documentation

### Verification Controls

All AI-generated artifacts undergo a three-layer validation pipeline before deployment:

1. **Shell Lint (Automated)**: Every probe command is validated through `shellcheck` static analysis to detect syntax errors, ghost flags, and non-standard constructs. Zero errors required for acceptance.

2. **XCCDF Cross-Check (Automated)**: Probe commands are compared against official DISA STIG check content parsed from XCCDF benchmark files. File path targets, threshold values, and configuration directives are cross-referenced. Discrepancies are flagged as drift findings requiring human review.

3. **Provenance Tracing (Automated + Human)**: Each probe carries traceability metadata linking it to the originating DISA Rule ID, CCI reference, and XCCDF check content SHA-256 hash. The provenance manifest (`config/probe_provenance.json`) provides a machine-verifiable chain from DISA Cyber Exchange source to deployed probe.

### Architectural Safeguards

The Axiom architecture inherently mitigates AI hallucination risk in the following ways:

- **Deterministic Adjudication**: The verdict engine evaluates `factor_b >= factor_a` (or similar rule expressions). The same inputs always produce the same verdict regardless of who authored the probe — human or AI. Probe authorship does not affect verdict integrity.

- **Read-Only Evidence Collection**: Probe commands only *read* system state (file contents, service status, kernel parameters). They do not modify the target system. A hallucinated command can produce an incorrect *reading*, but cannot alter the system.

- **Prescriptive Remediation**: Axiom prints remediation commands for the operator to review and execute manually. It does not auto-remediate. The human-in-the-loop is enforced at the remediation boundary.

- **Regression Baseline**: The `axiom scan --dry-run --all --json` output is deterministic. Any probe change that alters a verdict is detectable through baseline comparison.

### Version Control Identification

AI-assisted commits are identified via the `Co-Authored-By` Git trailer:

```
Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

The complete development history, including all AI-assisted changes, is preserved in the Git repository and available for audit review.

### Validation Toolkit

The probe validation pipeline is executable on demand:

```
python scripts/axiom-probe-validate.py --all
```

This produces a machine-readable report covering shell lint results, XCCDF cross-check findings, and provenance coverage. The report can be included in assessment evidence packages.

### AI System Boundaries

The AI engineering assistant:
- **Does NOT** have access to production systems or customer environments
- **Does NOT** have access to the adjudication pipeline or verdict engine at runtime
- **Does NOT** have access to customer data, API keys, or credentials
- **Does NOT** execute remediation commands on target systems
- **Is NOT** involved in the real-time scan → adjudicate → witness pipeline

### Applicable Standards

- NIST SP 800-218 (SSDF) — PW.1.1: Provenance of software components
- NIST SP 800-218 (SSDF) — PW.7.2: Verify software meets requirements
- NIST SP 800-53 Rev 5 — SA-15: Development Process, Standards, and Tools
- CMMC 2.0 — 3.4 family: Configuration Management (development tooling)
