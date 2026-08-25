# SWT3 Governance Gate - GitHub Action

Evaluate AI governance compliance gates in your CI/CD pipeline using SWT3 witness anchors.

## Usage

```yaml
- uses: tenova-labs/swt3-gate-action@v1
  with:
    api-key: ${{ secrets.SWT3_API_KEY }}
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api-key` | Yes | - | SWT3 API key (`axm_*`). Store as a GitHub secret. |
| `endpoint` | No | `https://sovereign.tenova.io` | SWT3 endpoint URL |
| `config-path` | No | auto-detect | Path to `.swt3-gate.yml` |
| `framework` | No | from config | Framework to evaluate |
| `strict` | No | `false` | Exit 1 on warnings |
| `sdk-version` | No | `0.6.5` | Pinned SDK version (supply chain safety) |
| `doctor` | No | `true` | Run config health check first |

## Outputs

| Output | Description |
|--------|-------------|
| `result` | `PASS` or `FAIL` |
| `procedures-checked` | Number of procedures evaluated |
| `summary` | Human-readable gate summary |

## Example: EU AI Act High-Risk Gate

```yaml
name: AI Governance Gate
on: [push, pull_request]

jobs:
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tenova-labs/swt3-gate-action@v1
        with:
          api-key: ${{ secrets.SWT3_API_KEY }}
          framework: EU-AI-ACT
          strict: true
```

## Supply Chain Safety

The `sdk-version` input pins the exact `@tenova/swt3-ai` version installed during the action run. This prevents supply chain attacks where a compromised latest version could exfiltrate secrets. Always pin to a known-good version.

## License

Apache-2.0. SWT3 is a trademark of Tenable Nova LLC. Patent pending.
