# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the SWT3 Protocol, any of the SDKs, or the Axiom Sovereign Engine, please report it responsibly.

**Email:** security@tenovaai.com

**What to include:**
- Description of the vulnerability
- Steps to reproduce
- Affected component (swt3-ai, @tenova/swt3-ai, @tenova/libswt3, or protocol spec)
- Impact assessment (if known)

**Response timeline:**
- Acknowledgment within 48 hours
- Initial assessment within 5 business days
- Fix or mitigation plan within 30 days for confirmed vulnerabilities

## Scope

The following are in scope for security reports:

- SWT3 fingerprint formula integrity
- Clearing engine data leakage (fields appearing at higher clearing levels than specified)
- Cross-language parity failures (Python and TypeScript producing different outputs from identical inputs)
- Authentication or authorization bypass in the Axiom dashboard or API
- Dependency vulnerabilities in shipped packages

## Out of Scope

- Vulnerabilities in third-party AI providers (OpenAI, Anthropic, etc.)
- Social engineering attacks
- Denial of service against hosted infrastructure

## Supported Versions

| Package | Supported |
|---------|-----------|
| swt3-ai (Python) | Latest minor version |
| @tenova/swt3-ai (TypeScript) | Latest minor version |
| @tenova/libswt3 | Latest minor version |

## Responsible Disclosure

We ask that you do not publicly disclose the vulnerability until we have had an opportunity to address it. We will credit reporters in the release notes unless anonymity is requested.
