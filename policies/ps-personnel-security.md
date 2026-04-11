# Personnel Security Policy

**Policy Identifier:** PS-1.1
**NIST 800-53 Control:** PS-1 — Personnel Security Policy and Procedures
**CMMC v2.0 Practice:** PS.L2-3.9.2
**Effective Date:** 2026-03-16
**Review Cycle:** Annual (or upon significant organizational change)
**Classification:** CUI / FOUO

---

## 1. Purpose

This policy establishes the personnel security requirements for TeNova Axiom to ensure that individuals who access organizational information systems and data are trustworthy, meet established security criteria, and are aware of their security responsibilities. This policy implements the requirements of NIST SP 800-53 Rev 5, PS family controls (PS-1 through PS-8).

## 2. Scope

This policy applies to all employees, contractors, subcontractors, and third parties who access TeNova Axiom information systems, process Controlled Unclassified Information (CUI), or operate within the authorization boundary of any system governed by NIST 800-53 or CMMC v2.0.

## 3. Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| **Authorizing Official (AO)** | Approves personnel security policy; reviews annually |
| **Information System Security Officer (ISSO)** | Enforces screening, access, and termination procedures |
| **Human Resources (HR)** | Conducts background investigations; manages onboarding/offboarding |
| **System Administrators** | Provisions and revokes system access per HR direction |
| **Chief Information Security Officer (CISO)** | Designated policy owner; ensures compliance and audit readiness |

## 4. Policy Statements

### 4.1 Personnel Screening (PS-3)

All individuals requiring access to TeNova Axiom information systems shall undergo a background investigation commensurate with the sensitivity of the position and the classification of information accessed.

- **Tier 1 (Public Trust):** National Agency Check with Inquiries (NACI) or equivalent for all CUI-handling positions.
- **Tier 3 (Secret):** Background Investigation (BI) for positions requiring access to classified systems or environments.
- Screening shall be completed and adjudicated **prior to granting system access**.
- Re-investigation shall occur every 5 years or upon cause.

### 4.2 Personnel Termination (PS-4)

Upon termination of employment or contract, TeNova Axiom shall:

- Revoke all system access within **24 hours** of separation.
- Retrieve all organizational assets (laptops, badges, tokens, keys).
- Conduct an exit interview addressing ongoing security obligations.
- Disable accounts via the organization's identity management system.
- Notify the ISSO within **4 business hours** of any involuntary termination.

**Technical Enforcement:** Account deactivation is verified by the Axiom Sovereign Engine via control AC-2.1 (Empty Password Accounts) and AC-2.3 (Inactive System Accounts). Disabled accounts that remain on the system are automatically detected and flagged.

### 4.3 Personnel Transfer (PS-5)

When personnel transfer between roles within TeNova Axiom:

- Access rights shall be reviewed and adjusted within **5 business days**.
- Previous role-specific access shall be revoked before new access is granted (separation of duties per AC-5.1).
- The ISSO shall verify that no privilege escalation occurs as a result of the transfer.

### 4.4 Access Agreements (PS-6)

All personnel shall sign the following prior to system access:

- Acceptable Use Agreement (AUA)
- Non-Disclosure Agreement (NDA)
- Rules of Behavior (cross-reference: PL-4.1)

Agreements shall be reviewed and re-signed annually.

### 4.5 Third-Party Personnel Security (PS-7)

Third-party personnel (contractors, subcontractors, managed service providers) are subject to the same screening and access control requirements as TeNova Axiom employees. Additionally:

- Third-party access shall be documented in the system security plan.
- Contracts shall include security clauses per SA-4.1 (Acquisition Process).
- Third-party accounts shall be reviewed quarterly by the ISSO.

## 5. Technical Verification

Compliance with this policy is continuously verified through the **TeNova Axiom Sovereign Engine**. The following automated controls provide ongoing assurance:

| Control | Verification | Method |
|---------|-------------|--------|
| AC-2.1 | No accounts with empty passwords | Automated scan of /etc/shadow |
| AC-2.2 | Only root has UID 0 | Automated scan of /etc/passwd |
| AC-2.3 | Inactive accounts within threshold | Automated enumeration of login shells |
| AC-5.1 | Root direct login restricted | SSH configuration verification |
| AC-6.1 | Sudoers within least-privilege threshold | Sudoers file enumeration |
| AU-12.1 | Audit trail active for personnel actions | Auditd service verification |
| IA-2.1 | Multi-factor or key-based authentication | SSH key auth verification |

All verification results are recorded as **SWT3 Witness Anchors** in the Compliance Ledger with SHA-256 cryptographic fingerprints, providing tamper-evident proof of continuous compliance.

## 6. Enforcement

Violations of this policy may result in:

- Immediate suspension of system access
- Disciplinary action up to and including termination
- Referral to law enforcement for criminal violations
- Reporting to the contracting officer for contract-related breaches

## 7. Review and Maintenance

This policy shall be reviewed **annually** by Chief Information Security Officer (CISO) and updated as necessary to reflect changes in organizational structure, regulatory requirements, or threat landscape. All reviews and updates are witnessed into the Axiom Compliance Ledger under control PS-1.1.

---

**Approved By:** ________________________________________
**Title:** Authorizing Official
**Date:** ________________________________________
