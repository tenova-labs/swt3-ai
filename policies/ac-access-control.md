# Access Control Policy

**Policy Identifier:** AC-1.1
**NIST 800-53 Control:** AC-1 — Access Control Policy and Procedures
**CMMC v2.0 Practice:** AC.L2-3.1.1
**Effective Date:** 2026-03-16
**Review Cycle:** Annual (or upon significant organizational change)
**Classification:** CUI / FOUO

---

## 1. Purpose

This policy establishes the access control requirements for TeNova Axiom to ensure that only authorized individuals have access to organizational information systems, that access is granted on a least-privilege basis, and that all access decisions are auditable. This policy implements the requirements of NIST SP 800-53 Rev 5, AC family controls (AC-1 through AC-25).

## 2. Scope

This policy applies to all information systems, network devices, applications, and data repositories within the TeNova Axiom authorization boundary, including cloud-hosted infrastructure, on-premises servers, and remote access endpoints.

## 3. Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| **Authorizing Official (AO)** | Approves access control policy; authorizes system operation |
| **Information System Security Officer (ISSO)** | Implements and monitors access controls |
| **System Administrators** | Configures accounts, permissions, and authentication mechanisms |
| **Users** | Comply with access control requirements; report anomalies |
| **Chief Information Security Officer (CISO)** | Designated policy owner; ensures compliance and audit readiness |

## 4. Policy Statements

### 4.1 Account Management (AC-2)

TeNova Axiom shall manage information system accounts through a formal process that includes:

- **Account creation** requires documented authorization from the account owner's supervisor and the ISSO.
- **Account modification** requires re-authorization when access levels change.
- **Account termination** follows the personnel termination procedure (PS-4) with system access revoked within 24 hours.
- **Periodic review** of all accounts shall occur quarterly. Inactive accounts (no login within 90 days) shall be disabled.

**Technical Enforcement:**
- AC-2.1: Zero accounts with empty passwords (continuously scanned)
- AC-2.2: Only the root account has UID 0 (continuously scanned)
- AC-2.3: Interactive accounts within the organizational threshold (continuously scanned)

### 4.2 Access Enforcement (AC-3)

The organization shall enforce approved authorizations for logical access to information systems in accordance with applicable access control policies. All access control decisions are:

- Based on role-based access control (RBAC) principles
- Enforced at the operating system, application, and network layers
- Logged and available for audit

### 4.3 Information Flow Enforcement (AC-4)

TeNova Axiom shall enforce controls on information flow between network segments:

- IP forwarding shall be disabled on all hosts except designated routers (AC-4.1).
- Network segmentation shall isolate CUI-processing systems from general-purpose networks.

### 4.4 Separation of Duties (AC-5)

The organization shall enforce separation of duties through:

- Restriction of direct root login (AC-5.1) — administrative actions require individual accountability via sudo.
- Separation of system administration, audit, and operational roles.

### 4.5 Least Privilege (AC-6)

Access rights shall be limited to the minimum necessary for job functions:

- Sudoers entries shall be reviewed and minimized (AC-6.1).
- SUID binaries shall be reduced to essential system utilities (AC-6.2).
- SGID binaries shall be audited and unnecessary instances removed (AC-6.3).

### 4.6 Unsuccessful Logon Attempts (AC-7)

The organization shall enforce account lockout after **5 consecutive failed login attempts** with a lockout duration of **15 minutes** (AC-7.1).

### 4.7 System Use Notification (AC-8)

A login banner shall be displayed before authentication that notifies users of authorized use requirements and monitoring (AC-8.1).

### 4.8 Session Management (AC-11, AC-12)

- SSH sessions shall timeout after **5 minutes** of inactivity (AC-11.1).
- All idle sessions shall be terminated to prevent unauthorized access.

### 4.9 Remote Access (AC-17)

Remote access shall be permitted only via SSH Protocol 2 with public key authentication (AC-17.1). VPN access, where required, shall use FIPS-validated encryption.

## 5. Technical Verification

Compliance with this policy is continuously verified through the **TeNova Axiom Sovereign Engine**. The following controls are scanned automatically:

| Control | What It Verifies | STIG Severity |
|---------|-----------------|---------------|
| AC-2.1 | No empty password accounts | CAT I |
| AC-2.2 | Only root has UID 0 | CAT I |
| AC-2.3 | Interactive accounts within threshold | CAT II |
| AC-3.1 | No world-writable files in /etc | CAT II |
| AC-4.1 | IP forwarding disabled | CAT II |
| AC-5.1 | Root direct login restricted | CAT II |
| AC-6.1 | Sudoers within threshold | CAT II |
| AC-6.2 | SUID binaries within threshold | CAT I |
| AC-6.3 | SGID binaries within threshold | CAT II |
| AC-7.1 | Account lockout configured | CAT II |
| AC-8.1 | Login banner present | CAT III |
| AC-11.1 | SSH idle timeout configured | CAT II |
| AC-17.1 | SSH Protocol 2 enforced | CAT I |

All results are recorded as **SWT3 Witness Anchors** with SHA-256 fingerprints in the Compliance Ledger, providing tamper-evident proof of continuous technical enforcement.

## 6. Enforcement

Violations of this policy may result in immediate suspension of system access, disciplinary action, or referral to law enforcement. Repeated violations shall be escalated to the Authorizing Official.

## 7. Review and Maintenance

This policy shall be reviewed **annually** by Chief Information Security Officer (CISO) and updated to reflect changes in the threat landscape, regulatory environment, or organizational structure. All reviews are witnessed into the Axiom Compliance Ledger under control AC-1.1.

---

**Approved By:** ________________________________________
**Title:** Authorizing Official
**Date:** ________________________________________
