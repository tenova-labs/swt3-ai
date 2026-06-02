
                    CONFIGURATION MANAGEMENT POLICY

Policy Identifier:   CM-1.1
NIST 800-53 Control: CM-1 - Configuration Management Policy and Procedures
CMMC v2.0 Practice:  CM.L2-3.4.1
Effective Date:      2026-04-27
Review Cycle:        Annual (or upon significant organizational change)
Classification:      CUI / FOUO

________________________________________________________________________________

1. PURPOSE

This policy establishes the configuration management requirements for TeNova
Axiom to ensure that information systems are configured securely, that changes
are tracked and authorized, and that systems operate with the minimum
functionality necessary. This policy implements the requirements of NIST SP
800-53 Rev 5, CM family controls (CM-1 through CM-11), and satisfies NIST SP
800-171 requirements 3.4.1, 3.4.2, 3.4.3, 3.4.5, 3.4.6, and 3.4.7.

2. SCOPE

This policy applies to all information systems, operating systems,
applications, network devices, and firmware within the TeNova Axiom
authorization boundary, including cloud-hosted infrastructure, on-premises
servers, and all software installed on production systems.

3. ROLES AND RESPONSIBILITIES

   Authorizing Official (AO)
      Approves configuration management policy; authorizes baseline deviations.

   Information System Security Officer (ISSO)
      Monitors configuration compliance; reviews change requests.

   System Administrators
      Maintains baseline configurations; implements approved changes.

   Configuration Control Board (CCB)
      Reviews and approves proposed configuration changes.

   Chief Information Security Officer (CISO)
      Designated policy owner; ensures compliance and audit readiness.

4. POLICY STATEMENTS

   4.1 Baseline Configuration (CM-2)

   TeNova Axiom shall develop, document, and maintain a current baseline
   configuration for all information systems. The baseline includes:

   - A complete inventory of installed software packages maintained at or
     below the organizational threshold of 900 packages.
   - Baseline documentation reviewed and updated with each major system
     change or annually, whichever is more frequent.
   - Deviations from the approved baseline require Configuration Control
     Board (CCB) authorization and documented justification.

   Technical Enforcement:
   - CM-2.1: Total installed packages shall not exceed 900 (continuously
     scanned). Unauthorized package additions trigger FAIL verdicts and
     require CCB review within 72 hours.

   4.2 Configuration Change Control (CM-3)

   The organization shall track, review, approve, and audit all changes to
   information systems:

   - All changes require documented authorization prior to implementation.
   - Scheduled tasks (cron jobs) shall not exceed 25 entries without CCB
     approval, as each scheduled task represents an automated change vector.
   - Emergency changes follow the emergency change procedure and require
     retroactive CCB approval within 48 hours.
   - All change activity is logged and auditable.

   Technical Enforcement:
   - CM-3.1: Total cron job entries shall not exceed 25 (continuously
     scanned). Each entry is enumerated and compared against the approved
     baseline.

   4.3 Access Restrictions for Change (CM-5)

   The organization shall define, document, approve, and enforce access
   restrictions associated with changes to the information system:

   - The /etc directory and all configuration files within it shall be owned
     exclusively by root (UID 0).
   - Non-root ownership of any file under /etc represents an unauthorized
     modification vector and triggers immediate remediation.
   - Write access to system configuration files is restricted to authorized
     administrators using sudo.

   Technical Enforcement:
   - CM-5.1: Zero non-root-owned files in /etc (continuously scanned, DISA
     STIG V-238243). Any non-root ownership triggers an immediate FAIL
     verdict.

   4.4 Configuration Settings (CM-6)

   TeNova Axiom shall configure all information systems using the most
   restrictive settings consistent with operational requirements. SSH
   hardening settings include:

   - Root login disabled. Direct SSH access as root is prohibited. All
     administrative actions require individual accountability through named
     accounts and sudo.
   - Password authentication disabled. Only public key authentication is
     permitted for SSH sessions, eliminating brute-force password attack
     vectors.
   - Core dumps disabled. Process core dumps are prohibited to prevent
     inadvertent exposure of sensitive data held in memory.
   - Maximum authentication attempts. SSH shall permit no more than 4
     authentication attempts per connection to limit brute-force attacks.

   Technical Enforcement:
   - CM-6.1: SSH PermitRootLogin set to "no" (continuously scanned, DISA
     STIG V-238320)
   - CM-6.2: SSH PasswordAuthentication set to "no" (continuously scanned,
     DISA STIG V-238332)
   - CM-6.3: Core dumps disabled via limits.conf and sysctl (continuously
     scanned, DISA STIG V-238328)
   - CM-6.4: SSH MaxAuthTries set to 4 or fewer (continuously scanned, DISA
     STIG V-238322)

   4.5 Least Functionality (CM-7)

   The organization shall configure systems to provide only essential
   capabilities, prohibiting or restricting the use of unnecessary functions,
   ports, protocols, and services:

   - Running services shall not exceed 80 on any single host. Services
     beyond this threshold require documented justification and CCB approval.
   - Unnecessary kernel modules (DCCP, SCTP, RDS, TIPC) shall be disabled
     or blacklisted. These protocols have known vulnerability histories and
     are not required for system operation.
   - Listening network ports shall not exceed 25 per host. Each listening
     port expands the attack surface and requires documented justification.

   Technical Enforcement:
   - CM-7.1: Running services count shall not exceed 80 (continuously
     scanned)
   - CM-7.2: Zero unnecessary kernel modules loaded for DCCP, SCTP, RDS,
     and TIPC protocols (continuously scanned). Presence of any triggers an
     immediate FAIL verdict.
   - CM-7.3: Listening port count shall not exceed 25 (continuously scanned)

5. TECHNICAL VERIFICATION

Compliance with this policy is continuously verified through the TeNova Axiom
Sovereign Engine. The following controls are scanned automatically:

   Control   What It Verifies                                       STIG Severity
   --------  -----------------------------------------------------  -------------
   CM-2.1    Installed packages within baseline (max 900)            CAT II
   CM-3.1    Cron jobs within threshold (max 25)                     CAT II
   CM-5.1    /etc directory files owned by root                      CAT I
   CM-6.1    SSH root login disabled                                 CAT I
   CM-6.2    SSH password authentication disabled                    CAT I
   CM-6.3    Core dumps disabled                                     CAT II
   CM-6.4    SSH MaxAuthTries at or below 4                          CAT II
   CM-7.1    Running services within threshold (max 80)              CAT II
   CM-7.2    No unnecessary kernel modules (DCCP/SCTP/RDS/TIPC)     CAT II
   CM-7.3    Listening ports within threshold (max 25)               CAT II

All results are recorded as SWT3 Witness Anchors with SHA-256 fingerprints in
the Compliance Ledger, providing tamper-evident proof of continuous technical
enforcement.

6. ENFORCEMENT

Violations of this policy may result in immediate suspension of system access,
disciplinary action, or referral to law enforcement. Unauthorized configuration
changes shall be reverted immediately and escalated to the ISSO. Repeated
violations shall be escalated to the Authorizing Official.

7. REVIEW AND MAINTENANCE

This policy shall be reviewed annually by the Chief Information Security
Officer (CISO) and updated to reflect changes in the threat landscape,
regulatory environment, or organizational structure. All reviews are witnessed
into the Axiom Compliance Ledger under control CM-1.1.

________________________________________________________________________________

Approved By:  ________________________________________
Title:        Authorizing Official
Date:         ________________________________________
