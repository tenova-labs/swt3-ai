
                SYSTEM AND INFORMATION INTEGRITY POLICY

Policy Identifier:   SI-1.1
NIST 800-53 Control: SI-1 - System and Information Integrity Policy and Procedures
CMMC v2.0 Practice:  SI.L2-3.14.1
Effective Date:      2026-04-27
Review Cycle:        Annual (or upon significant organizational change)
Classification:      CUI / FOUO

________________________________________________________________________________

1. PURPOSE

This policy establishes the system and information integrity requirements for
TeNova Axiom to ensure that flaws are identified and remediated, malicious code
is detected and eradicated, systems are monitored for anomalous activity, and
software integrity is maintained. This policy implements the requirements of
NIST SP 800-53 Rev 5, SI family controls (SI-1 through SI-16), and satisfies
NIST SP 800-171 requirements 3.14.1, 3.14.2, and 3.14.6.

2. SCOPE

This policy applies to all information systems, operating systems,
applications, and monitoring infrastructure within the TeNova Axiom
authorization boundary, including patch management systems, antimalware tools,
intrusion detection mechanisms, and file integrity monitoring solutions.

3. ROLES AND RESPONSIBILITIES

   Authorizing Official (AO)
      Approves system integrity policy; accepts residual risk from deferred
      patches.

   Information System Security Officer (ISSO)
      Monitors integrity controls; reviews vulnerability scan results.

   System Administrators
      Applies patches, maintains antimalware, configures monitoring.

   Security Operations
      Investigates alerts from monitoring and integrity tools.

   Chief Information Security Officer (CISO)
      Designated policy owner; ensures compliance and audit readiness.

4. POLICY STATEMENTS

   4.1 Flaw Remediation (SI-2)

   TeNova Axiom shall identify, report, and correct information system flaws
   in a timely manner:

   - Pending security updates shall not exceed 10 at any time. Systems
     exceeding this threshold require immediate patching or documented
     justification in the Plan of Action and Milestones (POA&M).
   - Automatic updates shall be enabled via unattended-upgrades (or
     equivalent) to ensure security patches are applied without manual
     intervention. The auto-update service must be active and configured
     for security repositories.
   - System reboots required by kernel or library updates shall be performed
     promptly. Zero pending-reboot conditions are permitted during
     steady-state operations.
   - Remediation timelines by DISA severity category:

        CAT I (Critical):     Remediated within 30 days of discovery
        CAT II (High):        Remediated within 60 days of discovery
        CAT III (Medium/Low): Remediated within 90 days of discovery

   - Patches that cannot be applied within the required timeline shall be
     documented in the POA&M with risk acceptance from the AO.

   Technical Enforcement:
   - SI-2.1: Pending security updates shall not exceed 10 (continuously
     scanned, DISA STIG V-238388). Exceeding the threshold triggers a FAIL
     verdict.
   - SI-2.2: Automatic updates enabled via unattended-upgrades service
     (continuously scanned). Disabled auto-updates trigger a FAIL verdict.
   - SI-2.3: Zero pending system reboots (continuously scanned). A required
     reboot triggers a FAIL verdict until the reboot is performed.

   4.2 Malicious Code Protection (SI-3)

   The organization shall employ malicious code protection mechanisms at
   system entry and exit points:

   - At least one antimalware scanner shall be installed and operational on
     every host. Acceptable tools include ClamAV, rkhunter, chkrootkit, or
     equivalent.
   - Malware definitions shall be updated automatically, no less frequently
     than daily.
   - Full system scans shall be performed weekly and on-demand following
     suspected incidents.
   - Detected malicious code shall be quarantined, reported to the ISSO
     within 4 hours, and eradicated within 24 hours.

   Technical Enforcement:
   - SI-3.1: At least one antimalware tool present and installed
     (continuously scanned, DISA STIG V-238392). Absence of any malware
     scanner triggers an immediate FAIL verdict.

   4.3 System Monitoring (SI-4)

   TeNova Axiom shall monitor information systems to detect attacks,
   unauthorized access, and anomalous behavior:

   - Auditd (or equivalent audit subsystem) shall be active and running on
     all hosts. The audit daemon provides kernel-level monitoring of system
     calls, file access, and authentication events.
   - A minimum of 5 audit monitoring rules shall be configured, covering at
     minimum: authentication events, privilege escalation, file system
     modifications, user/group changes, and network configuration changes.
   - Audit logs shall be protected from unauthorized modification and
     retained in accordance with AU-11 (Audit Record Retention).
   - Monitoring alerts shall be reviewed by Security Operations within 24
     hours of generation.

   Technical Enforcement:
   - SI-4.1: Auditd service active and running (continuously scanned).
     Inactive audit daemon triggers an immediate FAIL verdict.
   - SI-4.2: At least 5 audit monitoring rules configured (continuously
     scanned). Fewer than 5 rules triggers a FAIL verdict.

   4.4 Security Function Verification (SI-6)

   The organization shall verify the correct operation of security functions:

   - Mandatory Access Control shall be enforced through AppArmor or SELinux
     on all hosts. At least one MAC framework must be active and in
     enforcing (or complain) mode.
   - Security function verification shall occur at system startup, upon
     administrator command, and during continuous monitoring cycles.
   - Failures in security function verification shall be reported to the
     ISSO and remediated within 48 hours.

   Technical Enforcement:
   - SI-6.1: AppArmor or SELinux active (continuously scanned, DISA STIG
     V-238396). Absence of any Mandatory Access Control framework triggers
     an immediate FAIL verdict.

   4.5 Software and Information Integrity (SI-7)

   TeNova Axiom shall employ integrity verification tools to detect
   unauthorized changes to software and information:

   - A file integrity monitoring tool (AIDE, Tripwire, or equivalent) shall
     be installed and configured on all hosts. The tool shall maintain a
     baseline database of critical system files and report deviations.
   - Package verification shall confirm that installed packages match their
     distribution signatures. Modified packages shall not exceed 10 at any
     time. Packages failing verification require investigation and
     re-installation or documented justification.
   - Integrity baselines shall be updated following authorized changes and
     verified weekly.
   - Unauthorized modifications detected by integrity tools shall be
     reported to the ISSO within 4 hours.

   Technical Enforcement:
   - SI-7.1: File integrity monitoring tool installed (AIDE, Tripwire, or
     equivalent) (continuously scanned, DISA STIG V-238400). Absence of any
     integrity tool triggers an immediate FAIL verdict.
   - SI-7.2: Modified packages shall not exceed 10 (continuously scanned).
     Exceeding the threshold triggers a FAIL verdict pending investigation.

5. TECHNICAL VERIFICATION

Compliance with this policy is continuously verified through the TeNova Axiom
Sovereign Engine. The following controls are scanned automatically:

   Control   What It Verifies                                       STIG Severity
   --------  -----------------------------------------------------  -------------
   SI-2.1    Pending security updates within threshold (max 10)      CAT II
   SI-2.2    Automatic updates enabled (unattended-upgrades)         CAT II
   SI-2.3    No pending system reboot required                       CAT III
   SI-3.1    Antimalware scanner present                             CAT I
   SI-4.1    Auditd service active                                   CAT I
   SI-4.2    Audit rules within threshold (min 5)                    CAT II
   SI-6.1    AppArmor or SELinux active                              CAT I
   SI-7.1    File integrity monitoring tool installed                 CAT I
   SI-7.2    Modified packages within threshold (max 10)             CAT II

All results are recorded as SWT3 Witness Anchors with SHA-256 fingerprints in
the Compliance Ledger, providing tamper-evident proof of continuous technical
enforcement.

6. ENFORCEMENT

Violations of this policy may result in immediate suspension of system access,
disciplinary action, or referral to law enforcement. Disabled monitoring or
integrity tools shall be restored within 4 hours. Unpatched CAT I
vulnerabilities exceeding the 30-day remediation window shall be escalated to
the Authorizing Official for risk acceptance.

7. REVIEW AND MAINTENANCE

This policy shall be reviewed annually by the Chief Information Security
Officer (CISO) and updated to reflect changes in the threat landscape,
regulatory environment, or organizational structure. All reviews are witnessed
into the Axiom Compliance Ledger under control SI-1.1.

________________________________________________________________________________

Approved By:  ________________________________________
Title:        Authorizing Official
Date:         ________________________________________
