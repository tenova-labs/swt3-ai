                             MAINTENANCE POLICY

Policy Identifier:   MA-1.1
NIST 800-53 Control: MA-1 - Maintenance Policy and Procedures
CMMC v2.0 Practice:  MA.L2-3.7.1
Effective Date:      2026-03-17
Review Cycle:        Annual (or upon significant organizational change)
Classification:      CUI / FOUO

________________________________________________________________________________

1. PURPOSE

This policy establishes requirements for the maintenance of information systems
within the TeNova Axiom authorization boundary. It ensures that maintenance
activities are scheduled, documented, reviewed, and performed by authorized
personnel using approved tools, in accordance with NIST SP 800-53 Rev 5, MA
family controls (MA-1 through MA-6).

________________________________________________________________________________

2. SCOPE

This policy applies to all information systems, network infrastructure, servers,
workstations, and supporting hardware within the TeNova Axiom authorization
boundary, including cloud-hosted instances, on-premises equipment, and
remote-managed systems.

________________________________________________________________________________

3. ROLES AND RESPONSIBILITIES

   Authorizing Official (AO)
      Approves maintenance policy; authorizes maintenance windows.

   Information System Security Officer (ISSO)
      Monitors compliance with maintenance procedures.

   System Administrators
      Perform scheduled and unscheduled maintenance; document activities.

   Maintenance Personnel
      Execute maintenance tasks under authorization and supervision.

   Chief Information Security Officer (CISO)
      Designated policy owner; ensures audit readiness.

________________________________________________________________________________

4. POLICY STATEMENTS

   4.1 Controlled Maintenance (MA-2)

   - All maintenance activities shall be scheduled, performed, documented, and
     reviewed in accordance with manufacturer specifications and organizational
     requirements.
   - Maintenance records shall include date, time, personnel involved,
     description of work performed, and system components affected.
   - Emergency maintenance shall be documented within 24 hours of completion.


   4.2 Maintenance Tools (MA-3)

   - Only approved maintenance tools shall be used on information systems.
   - All maintenance tools shall be inspected for improper or unauthorized
     modifications before use.
   - The organization shall maintain an inventory of approved maintenance tools
     and verify tool integrity through file integrity monitoring (AIDE,
     Tripwire, or equivalent).
   - Diagnostic and test software shall be subject to the same access controls
     as production systems.


   4.3 Non-Local Maintenance (MA-4)

   - Non-local (remote) maintenance shall require multi-factor authentication.
   - All remote maintenance sessions shall be logged and monitored.
   - Remote maintenance connections shall use encrypted channels (SSH,
     TLS 1.2+).
   - Sessions shall be terminated when maintenance is complete.


   4.4 Maintenance Personnel (MA-5)

   - All maintenance personnel shall be authorized before accessing information
     systems.
   - External maintenance personnel shall be supervised by authorized
     organizational staff.
   - Personnel authorization shall be verified against current access control
     lists.
   - Maintenance activities by external personnel shall be logged in the
     compliance ledger.


   4.5 Timely Maintenance (MA-6)

   The organization shall perform maintenance at regular intervals as defined
   by system criticality:

   - Critical systems: Monthly maintenance window
   - Standard systems: Quarterly maintenance window

   Security patches shall be applied within the timeframes defined by DISA STIG
   severity:

   - CAT I: 30 days
   - CAT II: 60 days
   - CAT III: 90 days

   Maintenance activity logs (e.g., apt history) shall demonstrate ongoing
   compliance.

________________________________________________________________________________

5. COMPLIANCE MONITORING

The Axiom Collector automatically verifies:

   - Existence and currency of this policy document (MA-1.1)
   - Availability of file integrity monitoring tools (MA-3.1)
   - Recent maintenance activity in system logs (MA-6.1)

Non-compliance triggers an automated FAIL verdict in the Sovereign Witness
Ledger.

________________________________________________________________________________

6. REVIEW AND MAINTENANCE

This policy shall be reviewed annually or upon significant changes to the
information system environment, threat landscape, or regulatory requirements.
Reviews shall be documented and approved by the AO.

________________________________________________________________________________

Approved By:  ________________________________________
Title:        Authorizing Official
Date:         ________________________________________
