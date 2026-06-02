
                    CONTINGENCY PLANNING POLICY

_______________________________________________________________________________

  Policy Identifier:       CP-1.1
  NIST 800-53 Control:     CP-1 - Contingency Planning Policy and Procedures
  CMMC v2.0 Practice:      CP.L2-3.6.1
  NIST 800-171 Controls:   3.6.1, 3.6.2, 3.6.3, 3.8.9
  Effective Date:          2026-04-27
  Review Cycle:            Annual (or upon significant organizational change)
  Classification:          CUI / FOUO

_______________________________________________________________________________


1. PURPOSE

This policy establishes the contingency planning requirements for TeNova Axiom
to ensure the organization can continue essential missions and business
functions during and after a disruption to information systems. This policy
implements the requirements of NIST SP 800-53 Rev 5, CP family controls
(CP-1, CP-2, CP-3, CP-4, and CP-9), CMMC v2.0 Practice CP.L2-3.6.1, and
NIST SP 800-171 requirements 3.6.1, 3.6.2, 3.6.3, and 3.8.9.

_______________________________________________________________________________


2. SCOPE

This policy applies to all information systems operated by or on behalf of
TeNova Axiom that process, store, or transmit Controlled Unclassified
Information (CUI) or support essential mission functions. This includes
production systems, supporting infrastructure, backup systems, and alternate
processing sites. All personnel with contingency planning responsibilities,
including recovery team members, system administrators, and management, are
subject to this policy.

_______________________________________________________________________________


3. ROLES AND RESPONSIBILITIES

  Authorizing Official (AO)
      Approves the contingency planning policy and the contingency plan
      itself. Reviews and endorses annual test results. Authorizes
      activation of the contingency plan during actual disruptions.

  Chief Information Security Officer (CISO)
      Designated policy owner. Ensures the contingency plan is developed,
      maintained, and tested in accordance with this policy. Reports
      contingency readiness posture to the AO quarterly.

  Contingency Plan Coordinator
      Develops and maintains the contingency plan document. Coordinates
      annual training and testing exercises. Maintains the recovery team
      roster and communication plan. Prepares after-action reports
      following tests and actual activations.

  Information System Security Officer (ISSO)
      Verifies that backup procedures are executed according to schedule.
      Validates restore testing results. Ensures contingency planning
      controls are addressed in the system security plan.

  Recovery Team Members
      Participate in annual contingency training. Execute assigned recovery
      procedures during tests and actual disruptions. Report readiness
      gaps to the Contingency Plan Coordinator.

  System Administrators
      Execute backup procedures per the defined schedule. Perform quarterly
      restore testing. Maintain documentation of backup configurations
      and offsite storage locations.

_______________________________________________________________________________


4. ATTESTATION REQUIREMENTS

4.1 Contingency Planning Policy (CP-1)

    TeNova Axiom shall maintain a documented contingency planning policy
    that addresses purpose, scope, roles, responsibilities, management
    commitment, coordination among organizational entities, and compliance.

    The policy shall be reviewed and updated at least annually or whenever
    significant changes occur to the information system, organizational
    structure, or threat environment. Each review shall be documented with
    the date, reviewer, and a summary of changes made. The CISO shall
    attest to the currency of this policy annually.

4.2 Contingency Plan (CP-2)

    TeNova Axiom shall develop and maintain a contingency plan for each
    information system within the authorization boundary. The contingency
    plan shall include, at a minimum:

    (a)  Identification of essential missions and business functions
    (b)  Recovery objectives including:
             Recovery Time Objective (RTO): Maximum acceptable downtime
             before mission impact becomes unacceptable
             Recovery Point Objective (RPO): Maximum acceptable data loss
             measured in time
    (c)  Recovery team roster with primary and alternate contacts,
         including after-hours contact information
    (d)  Roles, responsibilities, and assigned recovery tasks for each
         team member
    (e)  Communication plan for internal notification, external
         stakeholders, and regulatory reporting
    (f)  Alternate processing site identification and activation procedures
    (g)  System recovery procedures in priority order based on mission
         criticality
    (h)  Inventory of critical systems, data, and supporting resources
    (i)  Procedures for returning to normal operations

    The contingency plan shall be reviewed and updated at least every
    180 days to ensure accuracy of contact information, system
    configurations, and recovery procedures. The Contingency Plan
    Coordinator shall attest to the currency and completeness of the plan
    at each review cycle.

4.3 Contingency Training (CP-3)

    All recovery team members shall receive contingency training specific
    to their assigned roles and responsibilities. Training shall occur:

    (a)  Within 30 days of assignment to a contingency role
    (b)  Annually thereafter as a refresher
    (c)  When significant changes are made to the contingency plan

    Training content shall include the location and use of the contingency
    plan, individual recovery responsibilities, coordination procedures,
    and communication protocols. The Contingency Plan Coordinator shall
    attest annually that all recovery team members have completed the
    required training.

4.4 Contingency Plan Testing (CP-4)

    The contingency plan shall be tested at least annually to determine
    its effectiveness and the organization's readiness to execute the plan.
    Acceptable testing methods include:

    (a)  Tabletop exercise: Structured walkthrough of the contingency plan
         with recovery team members discussing roles and response actions
         against a realistic scenario
    (b)  Functional exercise: Simulated disruption requiring actual
         execution of recovery procedures in a controlled environment
    (c)  Full-scale exercise: Complete activation of the contingency plan
         including failover to alternate processing capability

    Each test shall produce an after-action report documenting the
    scenario, participants, timeline, findings, and corrective actions.
    Identified deficiencies shall be remediated and the contingency plan
    updated within 30 days of the exercise. The Contingency Plan
    Coordinator shall attest to completion of annual testing and
    remediation of findings.

4.5 Information System Backup (CP-9)

    TeNova Axiom shall conduct backups of user-level information and
    system-level information at the following frequencies:

    (a)  User-level data (databases, application data, CUI repositories):
         Daily incremental, weekly full
    (b)  System-level data (configurations, system state, security
         policies): Weekly full, and before any significant change
    (c)  Boot and recovery media: Updated with each system baseline change

    Backup scope shall include all data necessary to restore the system to
    a known operational state consistent with the defined RPO. Backups
    shall be stored at an offsite location that is geographically separated
    from the primary processing site.

    Restore testing shall be conducted quarterly to verify the integrity
    and recoverability of backup data. Restore tests shall include at
    least one full system restoration annually. The ISSO shall attest
    every 90 days that backups are being conducted per schedule and that
    the most recent restore test was successful.

_______________________________________________________________________________


5. ATTESTATION VERIFICATION

Compliance with this policy is verified through periodic attestation review.
These controls are organizational in nature and are not subject to automated
technical scanning. The ISSO and CISO shall verify compliance through
documented review at the intervals specified below.

  Control     Description                     Review Interval
  --------    ----------------------------    ---------------
  CP-1.1      Contingency Planning Policy     365 days
  CP-2.1      Contingency Plan                180 days
  CP-3.1      Contingency Training            365 days
  CP-4.1      Contingency Plan Testing        365 days
  CP-9.1      Information System Backup        90 days

Each attestation review shall produce a signed attestation record documenting
the reviewer, date of review, findings, and any corrective actions required.
All attestation results are recorded as SWT3 Witness Anchors in the
Compliance Ledger with SHA-256 cryptographic fingerprints, providing
tamper-evident proof of continuous compliance.

_______________________________________________________________________________


6. ENFORCEMENT

Violations of this policy may result in:

    (a)  Immediate corrective action and documented plan of action
    (b)  Suspension of system operations if backup or recovery capability
         is determined to be inadequate
    (c)  Disciplinary action for personnel who fail to fulfill assigned
         contingency roles
    (d)  Reporting to the contracting officer for contract-related breaches
    (e)  Referral to the AO for risk acceptance determination if
         contingency gaps cannot be remediated within required timeframes

_______________________________________________________________________________


7. REVIEW AND MAINTENANCE

This policy shall be reviewed annually by the Chief Information Security
Officer (CISO) and updated as necessary to reflect changes in organizational
structure, information system architecture, regulatory requirements, or
threat landscape. All reviews and updates are witnessed into the Axiom
Compliance Ledger under control CP-1.1.

_______________________________________________________________________________


Approved By:    ________________________________________

Title:          Authorizing Official

Date:           ________________________________________
