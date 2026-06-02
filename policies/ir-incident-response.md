
                      INCIDENT RESPONSE POLICY

_______________________________________________________________________________

  Policy Identifier:       IR-1.1
  NIST 800-53 Control:     IR-1 - Incident Response Policy and Procedures
  CMMC v2.0 Practice:      IR.L2-3.6.1
  NIST 800-171 Controls:   3.6.1, 3.6.2, 3.6.3
  Effective Date:          2026-04-27
  Review Cycle:            Annual (or upon significant organizational change)
  Classification:          CUI / FOUO

_______________________________________________________________________________


1. PURPOSE

This policy establishes the incident response requirements for TeNova Axiom
to ensure that security incidents are detected, reported, analyzed, contained,
eradicated, and recovered from in a timely and effective manner. This policy
implements the requirements of NIST SP 800-53 Rev 5, IR family controls
(IR-1, IR-2, IR-4, IR-5, IR-6, and IR-8), CMMC v2.0 Practices IR.L2-3.6.1
and IR.L2-3.6.2, and NIST SP 800-171 requirements 3.6.1, 3.6.2, and 3.6.3.
Procedures are aligned with NIST SP 800-61 Rev 2, Computer Security Incident
Handling Guide.

_______________________________________________________________________________


2. SCOPE

This policy applies to all information systems operated by or on behalf of
TeNova Axiom, all personnel (employees, contractors, subcontractors, and
third parties) with access to organizational systems, and all security events
and incidents occurring within the authorization boundary. This includes
incidents involving Controlled Unclassified Information (CUI), denial of
service conditions, unauthorized access, malicious code, and insider threats.

_______________________________________________________________________________


3. ROLES AND RESPONSIBILITIES

  Authorizing Official (AO)
      Approves the incident response policy and the incident response plan.
      Receives notification of all Category I and Category II incidents.
      Authorizes system shutdown or isolation decisions when mission impact
      is significant.

  Chief Information Security Officer (CISO)
      Designated policy owner. Oversees the incident response program.
      Ensures adequate staffing and resources for the incident response
      team. Approves external reporting of incidents to US-CERT and
      DIBCAC. Reports incident trends and metrics to the AO quarterly.

  Incident Response Team Lead
      Coordinates incident response activities. Makes initial incident
      categorization and severity determination. Directs containment,
      eradication, and recovery actions. Prepares after-action reports
      and ensures lessons learned are incorporated into procedures.

  Information System Security Officer (ISSO)
      Monitors security alerting systems for indicators of compromise.
      Performs initial triage of security events. Maintains the incident
      tracking system and ensures forensic evidence preservation. Verifies
      incident closure criteria are met before closing incidents.

  System Administrators
      Execute containment and eradication actions as directed by the
      Incident Response Team Lead. Preserve system logs and forensic
      artifacts. Perform system recovery and restoration activities.
      Report anomalous system behavior to the ISSO.

  All Personnel
      Report suspected security incidents to the ISSO or incident
      response team immediately upon discovery. Preserve evidence by
      not modifying or powering off affected systems unless directed.
      Cooperate fully with incident investigations.

_______________________________________________________________________________


4. ATTESTATION REQUIREMENTS

4.1 Incident Response Policy (IR-1)
    CCI: CCI-000393
    CMMC: IR.L2-3.6.1

    TeNova Axiom shall maintain a documented incident response policy that
    addresses purpose, scope, roles, responsibilities, management
    commitment, coordination among organizational entities, and compliance.

    The policy shall be reviewed and updated at least annually or whenever
    significant changes occur to the information system, organizational
    structure, or threat environment. Each review shall be documented with
    the date, reviewer, and a summary of changes made. The CISO shall
    attest to the currency of this policy annually.

4.2 Incident Response Training (IR-2)
    CCI: CCI-000396
    CMMC: IR.L2-3.6.2

    All personnel with incident response roles shall receive incident
    response training:

    (a)  Within 30 days of assignment to an incident response role
    (b)  Annually thereafter as a refresher
    (c)  When significant changes are made to the incident response plan
         or the information system

    Training content shall include incident identification and
    categorization, evidence preservation procedures, containment
    strategies, escalation procedures, and external reporting
    requirements. General users shall receive awareness-level training
    on recognizing and reporting incidents as part of the security
    awareness program (AT-2). The Incident Response Team Lead shall
    attest annually that all IR personnel have completed required training.

4.3 Incident Handling (IR-4)
    CCI: CCI-000399
    CMMC: IR.L2-3.6.1

    TeNova Axiom shall implement incident handling procedures consistent
    with NIST SP 800-61 Rev 2, encompassing the following phases:

    (a)  Preparation: Maintain incident response tools, communication
         channels, and forensic capabilities. Ensure contact lists and
         escalation matrices are current.

    (b)  Detection and Analysis: Monitor security alerts, logs, and
         user reports. Correlate indicators of compromise. Categorize
         incidents by type and severity:
             Category I (CAT I): Root compromise, active data exfiltration,
             or loss of CUI
             Category II (CAT II): Unauthorized access, malicious code,
             denial of service
             Category III (CAT III): Policy violations, unsuccessful
             attack attempts, anomalous activity

    (c)  Containment, Eradication, and Recovery: Isolate affected systems
         to prevent lateral movement. Remove malicious artifacts and
         restore systems from known-good baselines. Verify system integrity
         before returning to production.

    (d)  Post-Incident Activity: Conduct lessons learned review within
         10 business days of incident closure. Update procedures, rules,
         and detection signatures based on findings.

    The ISSO shall attest every 180 days that incident handling procedures
    are current and that all incidents within the review period were
    handled in accordance with established procedures.

4.4 Incident Monitoring (IR-5)
    CCI: CCI-000401
    CMMC: IR.L2-3.6.1

    TeNova Axiom shall track and document security incidents on an ongoing
    basis using an incident tracking system that records:

    (a)  Incident identifier and date of detection
    (b)  Category and severity classification
    (c)  Affected systems and data
    (d)  Timeline of response actions
    (e)  Personnel involved in response
    (f)  Root cause analysis (when determinable)
    (g)  Closure date and resolution summary

    Forensic evidence shall be preserved in accordance with organizational
    evidence handling procedures and applicable legal requirements. The
    CISO shall review incident trends quarterly and report to the AO.
    The ISSO shall attest every 180 days that the incident tracking system
    is operational and that all incidents are properly documented.

4.5 Incident Reporting (IR-6)
    CCI: CCI-000403
    CMMC: IR.L2-3.6.2

    Security incidents shall be reported through the following channels
    and timeframes:

    Internal Reporting:
    (a)  All suspected incidents reported to ISSO immediately upon
         discovery
    (b)  CAT I incidents escalated to CISO and AO within 1 hour of
         confirmation
    (c)  CAT II incidents escalated to CISO within 4 business hours
    (d)  CAT III incidents documented and reported to CISO in the
         weekly security summary

    External Reporting:
    (a)  US-CERT: Within 72 hours for incidents involving federal
         information or systems, per US-CERT Federal Incident
         Notification Guidelines
    (b)  DIBCAC: As required for incidents involving CUI on contractor
         information systems, per DFARS 252.204-7012
    (c)  Law Enforcement: When criminal activity is suspected, in
         coordination with legal counsel

    The CISO shall attest annually that reporting procedures are current
    and that all reportable incidents within the review period were
    reported within required timeframes.

4.6 Incident Response Plan (IR-8)
    CCI: CCI-000407
    CMMC: IR.L2-3.6.3

    TeNova Axiom shall maintain an incident response plan that provides
    the roadmap for the organization's incident response capability.
    The plan shall include:

    (a)  Organizational structure of the incident response team, including
         primary and alternate personnel with contact information
    (b)  Escalation matrix defining notification thresholds by incident
         category
    (c)  Communication plan for internal stakeholders, external partners,
         customers, and regulatory bodies
    (d)  Resource requirements including tools, facilities, and
         vendor support agreements
    (e)  Metrics and measures of effectiveness for the incident
         response program
    (f)  Cross-references to related plans (contingency, business
         continuity, disaster recovery)

    The incident response plan shall be reviewed and approved by the AO
    annually. The plan shall be updated within 30 days of any significant
    incident, organizational change, or lessons learned finding. The
    Incident Response Team Lead shall attest annually that the plan is
    current, approved, and distributed to all responsible personnel.

_______________________________________________________________________________


5. ATTESTATION VERIFICATION

Compliance with this policy is verified through periodic attestation review.
These controls are organizational in nature and are not subject to automated
technical scanning. The ISSO and CISO shall verify compliance through
documented review at the intervals specified below.

  Control     Description                     Review Interval    CCI
  --------    ----------------------------    ---------------    -----------
  IR-1.1      Incident Response Policy        365 days           CCI-000393
  IR-2.1      Incident Response Training      365 days           CCI-000396
  IR-4.1      Incident Handling               180 days           CCI-000399
  IR-5.1      Incident Monitoring             180 days           CCI-000401
  IR-6.1      Incident Reporting              365 days           CCI-000403
  IR-8.1      Incident Response Plan          365 days           CCI-000407

Each attestation review shall produce a signed attestation record documenting
the reviewer, date of review, findings, and any corrective actions required.
All attestation results are recorded as SWT3 Witness Anchors in the
Compliance Ledger with SHA-256 cryptographic fingerprints, providing
tamper-evident proof of continuous compliance.

_______________________________________________________________________________


6. ENFORCEMENT

Violations of this policy may result in:

    (a)  Immediate suspension of system access for personnel who fail to
         report known incidents
    (b)  Disciplinary action up to and including termination of employment
    (c)  Removal of contractor personnel from the contract
    (d)  Reporting to the contracting officer for contract-related breaches
    (e)  Referral to law enforcement for willful destruction of evidence
         or obstruction of incident investigations
    (f)  Regulatory penalties for failure to meet external reporting
         requirements

_______________________________________________________________________________


7. REVIEW AND MAINTENANCE

This policy shall be reviewed annually by the Chief Information Security
Officer (CISO) and updated as necessary to reflect changes in organizational
structure, information system architecture, regulatory requirements, threat
landscape, or lessons learned from incident response activities. All reviews
and updates are witnessed into the Axiom Compliance Ledger under control
IR-1.1.

_______________________________________________________________________________


Approved By:    ________________________________________

Title:          Authorizing Official

Date:           ________________________________________
