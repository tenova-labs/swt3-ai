
                          RISK ASSESSMENT POLICY


_______________________________________________________________________________

  Policy Identifier:      RA-1.1
  NIST 800-53 Control:    RA-1 - Risk Assessment Policy and Procedures
  CMMC v2.0 Practice:     RA.L2-3.11.1
  NIST 800-171:           3.11.1, 3.11.2
  Effective Date:         2026-04-27
  Review Cycle:           Annual (365 days); Vulnerability Scanning at 90 days
  Classification:         CUI / FOUO

_______________________________________________________________________________


1. PURPOSE

   This policy establishes the requirements for conducting risk assessments
   and vulnerability scanning across the Axiom Sovereign Engine environment.
   It defines the organizational approach to identifying, evaluating, and
   documenting risks to information systems and the data they process, store,
   and transmit, in accordance with NIST SP 800-53 Rev. 5 and CMMC v2.0
   Level 2 requirements.


2. SCOPE

   This policy applies to all information systems, network infrastructure,
   applications, and services within the Axiom Sovereign Engine authorization
   boundary. This includes:

       a) All production and development environments
       b) Host operating systems, installed packages, and configurations
       c) Container images and runtime environments
       d) Supply chain dependencies (npm, pip, system packages)
       e) Third-party services and interconnections


3. ROLES AND RESPONSIBILITIES

   Authorizing Official (AO)
       - Reviews and signs the Risk Assessment Report
       - Accepts or rejects residual risk
       - Approves risk response actions for High and Very High findings

   Information System Security Officer (ISSO)
       - Coordinates and schedules risk assessments
       - Maintains the risk register and Risk Assessment Report
       - Ensures vulnerability scan results are reviewed and actioned
       - Correlates findings with CISA Known Exploited Vulnerabilities (KEV)

   System Administrator
       - Executes vulnerability scans per the defined schedule
       - Implements remediation actions within prescribed timelines
       - Maintains POA&M entries for open findings
       - Reports newly discovered vulnerabilities to the ISSO

   Security Operations
       - Monitors scan results for critical and high severity findings
       - Escalates KEV-correlated vulnerabilities for priority remediation
       - Validates remediation effectiveness through re-scanning


4. POLICY STATEMENTS

   4.1  Risk Assessment Policy (RA-1)

        The organization maintains a documented risk assessment policy and
        supporting procedures aligned with NIST SP 800-30 (Guide for
        Conducting Risk Assessments).

        Risk is categorized using the following scale:

            Very High    Threat exploitation is almost certain and impact
                         would be catastrophic to mission operations.

            High         Threat exploitation is highly likely and impact
                         would cause significant degradation of mission.

            Moderate     Threat exploitation is possible and impact would
                         cause noticeable degradation of mission.

            Low          Threat exploitation is unlikely and impact would
                         be limited.

            Very Low     Threat exploitation is highly unlikely and impact
                         would be negligible.

        The risk assessment policy is reviewed and updated at least annually
        or upon significant changes to the threat landscape, system
        architecture, or organizational mission.

   4.2  Risk Assessment (RA-3)

        A formal risk assessment is conducted at least annually or upon
        significant change to the information system or its environment of
        operation. Significant changes include but are not limited to:

            a) Major software or hardware upgrades
            b) Changes to the authorization boundary
            c) Addition of new interconnections or data flows
            d) Changes in threat intelligence indicating elevated risk
            e) Organizational restructuring affecting security posture

        The risk assessment identifies:

            a) Threat sources and threat events
            b) Vulnerabilities that could be exploited
            c) Potential impact to confidentiality, integrity, availability
            d) Likelihood of exploitation
            e) Resulting risk determination and recommended response

        Results are documented in a Risk Assessment Report. The Authorizing
        Official reviews and signs the report, accepting residual risk or
        directing additional mitigation.

   4.3  Vulnerability Scanning (RA-5)

        Vulnerability scans are conducted on all systems within the
        authorization boundary. The minimum scanning schedule is monthly;
        the Axiom Sovereign Engine maintains a daily scanning cadence via
        automated Trivy scans executed at 04:00 UTC.

        Scanning coverage includes:

            a) Host operating system and kernel
            b) Installed system packages and libraries
            c) Container images (when applicable)
            d) Five-layer supply chain audit (npm production, npm dev,
               npm global, pip isolated venv, system packages)

        Scan findings are correlated with the CISA Known Exploited
        Vulnerabilities (KEV) catalog. KEV-listed vulnerabilities receive
        priority remediation regardless of CVSS score.

        Remediation timelines follow SI-2 policy:

            Critical     7 calendar days
            High         30 calendar days
            Medium       90 calendar days
            Low          180 calendar days (or accept risk with AO approval)

        All findings are entered into the Plan of Action and Milestones
        (POA&M). Findings are automatically closed upon verified remediation
        through re-scanning. Overdue findings are flagged and escalated.

        Scan results feed the CVE Export report available to auditors and
        assessors, which includes POA&M status and SWT3 Witness Anchor
        provenance.


5. ATTESTATION VERIFICATION

   The following controls are verified through organizational attestation,
   document review, and scan evidence at the intervals specified below.

   Control       Description                        Review Interval
   ________________________________________________________________________

   RA-1.1        Risk Assessment Policy              365 days (annual)
                  Verified by: Document review confirming policy exists,
                  is current, and has been reviewed within the cycle.

   RA-3.1        Risk Assessment                     365 days (annual)
                  Verified by: Review of the Risk Assessment Report
                  confirming assessment was conducted within the cycle,
                  findings are documented, and AO signature is current.

   RA-5.1        Vulnerability Scanning              90 days (quarterly)
                  Verified by: Review of scan logs confirming daily
                  execution, evidence of finding remediation, POA&M
                  currency, and KEV correlation records.

   ________________________________________________________________________


6. ENFORCEMENT

   Failure to conduct risk assessments within the prescribed cycle will
   result in escalation to the Authorizing Official and may affect system
   authorization status. Systems with overdue vulnerability scans exceeding
   30 days beyond the scheduled cadence will be flagged for immediate
   remediation or isolation.


7. REFERENCES

   NIST SP 800-53 Rev. 5, RA-1, RA-3, RA-5
   NIST SP 800-30 Rev. 1, Guide for Conducting Risk Assessments
   NIST SP 800-171 Rev. 2, 3.11.1, 3.11.2
   CMMC v2.0 Level 2, RA.L2-3.11.1
   CISA Known Exploited Vulnerabilities (KEV) Catalog


8. REVISION HISTORY

   Date           Version    Description
   ________________________________________________________________________
   2026-04-27     1.0        Initial policy document
   ________________________________________________________________________
