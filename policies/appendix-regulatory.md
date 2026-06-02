           APPENDIX A - REGULATORY FRAMEWORK AND APPLICABILITY

Classification:      CUI / FOUO
Applicable Standard: NIST SP 800-53 Rev 5 (Moderate Baseline)
Crosswalk:           CMMC v2.0 Level 2 / NIST SP 800-171 Rev 2

________________________________________________________________________________

A.1 REGULATORY BASIS

This organization operates under the following regulatory and contractual
obligations governing the protection of Controlled Unclassified Information
(CUI):

   DFARS 252.204-7012
      Safeguarding Covered Defense Information and Cyber Incident Reporting.
      Applicability: All DoD contracts involving CDI/CUI.

   DFARS 252.204-7019
      Notice of NIST SP 800-171 DoD Assessment Requirements.
      Applicability: Self-assessment score submission to SPRS.

   DFARS 252.204-7020
      NIST SP 800-171 DoD Assessment Requirements.
      Applicability: Medium/High assessments by DCMA DIBCAC.

   DFARS 252.204-7021
      Cybersecurity Maturity Model Certification Requirements.
      Applicability: CMMC Level 2 certification by C3PAO.

   32 CFR Part 2002
      Controlled Unclassified Information.
      Applicability: CUI marking, safeguarding, and dissemination.

   NIST SP 800-171 Rev 2
      Protecting CUI in Nonfederal Systems.
      Applicability: 110 security requirements across 14 families.

   NIST SP 800-53 Rev 5
      Security and Privacy Controls for Information Systems.
      Applicability: Control catalog (Moderate baseline).

   NIST SP 800-171A
      Assessing Security Requirements for CUI.
      Applicability: Assessment procedures and methodologies.

   FAR 52.204-21
      Basic Safeguarding of Covered Contractor Information Systems.
      Applicability: 15 basic safeguarding requirements (CMMC L1).

   NIST AI RMF 1.0
      Artificial Intelligence Risk Management Framework.
      Applicability: AI system governance and monitoring.

________________________________________________________________________________

A.2 COVERED DEFENSE INFORMATION (CDI)

Per DFARS 252.204-7012, Covered Defense Information includes:

   - Controlled Technical Information (CTI) - technical data with military or
     space application subject to distribution controls.

   - Controlled Unclassified Information (CUI) - information requiring
     safeguarding per 32 CFR Part 2002 and the CUI Registry.

   - Export-controlled information - subject to ITAR (22 CFR 120-130) or EAR
     (15 CFR 730-774).

   - Other information - marked or otherwise identified in the contract as
     requiring protection.

The organization shall safeguard all CDI residing on or transiting through its
information systems in accordance with the security requirements specified in
NIST SP 800-171 Rev 2.

________________________________________________________________________________

A.3 CMMC V2.0 COMPLIANCE MODEL

The Cybersecurity Maturity Model Certification (CMMC) v2.0 establishes three
levels of cybersecurity maturity:

   Level 1 - Foundational
      Practices: 17 practices (FAR 52.204-21)
      Assessment: Annual self-assessment
      Applicable Contracts: FCI-only contracts

   Level 2 - Advanced
      Practices: 110 practices (NIST 800-171)
      Assessment: Triennial C3PAO assessment
      Applicable Contracts: CUI contracts

   Level 3 - Expert
      Practices: 110 + 24 enhanced (800-172)
      Assessment: Government-led assessment
      Applicable Contracts: Highest-priority programs

This organization targets CMMC Level 2 compliance. All 110 practices from NIST
SP 800-171 Rev 2 are mapped to the organization's technical and administrative
controls via the TeNova Axiom compliance engine.

________________________________________________________________________________

A.4 CONTINUOUS MONITORING AND EVIDENCE STANDARD

All technical controls documented in the associated policy are continuously
verified by the TeNova Axiom Sovereign Engine using the SWT3 (Sovereign Witness
Token v3) protocol:

   - Evidence Collection: Read-only system inspections executed by the Axiom
     Collector.

   - Cryptographic Witnessing: Each verdict is anchored with a SHA-256
     fingerprint, producing a tamper-evident compliance record.

   - Compliance Ledger: All witness events are recorded in a centralized,
     append-only ledger with tenant isolation via Row-Level Security (RLS).

   - OSCAL Artifact Generation: System Security Plans (SSP), Plans of Action
     and Milestones (POA&M), and Assessment Results (AR) are generated in OSCAL
     v1.1.3 JSON format and validated against the NIST reference
     implementation.

________________________________________________________________________________

A.5 STANDARD OF PRACTICE

The security controls, policies, and procedures documented herein are
maintained in accordance with:

   - NIST SP 800-53 Rev 5 control descriptions and supplemental guidance.
   - NIST SP 800-171A assessment objectives and determination statements.
   - CMMC Assessment Guide (Level 2) assessment objectives.
   - CISA Binding Operational Directives as applicable.
   - DoD CIO memoranda on cybersecurity requirements for the Defense Industrial
     Base (DIB).

This appendix applies to all policy documents generated by the TeNova Axiom
compliance engine and should be read in conjunction with the associated
traceability matrix.

________________________________________________________________________________

This appendix is auto-attached to policy exports by the TeNova Axiom Sovereign
Engine. It is not a standalone document.
