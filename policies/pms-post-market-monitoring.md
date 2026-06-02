                    POST-MARKET MONITORING SYSTEM PLAN

Policy Identifier:   PMS-1.1
EU AI Act:           Art. 61 (Post-Market Monitoring), Art. 72 (Monitoring)
NIST 800-53 Control: CA-7 (Continuous Monitoring), RA-5 (Vulnerability Scanning)
Effective Date:      2026-04-27
Review Cycle:        Annual (or upon significant regulatory or system change)
Classification:      CUI / FOUO

________________________________________________________________________________

1. PURPOSE

This document establishes the Post-Market Monitoring System (PMS) plan for
TeNova Axiom, as required by EU AI Act Article 61 for providers of high-risk
AI systems. The plan is proportionate to the nature, risk level, and scale of
the AI systems operated within the Axiom authorization boundary and ensures
continuous conformity monitoring throughout the entire AI system lifecycle,
from initial deployment through decommissioning or model recall.

The PMS plan integrates with existing NIST 800-53 continuous monitoring (CA-7)
and vulnerability management (RA-5) capabilities, extending them to cover
AI-specific obligations including behavioral drift, inference safety, model
governance, and regulatory change tracking.

________________________________________________________________________________

2. SCOPE

This plan applies to all AI systems deployed via the SWT3 witness pipeline,
including:

   a) Inference endpoints serving production traffic
   b) Model deployments across all clearing levels (0 through 3)
   c) Agent workflows with tool-calling capabilities
   d) SDK-connected client applications using Python, TypeScript, Rust, C#,
      or Ruby SDKs
   e) Third-party models accessed via LiteLLM or direct provider adapters
   f) Any AI component within the Axiom authorization boundary that generates
      SWT3 Witness Anchors

Systems outside the SWT3 pipeline that do not generate witness anchors are
governed by the general continuous monitoring provisions of CA-7 and are not
within the scope of this PMS plan.

________________________________________________________________________________

3. ROLES AND RESPONSIBILITIES

   AI Governance Officer
      Owns the PMS plan. Serves as the primary regulatory liaison with national
      market surveillance authorities and Notified Bodies. Responsible for
      ensuring conformity reporting obligations are met, including Art. 62
      serious incident reports and annual re-assessment summaries.

   Information System Security Officer (ISSO)
      Executes the technical monitoring activities defined in this plan.
      Manages drift detection response, vulnerability management coordination,
      and SWT3 Witness Anchor integrity verification. Maintains the continuous
      monitoring schedule and escalates anomalous findings.

   Model Owners
      Responsible for model-specific performance tracking, including behavioral
      drift threshold management, inference quality metrics, and model inventory
      accuracy. Model Owners ensure that baseline configurations are current
      and that drift beyond accepted thresholds triggers corrective action.

   Chief Information Security Officer (CISO)
      Conducts management review of PMS plan effectiveness. Allocates resources
      for monitoring activities, approves corrective action plans for high-
      severity findings, and serves as final escalation authority for PMS-
      related decisions.

________________________________________________________________________________

4. MONITORING OBJECTIVES

   4.1 Compliance Maintenance

   Continuous control monitoring is performed via SWT3 Witness Anchors. Each
   AI procedure (AI-GOV, AI-MDL, AI-INF, AI-GRD, AI-ID, AI-TOOL, AI-ACC,
   AI-REV families) produces a deterministic PASS or FAIL verdict on every
   evaluation cycle. Identical inputs always produce identical verdicts,
   enabling reproducible conformity checks by internal reviewers, Notified
   Bodies, and market surveillance authorities.

   Daily Merkle rollups aggregate all procedure evaluations into a single
   tamper-evident root hash per tenant per day, stored in the
   daily_merkle_rollups ledger. This provides cryptographic proof that all
   required procedures were evaluated within the monitoring window.

   4.2 Performance Tracking

   Model behavioral drift is detected via AI-MDL.3 with configurable baseline
   thresholds. When observed model behavior exceeds the established drift
   tolerance, the procedure emits a FAIL verdict and triggers the corrective
   action workflow defined in Section 7.

   Inference latency is monitored via AI-INF.2 with a 30-second threshold. Any
   inference exceeding this threshold generates a performance alert for
   capacity review.

   Token volume tracking via AI-INF.3 supports capacity planning and cost
   forecasting. Volume trends are analyzed monthly to identify unexpected
   consumption patterns that may indicate misuse or system degradation.

   4.3 Incident Detection

   The following conditions are treated as potential incidents requiring
   investigation:

   - Guardrail failure: AI-GRD.1 or AI-GRD.2 FAIL verdicts indicating that
     content safety filters or input validation guardrails were bypassed or
     failed to activate.

   - Content safety filter triggers: Patterns of repeated guardrail activations
     that may indicate adversarial probing or systematic misuse.

   - Anomalous inference patterns: Unexpected spikes in inference volume, token
     consumption, or error rates that deviate from established baselines.

   - Unauthorized model deployments: AI-GOV.4 FAIL verdicts indicating a model
     was deployed without completing the required governance approval workflow.

   4.4 Regulatory Change Tracking

   The AI Governance Officer monitors the following sources for changes that
   may affect monitoring obligations:

   - EU AI Act implementing acts and delegated acts published in the Official
     Journal of the European Union
   - NIST AI RMF updates, playbook revisions, and companion publications
   - National market surveillance authority guidance and enforcement actions
   - Harmonized standard publications under Art. 40, including any new
     standards adopted by the European Commission

   Identified changes are assessed within 30 calendar days and, where
   applicable, incorporated into the monitoring program through updated
   procedures, thresholds, or reporting requirements.

________________________________________________________________________________

5. DATA COLLECTION METHODS

   5.1 Automated (Continuous)

   SWT3 Witness Anchors are minted per inference event. Each anchor contains
   a SHA-256 fingerprint computed from the canonical formula
   (WITNESS:tenant:procedure:factor_a:factor_b:factor_c:timestamp_ms) and a
   deterministic PASS/FAIL verdict. Clearing levels are applied per data
   classification:

      Level 0 - Analytics:   Factor values visible, suitable for dashboards
      Level 1 - Standard:    Default production level, factors hashed
      Level 2 - Sensitive:   Factors redacted, metadata retained
      Level 3 - Classified:  Minimal metadata, full evidence sealed

   This enables evidence sharing with authorities at the appropriate
   disclosure level without exposing proprietary model data.

   5.2 Automated (Scheduled)

      Daily, 04:00 UTC
         Vulnerability scanning via Trivy v0.69.3 in host mode. Findings are
         processed through CVE-to-POA&M sync with automatic milestone
         assignment. Full scanning details are governed by RA-1.1.

      Every 4 hours
         Drift detection cycle (CA-7). Compares current control posture
         against the established baseline and flags deviations.

      Daily
         CISA Known Exploited Vulnerabilities catalog synchronization (SI-5).
         KEV-listed vulnerabilities receive priority remediation regardless of
         CVSS score.

      Daily, 00:01 UTC
         Merkle rollup computation (AU-10). Aggregates all witness anchors
         from the preceding 24-hour window into a single root hash.

      After each scan
         CVE-to-POA&M synchronization. New findings are entered with severity-
         based milestones. Previously open findings verified as resolved are
         auto-closed with evidence-linked closure records.

   5.3 Semi-Automated

      Monthly
         Attestation currency review via the Axiom dashboard. Identifies any
         attestation-based controls approaching or exceeding their review
         cycle deadline.

      Weekly
         POA&M status review and milestone updates. Overdue items are flagged
         and escalated per IRP-8.1 severity classification.

      Ongoing
         Posture trend analysis via Sovereign Score tracking. Score
         degradation triggers investigation into root cause.

   5.4 Manual

      Annually
         Full policy review across all organizational policy documents.
         Each policy is re-assessed for currency, accuracy, and alignment
         with current regulatory requirements.

      Quarterly
         Account review (AC-2). All user accounts, service accounts, and
         API keys are reviewed for continued need and appropriate privilege.

      Quarterly
         Model inventory review (AI-GOV.3). All deployed models are verified
         against the authorized model registry. Unregistered models are
         flagged for governance review.

      Annually
         Tabletop exercise (CP-4/IR-3). Scenario-based exercise covering
         AI-specific incident types including model compromise, data
         contamination, and adversarial attack.

________________________________________________________________________________

6. REVIEW FREQUENCY AND CORRECTIVE TRIGGERS

   Daily
      Merkle rollup integrity verification. CVE scan results review.
      FAIL verdict notification processing and initial triage.

   Weekly
      POA&M status review. Audit log review per AU-6.

   Monthly
      Attestation currency review. Posture trend analysis. Model
      performance metrics review (latency, drift, token volume).

   Quarterly
      Model inventory review (AI-GOV.3). Third-party vendor assessment
      (AI-GOV.5). Account review (AC-2).

   Annually
      Full QMS audit (QMS-1.1). Policy refresh cycle across all documents.
      Complete re-attestation of all attestation-based controls. Tabletop
      exercise (CP-4/IR-3).

   Trigger-Based (immediate)
      Any FAIL verdict on a critical AI procedure (AI-GRD, AI-GOV.4,
      AI-ACC families). Any SEV-1 or SEV-2 incident per IRP-8.1. Any
      regulatory change affecting AI monitoring obligations. Any model
      recall or anchor revocation event (AI-REV.1).

________________________________________________________________________________

7. CORRECTIVE ACTION PROCEDURES

   Severity Classification

   All findings are classified per the IRP-8.1 severity scale (SEV-1 through
   SEV-4). Severity determines escalation path, response timeline, and
   reporting obligations.

   POA&M Auto-Creation

   New findings generate POA&M entries automatically with severity-based
   milestone schedules:

      CRITICAL    7 calendar days to remediation
      HIGH        30 calendar days to remediation
      MEDIUM      90 calendar days to remediation

   Findings verified as resolved on subsequent passing scans are auto-closed
   with evidence-linked closure records referencing the specific scan result
   and SWT3 Witness Anchor that confirmed resolution.

   Root Cause Analysis

   SEV-1 and SEV-2 findings require root cause analysis completed within 5
   business days of detection. The analysis documents the contributing factors,
   immediate containment actions taken, and long-term preventive measures.

   Preventive Action

   Lessons learned from each SEV-1 and SEV-2 incident are documented in the
   lessons learned register. Preventive actions are tracked as POA&M entries
   with assigned owners and completion milestones.

   Anchor Revocation

   The AI-REV.1 procedure provides a formal corrective mechanism. When an
   anchor must be invalidated due to model recall, data contamination, policy
   violation, or other qualifying reason, the revocation is recorded with one
   of seven typed reason codes:

      0 - Unspecified
      1 - Model recall
      2 - Policy violation
      3 - Data contamination
      4 - Consent withdrawal
      5 - Regulatory order
      6 - Error correction

   Revocation anchors are tamper-evident and timestamped, providing an
   auditable corrective action trail.

________________________________________________________________________________

8. REPORTING TO AUTHORITIES

   Art. 62 Serious Incident Reports

   Serious incidents involving high-risk AI systems are reported to the
   relevant national market surveillance authority without undue delay. The
   initial report is submitted within 15 calendar days of becoming aware of
   the incident. Follow-up reports are submitted as the investigation produces
   additional findings.

   Annual Conformity Re-Assessment

   An annual conformity re-assessment summary is prepared for coordination
   with the Notified Body coordination group established under Art. 38. The
   summary covers all AI systems within scope, their monitoring results, any
   corrective actions taken, and the current conformity status.

   Internal Management Reporting

   Trend reports are available via the /api/v1/posture-trend endpoint for
   internal management review. These reports provide time-series visibility
   into Sovereign Score, procedure pass rates, drift frequency, and POA&M
   aging.

   External Submission Packages

   The NB-AI submission package, generated via /api/v1/nb-ai, provides a
   structured evidence bundle suitable for Notified Body and market
   surveillance authority review. The package includes witness anchor
   summaries, clearing-level-appropriate evidence, and conformity assessment
   results.

________________________________________________________________________________

9. SWT3 AS PMS INFRASTRUCTURE

   The SWT3 protocol serves as the technical backbone of this PMS plan. Its
   properties directly support the monitoring, evidence, and reporting
   requirements of Art. 61:

   Deterministic Assessment
      Identical inputs always produce identical verdicts. This enables any
      party (internal reviewer, Notified Body, market surveillance authority)
      to independently reproduce a conformity check and arrive at the same
      result.

   Daily Merkle Rollups
      Tamper-evident aggregate proof that all required procedures were
      evaluated within each 24-hour monitoring window. The Merkle root
      provides a single hash that can be verified without access to
      individual anchor records.

   Clearing Protocol
      Four clearing levels (Analytics, Standard, Sensitive, Classified) enable
      graduated evidence sharing with authorities. Regulators receive
      sufficient evidence to verify conformity without requiring disclosure
      of proprietary model weights, training data, or trade secrets.

   Revocation Mechanism
      AI-REV.1 provides a documented, timestamped, and cryptographically
      anchored corrective action capability. Revocations are immutable once
      recorded and are visible to any party with verification access.

   Cross-Language SDK Parity
      Python, TypeScript, Rust, C#, and Ruby SDKs produce identical
      fingerprints from identical inputs. This enables verification by any
      party using any supported language, eliminating implementation-specific
      discrepancies in conformity evidence.

________________________________________________________________________________

10. PLAN MAINTENANCE

   This PMS plan is reviewed annually by the AI Governance Officer with CISO
   approval. Additional reviews and updates are triggered by:

   - Any regulatory change affecting AI monitoring obligations, within 30
     calendar days of the change taking effect.

   - Any significant change to the AI system portfolio (new model deployment,
     model decommissioning, new use case, or change in risk classification),
     within 30 calendar days of the change.

   - Any finding from a Notified Body assessment or market surveillance
     authority inspection that identifies a gap in monitoring coverage.

   Version history is maintained in Git. Each revision of this plan is
   witnessed with an SWT3 Witness Anchor, providing tamper-evident proof of
   the revision date and content at the time of approval.

________________________________________________________________________________

11. CROSS-REFERENCES

   QMS-1.1     Quality Management System
   IRP-8.1     Incident Response Plan
   RA-1.1      Risk Assessment Policy
   AU-1.1      Audit and Accountability Policy
   CA-7        Continuous Monitoring (ISSM Guide, Section 13)
   Art. 9      EU AI Act Risk Management System
   Art. 17     EU AI Act Quality Management System
   Art. 62     EU AI Act Reporting of Serious Incidents

________________________________________________________________________________

12. REVISION HISTORY

   Date           Version    Description
   ________________________________________________________________________
   2026-04-27     1.0        Initial PMS plan document
   ________________________________________________________________________

________________________________________________________________________________

Approved By:  ________________________________________
Title:        AI Governance Officer
Date:         ________________________________________

Reviewed By:  ________________________________________
Title:        Chief Information Security Officer
Date:         ________________________________________
