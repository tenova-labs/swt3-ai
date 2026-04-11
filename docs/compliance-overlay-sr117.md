# SWT3 Protocol: SR 11-7 / OCC 2011-12 Model Risk Management Overlay

**Version:** 1.0.0
**Date:** April 4, 2026
**Applies to:** Banks, credit unions, and financial institutions subject to Federal Reserve SR 11-7 and OCC Bulletin 2011-12
**Parent document:** SWT3 ToS Clearing Addendum (April 4, 2026)

---

## Who This Document Is For

This overlay is for Model Risk Management Officers, Chief Risk Officers, internal auditors, and OCC/Federal Reserve examiners who need to understand how SWT3 Witness Anchors provide examiner-ready evidence for model governance, validation, and monitoring.

If your institution uses AI or statistical models for credit decisions, fraud detection, pricing, or capital calculations, this document shows you how SWT3 creates a tamper-evident audit trail that satisfies the "effective challenge" requirements in SR 11-7.

---

## Quick Reference: FIN Procedures

| Procedure | What it proves | SR 11-7 Section | Examination Focus |
|-----------|---------------|----------------|-------------------|
| FIN-GOV.1 | Governance committee reviewed and approved the model | Section III - Board Oversight | Committee minutes, quorum, approval votes |
| FIN-MRM.1 | Model is registered and version matches approved inventory | Section V - Model Inventory | Inventory completeness, version lineage |
| FIN-VAL.1 | Independent validator performed effective challenge | Section VI - Model Validation | Validator independence, sign-off records |
| FIN-MON.1 | Performance metric within threshold, no drift detected | Section VII - Ongoing Monitoring | PSI/CSI thresholds, alerting frequency |
| FIN-OUT.1 | Back-test completed with sufficient sample, results within tolerance | Section VIII - Outcomes Analysis | Sample adequacy, prediction accuracy |

---

## Control-by-Control Mapping

### FIN-GOV.1: Model Governance Committee Approval

**SR 11-7 requires:** The board of directors and senior management should ensure that model risk management is part of the overall risk management framework. A governance structure with clear roles and responsibilities should be established.

**How SWT3 addresses it:** When the Model Risk Governance Committee votes to approve a model for production use, the vote is anchored with three factors: the quorum requirement (factor_a), the actual vote count (factor_b), and the approval decision (factor_c). The resulting SWT3 Witness Anchor proves that a properly constituted committee made a documented decision on a specific date. The anchor is tamper-evident and independently verifiable.

**What to show the examiner:** The SWT3 anchor token for the governance approval. The examiner can verify the anchor independently using the public verification formula. The factor values confirm quorum was met and the vote was recorded. Cross-reference with your committee charter to confirm the quorum threshold matches your governance policy.

### FIN-MRM.1: Model Inventory and Lineage

**SR 11-7 requires:** A firm-wide model inventory should be maintained, including information about the purpose, limitations, and risk tier of each model. Version lineage and deployment history should be tracked.

**How SWT3 addresses it:** Each time a model is deployed or updated, the SDK records whether the deployed model hash matches the approved version in the inventory. Factor_a is set to 1 (registration required), factor_b is 1 if the hash matches, and factor_c is reserved. A PASS verdict means the model in production is the same version that was approved. A FAIL means the deployed version doesn't match the inventory, which could indicate an unauthorized model change.

**What to show the examiner:** The SWT3 ledger filtered by FIN-MRM.1 for your model. Each anchor represents a version check at a specific point in time. A continuous chain of PASS verdicts demonstrates that the model in production has always matched the approved inventory. Any FAIL creates an auditable record of when a mismatch was detected.

### FIN-VAL.1: Independent Model Validation

**SR 11-7 requires:** Model validation should be conducted by qualified staff who are independent of the model development process. "Effective challenge" involves critical analysis by objective, informed parties who can identify model limitations and assumptions.

**How SWT3 addresses it:** When an independent validator completes their review and signs off, the sign-off is anchored. Factor_a is 1 (validation required), factor_b is 1 if the validator signed, and factor_c records the number of days since the last validation. The anchor proves that an independent validation occurred on a specific date. Combined with the validator's identity in the ledger metadata, this satisfies the "effective challenge" documentation requirement.

**What to show the examiner:** The SWT3 anchor for FIN-VAL.1 along with the validator's identity from the ledger. The examiner can confirm: (1) the validation occurred, (2) when it occurred, (3) that the record hasn't been altered since. Factor_c (days since last validation) provides a built-in staleness indicator that the examiner can compare against your validation frequency policy.

### FIN-MON.1: Ongoing Performance Monitoring

**SR 11-7 requires:** Models should be subject to ongoing monitoring to confirm they continue to perform as expected. Monitoring should include process verification, benchmarking, and sensitivity analysis. Deterioration in model performance should trigger review.

**How SWT3 addresses it:** The SDK records the model's performance metric (e.g., PSI, CSI, AUC, Gini coefficient) against its defined threshold at each monitoring interval. Factor_a is the threshold, factor_b is the actual metric, and factor_c flags whether drift was detected. A PASS means the model is performing within bounds. A FAIL means the metric has breached the threshold, creating a tamper-evident record that drift was detected on a specific date.

**What to show the examiner:** The time series of FIN-MON.1 anchors for your model. The examiner can see: monitoring is happening at regular intervals, the model stayed within bounds (consecutive PASS verdicts), and if drift occurred, exactly when it was detected (the first FAIL). The daily Merkle rollup binds all monitoring anchors for a given day into a single root hash, enabling efficient verification of the entire monitoring history.

### FIN-OUT.1: Outcomes Analysis (Back-testing)

**SR 11-7 requires:** Outcomes analysis compares model outputs to actual outcomes. This should be performed regularly and with sufficient sample sizes to draw statistically meaningful conclusions.

**How SWT3 addresses it:** Each back-testing cycle is anchored with three factors: the required sample size (factor_a), the actual sample size used (factor_b), and whether the results were within tolerance (factor_c). A PASS means the back-test was performed with adequate data and the model's predictions aligned with reality. A FAIL means either the sample was insufficient or the predictions deviated beyond the acceptable range.

**What to show the examiner:** The SWT3 anchor for FIN-OUT.1 from the most recent back-testing cycle. Factor_a and factor_b prove the sample size was adequate. Factor_c proves the results were evaluated against a tolerance threshold. The anchor's timestamp proves when the analysis was conducted. Compare the frequency against your MRM policy to confirm the testing cadence is being met.

---

## Examiner Quick Reference

| Examiner question | Where to look |
|---|---|
| "Show me your model governance documentation" | FIN-GOV.1 anchors. Each one represents a committee vote with quorum and approval status. |
| "Is this model in your inventory?" | FIN-MRM.1 anchors. PASS = hash matches approved version. FAIL = mismatch detected. |
| "Who validated this model and when?" | FIN-VAL.1 anchors. Factor_b = validator signed. Metadata contains validator identity. |
| "How often do you monitor model performance?" | FIN-MON.1 anchor frequency. Daily anchors = daily monitoring. Weekly = weekly. |
| "Has this model drifted?" | FIN-MON.1 factor_c values. 0 = no drift. 1 = threshold breached. |
| "When was the last back-test?" | FIN-OUT.1 most recent anchor timestamp. |
| "Was the back-test sample adequate?" | FIN-OUT.1 factor_a (required) vs factor_b (actual). |
| "Can I verify this independently?" | Yes. SHA256 verification formula, no TeNova dependency. See verification instructions. |
| "How do I know these records weren't altered?" | Each anchor is a SHA-256 fingerprint. Daily Merkle rollup binds all anchors. Tampering breaks the root. |
| "Where is the data stored?" | Clearing Level 2+: factors only, no model details on TeNova side. See Clearing Protocol Addendum. |

---

## Recommended MRM Policy Language

When documenting SWT3 in your Model Risk Management Policy, consider language similar to the following:

> The institution uses the SWT3 Witness Anchor protocol (TeNova Axiom) to create tamper-evident records of model governance decisions, validation sign-offs, performance monitoring results, and outcomes analysis. Each model risk management activity produces a cryptographic anchor that is independently verifiable without reliance on the vendor's infrastructure. The SWT3 Clearing Protocol is configured at Level [1/2/3] to ensure that model-specific metadata is handled in accordance with the institution's data classification policy. The daily Merkle rollup provides an aggregate integrity digest that can be furnished to examiners as a single verification artifact covering all model risk management activities for a given period.

---

## Document Lineage

This overlay references and depends on:

- **SWT3 ToS Clearing Addendum** (April 4, 2026) - shared responsibility model
- **SWT3 Factor Handoff Protocol** (v1.0.0, April 4, 2026) - factor custody at Clearing Level 2+
- **Federal Reserve SR 11-7** (April 4, 2011) - Guidance on Model Risk Management
- **OCC Bulletin 2011-12** (April 4, 2011) - Sound Practices for Model Risk Management

---

*Patent Pending. SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC.*
