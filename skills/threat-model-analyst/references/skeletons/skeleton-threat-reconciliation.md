# Skeleton: 2-threat-reconciliation.md

> **⛔ Copy the template content below VERBATIM (excluding the outer code fence). Replace `[FILL]` placeholders. Do NOT add/rename/reorder sections.**
> `[FILL]` = single value | `[FILL-PROSE]` = paragraphs | `[REPEAT]...[END-REPEAT]` = N copies | `[CONDITIONAL]...[END-CONDITIONAL]` = include if condition met

---

```markdown
# Threat Reconciliation — TM7 vs. Code

This document reconciles every TM7 threat against the codebase, determining status with evidence.

---

## Reconciliation Summary

| Metric | Value |
|--------|-------|
| Total TM7 Threats | [FILL] |
| KB-Based Threats | [FILL] |
| LLM-Augmented Threats | [FILL] |
| Coverage Percentage | [FILL]% |

### Status Distribution

| Status | Count | Percentage | Definition |
|--------|-------|-----------|------------|
| ✅ Addressed | [FILL] | [FILL]% | Code has explicit control preventing this threat |
| 🛡️ Mitigated | [FILL] | [FILL]% | Code has detection/response (not prevention) |
| 🔴 Open | [FILL] | [FILL]% | No code defense found — needs remediation |
| ⚪ NotApplicable | [FILL] | [FILL]% | Threat scenario doesn't exist in this codebase |
| 🟡 NotInCode | [FILL] | [FILL]% | TM7 element not mapped to any code component |
| 🟣 Deferred | [FILL] | [FILL]% | Mitigated by infrastructure/platform, not app code |
| **Total** | **[FILL]** | **100%** | |

<!-- ⛔ POST-TABLE CHECK: Verify Status Distribution:
  1. Status names are EXACT: Addressed, Mitigated, Open, NotApplicable, NotInCode, Deferred
  2. Status emojis are EXACT: ✅🛡️🔴⚪🟡🟣
  3. Total count equals Total TM7 Threats
  4. Percentages sum to 100%
  5. Coverage Percentage = (Addressed + Mitigated) / Total * 100
  If ANY check fails → FIX NOW. -->

---

## STRIDE Category Breakdown

| Category | Total Threats | Addressed | Mitigated | Open | NotApplicable | NotInCode | Deferred |
|----------|--------------|-----------|-----------|------|---------------|-----------|----------|
| Spoofing | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] |
| Tampering | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] |
| Repudiation | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] |
| Information Disclosure | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] |
| Denial of Service | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] |
| Elevation of Privilege | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] | [FILL] |
| **Total** | **[FILL]** | **[FILL]** | **[FILL]** | **[FILL]** | **[FILL]** | **[FILL]** | **[FILL]** |

<!-- ⛔ POST-TABLE CHECK: Verify STRIDE Category Breakdown:
  1. Category names are CANONICAL: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
  2. NO variants allowed: "Denial Of Service", "DoS", "Info Disclosure", "Elevation Of Privilege", "Elevation of Privileges"
  3. Total row sums match Status Distribution table
  4. All cells have integer values (no nulls)
  If ANY check fails → FIX NOW. -->

---

## Open Threats by Priority

[CONDITIONAL: Include if Open threats exist]
| Threat ID | Category | Title | Component | Priority | Recommended Controls |
|-----------|----------|-------|-----------|----------|---------------------|
[REPEAT: one row per Open threat, sorted by Priority (Tier 1 first, then Tier 2, then Tier 3)]
| [FILL: RECON-NNN] | [FILL: STRIDE category] | [FILL] | [FILL] | [FILL: Tier 1/2/3] | [FILL: comma-separated controls] |
[END-REPEAT]
[END-CONDITIONAL]

[CONDITIONAL: Include if no Open threats]
*No open threats. All TM7 threats are either addressed, mitigated, or not applicable to the codebase.*
[END-CONDITIONAL]

<!-- ⛔ POST-TABLE CHECK: Verify Open Threats:
  1. Count matches "Open" count from Status Distribution table
  2. All Priority values are from: Tier 1, Tier 2, Tier 3
  3. All Category values are canonical STRIDE names
  4. Recommended Controls are actionable (not generic like "implement security")
  If ANY check fails → FIX NOW. -->

---

## Per-Threat Reconciliation

[REPEAT: one subsection per TM7 threat, grouped by status (Addressed first, then Mitigated, Open, NotApplicable, NotInCode, Deferred)]

### [FILL: Status] Threats

#### RECON-[FILL: NNN]: [FILL: Threat Title]

| Attribute | Value |
|-----------|-------|
| TM7 Threat ID | [FILL: original TM7 threat ID] |
| STRIDE Category | [FILL: Spoofing/Tampering/Repudiation/Information Disclosure/Denial of Service/Elevation of Privilege] |
| Source | [FILL: KB / LLM] |
| TM7 Interaction | [FILL: e.g., "User → Web Server"] |
| Mapped Code Components | [FILL: source → target, or "—" if NotInCode] |
| Mapping Confidence | [FILL: 0.XX or "—" if NotInCode] |
| Status | [FILL: Addressed/Mitigated/Open/NotApplicable/NotInCode/Deferred] |

**Justification:**
[FILL-PROSE: 1-2 sentences explaining why this status was assigned]

[CONDITIONAL: Include for Addressed/Mitigated/Deferred status]
**Evidence:**
| Type | Location | Pattern | Confidence |
|------|----------|---------|------------|
[REPEAT: one row per evidence entry]
| [FILL: code_pattern/dependency/architecture/infrastructure_mitigation] | [FILL: file:line or component name] | [FILL: specific pattern or control name] | [FILL: 0.XX] |
[END-REPEAT]
[END-CONDITIONAL]

[CONDITIONAL: Include for Addressed/Mitigated status]
**Related Code Findings:**
[REPEAT: one link per related finding]
- [FIND-[FILL: NN]](5-findings.md#find-[FILL: nn]-[FILL: title-slug]): [FILL: finding title]
[END-REPEAT]
[END-CONDITIONAL]

[CONDITIONAL: Include for Open status]
**Remediation:**
- **Controls:** [FILL: comma-separated list of recommended controls]
- **Effort:** [FILL: Low / Medium / High]
- **Priority:** [FILL: Tier 1 / Tier 2 / Tier 3]
[END-CONDITIONAL]

[CONDITIONAL: Include for NotApplicable status]
**Why Not Applicable:**
[FILL-PROSE: specific reason this threat scenario doesn't exist in the codebase, e.g., "This threat assumes a web-facing deployment, but the code is a desktop application with no network listener."]
[END-CONDITIONAL]

[CONDITIONAL: Include for NotInCode status]
**Why Not In Code:**
[FILL-PROSE: specific reason no code mapping exists, e.g., "TM7 element 'External API Gateway' has no local code implementation. This is an external service managed separately."]
[END-CONDITIONAL]

[CONDITIONAL: Include for Deferred status]
**Infrastructure Mitigation:**
[FILL-PROSE: specific platform/infrastructure control handling this threat, e.g., "Container network isolation enforced by Kubernetes NetworkPolicy prevents unauthorized pod-to-pod communication."]
[END-CONDITIONAL]

---

[END-REPEAT: repeat per-threat block for all threats]

<!-- ⛔ POST-SECTION CHECK: Verify Per-Threat Reconciliation:
  1. Threat count matches Total TM7 Threats from summary
  2. Every threat has a non-empty Justification field
  3. Addressed/Mitigated threats have at least 1 Evidence entry
  4. Open threats have Remediation with all 3 fields (Controls, Effort, Priority)
  5. NotApplicable/NotInCode/Deferred threats have specific justification (not generic)
  6. All STRIDE categories use canonical names
  7. All evidence Type values are from: code_pattern, dependency, architecture, code_absence, infrastructure_mitigation
  8. All Related Code Findings are hyperlinks to 5-findings.md
  If ANY check fails → FIX NOW. -->

---

## Threat Clustering Analysis

[FILL-PROSE: Summary of how TM7 threats (per-flow granularity) map to code findings (per-control granularity). Examples:
- "Multiple TM7 Spoofing threats (T01.S, T03.S, T05.S) are all addressed by FIND-01: Missing Authentication on the API Gateway component."
- "TM7 Tampering threats (T02.T, T04.T) cluster around FIND-02: Input Validation, covering both user input and API request validation."]

### Clustering Summary

| Code Finding | TM7 Threats Addressed | STRIDE Categories | Status Summary |
|--------------|----------------------|-------------------|----------------|
[REPEAT: one row per code finding that addresses multiple TM7 threats]
| [FIND-[FILL: NN]](5-findings.md#find-[FILL: nn]-[FILL: title-slug]) | [FILL: N threats] | [FILL: comma-separated STRIDE categories] | [FILL: e.g., "All Addressed", "2 Addressed, 1 Open"] |
[END-REPEAT]

<!-- ⛔ POST-TABLE CHECK: Verify Threat Clustering:
  1. All Code Finding cells are hyperlinks to 5-findings.md
  2. TM7 Threats Addressed count is accurate (cross-reference per-threat reconciliation)
  3. STRIDE Categories use canonical names
  4. Status Summary reflects actual threat statuses
  If ANY check fails → FIX NOW. -->

---

## Reconciliation Verification

### Confidence Distribution

| Confidence Range | Addressed/Mitigated Count | Percentage |
|------------------|--------------------------|------------|
| High (≥0.70) | [FILL] | [FILL]% |
| Medium (0.50-0.69) | [FILL] | [FILL]% |
| Low (<0.50) | [FILL] | [FILL]% |

[FILL-PROSE: 1-2 sentences summarizing confidence quality, e.g., "87% of Addressed/Mitigated threats have high-confidence mappings (≥0.70). Medium and low confidence reconciliations are flagged for manual review."]

### Evidence Quality

| Evidence Type | Count | Percentage | Examples |
|---------------|-------|-----------|----------|
| code_pattern | [FILL] | [FILL]% | [FILL: 2-3 examples] |
| dependency | [FILL] | [FILL]% | [FILL: 2-3 examples] |
| architecture | [FILL] | [FILL]% | [FILL: 2-3 examples] |
| infrastructure_mitigation | [FILL] | [FILL]% | [FILL: 2-3 examples] |
| code_absence | [FILL] | [FILL]% | [FILL: 2-3 examples] |

---

## Related Files

- See [1-element-mapping.md](1-element-mapping.md) for TM7 element → code component mappings
- See [3-gap-analysis.md](3-gap-analysis.md) for bidirectional gap analysis
- See [5-findings.md](5-findings.md) for detailed code findings
- See [comparison-dashboard.html](comparison-dashboard.html) for interactive reconciliation visualization
- Raw reconciliation data: [comparison-metadata.json](comparison-metadata.json)
```

**Critical format rules baked into this skeleton:**
- Status names are EXACT: Addressed, Mitigated, Open, NotApplicable, NotInCode, Deferred (never abbreviated)
- Status emojis are EXACT: ✅🛡️🔴⚪🟡🟣 (never changed)
- STRIDE category names are CANONICAL (no variants allowed)
- Coverage Percentage = (Addressed + Mitigated) / Total * 100 (exact formula)
- Every threat has non-empty Justification field (no "TBD" or "—")
- Addressed/Mitigated require evidence array with at least 1 entry
- Open threats require Remediation object with Controls, Effort, Priority
- Threat clustering section is MANDATORY (even if no clustering)
- All related code findings are hyperlinks to 5-findings.md
- Evidence types are from: code_pattern, dependency, architecture, code_absence, infrastructure_mitigation
- All sections are mandatory (no optional sections except conditionals marked with `[CONDITIONAL]`)
