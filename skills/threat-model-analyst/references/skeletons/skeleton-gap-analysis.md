# Skeleton: 3-gap-analysis.md

> **⛔ Copy the template content below VERBATIM (excluding the outer code fence). Replace `[FILL]` placeholders. Do NOT add/rename/reorder sections.**
> `[FILL]` = single value | `[FILL-PROSE]` = paragraphs | `[REPEAT]...[END-REPEAT]` = N copies | `[CONDITIONAL]...[END-CONDITIONAL]` = include if condition met

---

```markdown
# Gap Analysis — TM7 vs. Code

This document identifies bidirectional gaps between the TM7 threat model and the code implementation.

---

## Gap Summary

| Gap Type | Count | Risk Level | Priority |
|----------|-------|-----------|----------|
| TM7-Only Elements | [FILL] | [FILL: High/Medium/Low] | [FILL: Design-reality gap] |
| Code-Only Components | [FILL] | [FILL: High/Medium/Low] | [FILL: Hidden attack surface] |
| TM7-Only Flows | [FILL] | [FILL: High/Medium/Low] | [FILL: Planned data paths not implemented] |
| Code-Only Flows | [FILL] | [FILL: High/Medium/Low] | [FILL: Actual data paths not modeled] |
| **Total Gaps** | **[FILL]** | | |

[FILL-PROSE: 2-3 paragraph executive summary of gap analysis findings. Highlight critical gaps and their security implications.]

<!-- ⛔ POST-TABLE CHECK: Verify Gap Summary:
  1. All counts are non-negative integers
  2. Total Gaps equals sum of all gap types
  3. Risk Level values are from: High, Medium, Low
  4. Priority column provides context (not just "High")
  If ANY check fails → FIX NOW. -->

---

## TM7-Only Elements

**Definition:** Elements present in the TM7 threat model but not implemented in the codebase.

[CONDITIONAL: Include if TM7-only elements exist]
| TM7 Element | Type | Reason | Impact | Recommendation |
|-------------|------|--------|--------|----------------|
[REPEAT: one row per TM7-only element]
| [FILL] | [FILL: Process/DataStore/ExternalEntity/DataFlow/Boundary] | [FILL: e.g., "Not implemented", "Future feature", "Design-only"] | [FILL: e.g., "Planned feature not yet available", "Security control gap"] | [FILL: e.g., "Implement component", "Update TM7 to remove", "No action (external service)"] |
[END-REPEAT]

### TM7-Only Elements by Category

| Category | Count | Examples |
|----------|-------|----------|
| Not Implemented | [FILL] | [FILL: 2-3 examples] |
| Future Features | [FILL] | [FILL: 2-3 examples] |
| Design-Only | [FILL] | [FILL: 2-3 examples] |
| External Services | [FILL] | [FILL: 2-3 examples] |
| Out of Scope | [FILL] | [FILL: 2-3 examples] |

[END-CONDITIONAL]

[CONDITIONAL: Include if no TM7-only elements]
*No TM7-only elements. All modeled components are implemented in the codebase.*
[END-CONDITIONAL]

<!-- ⛔ POST-SECTION CHECK: Verify TM7-Only Elements:
  1. Count matches Gap Summary table
  2. No element appears as both "mapped" in 1-element-mapping.md and "TM7-only" here
  3. All Type values are from: Process, DataStore, ExternalEntity, DataFlow, Boundary
  4. All Recommendations are actionable (not generic)
  If ANY check fails → FIX NOW. -->

---

## Code-Only Components

**Definition:** Code components not represented in the TM7 threat model.

[CONDITIONAL: Include if code-only components exist]
| Code Component | Type | Source Files | STRIDE Assessment | Risk Level | Recommendation |
|----------------|------|--------------|-------------------|-----------|----------------|
[REPEAT: one row per code-only component]
| [FILL] | [FILL: e.g., Process, DataStore, Service] | [FILL: relative file paths] | [FILL: comma-separated STRIDE categories OR "NotApplicable: <reason>"] | [FILL: High/Medium/Low] | [FILL: e.g., "Add to TM7", "Document threat coverage", "No action (internal utility)"] |
[END-REPEAT]

### Code-Only Components by STRIDE Risk

| STRIDE Category | Count | Components |
|-----------------|-------|------------|
| Spoofing | [FILL] | [FILL: comma-separated component names] |
| Tampering | [FILL] | [FILL: comma-separated component names] |
| Repudiation | [FILL] | [FILL: comma-separated component names] |
| Information Disclosure | [FILL] | [FILL: comma-separated component names] |
| Denial of Service | [FILL] | [FILL: comma-separated component names] |
| Elevation of Privilege | [FILL] | [FILL: comma-separated component names] |
| Abuse | [FILL] | [FILL: comma-separated component names] |
| NotApplicable | [FILL] | [FILL: comma-separated component names] |

[END-CONDITIONAL]

[CONDITIONAL: Include if no code-only components]
*No code-only components. All code components are represented in the TM7 model.*
[END-CONDITIONAL]

<!-- ⛔ POST-SECTION CHECK: Verify Code-Only Components:
  1. Count matches Gap Summary table
  2. No component appears as both "mapped" in 1-element-mapping.md and "code-only" here
  3. Every component has STRIDE Assessment OR explicit "NotApplicable: <reason>"
  4. STRIDE Category names are CANONICAL (no variants)
  5. Source Files contain at least one file path per component
  If ANY check fails → FIX NOW. -->

---

## Flow Mismatches

**Definition:** Data flow discrepancies between TM7 model and code implementation.

### TM7-Only Flows

**Definition:** Data flows present in TM7 but not found in code.

[CONDITIONAL: Include if TM7-only flows exist]
| Source | Target | Data Type | Reason | Impact | Recommendation |
|--------|--------|-----------|--------|--------|----------------|
[REPEAT: one row per TM7-only flow]
| [FILL: TM7 element name] | [FILL: TM7 element name] | [FILL: e.g., "User credentials", "API tokens"] | [FILL: e.g., "Flow not implemented", "Different routing in code"] | [FILL: e.g., "Planned feature gap", "Security control missing"] | [FILL: e.g., "Implement flow", "Update TM7"] |
[END-REPEAT]
[END-CONDITIONAL]

[CONDITIONAL: Include if no TM7-only flows]
*No TM7-only flows. All modeled data flows are present in the code.*
[END-CONDITIONAL]

### Code-Only Flows

**Definition:** Data flows present in code but not modeled in TM7.

[CONDITIONAL: Include if code-only flows exist]
| Source | Target | Data Type | STRIDE Tags | Risk Level | Recommendation |
|--------|--------|-----------|-------------|-----------|----------------|
[REPEAT: one row per code-only flow]
| [FILL: code component name] | [FILL: code component name] | [FILL: e.g., "Telemetry data", "Configuration"] | [FILL: comma-separated STRIDE categories OR "NotApplicable: <reason>"] | [FILL: High/Medium/Low] | [FILL: e.g., "Add to TM7", "Document threat coverage"] |
[END-REPEAT]
[END-CONDITIONAL]

[CONDITIONAL: Include if no code-only flows]
*No code-only flows. All code data flows are represented in the TM7 model.*
[END-CONDITIONAL]

<!-- ⛔ POST-SECTION CHECK: Verify Flow Mismatches:
  1. TM7-only flow count + matched flow count = total TM7 flows from phase9-context.txt
  2. No flow appears in multiple categories (tm7_only, code_only, matched)
  3. Every code-only flow has STRIDE Tags OR explicit "NotApplicable: <reason>"
  4. STRIDE Tag names are CANONICAL
  5. Flow mismatch counts match comparison-metadata.json
  If ANY check fails → FIX NOW. -->

### Flow Accounting

| Flow Category | TM7 Flows | Code Flows | Notes |
|---------------|-----------|------------|-------|
| Matched (in both) | [FILL] | [FILL] | Flows present in both TM7 and code |
| TM7-Only | [FILL] | — | Flows in TM7 but not in code |
| Code-Only | — | [FILL] | Flows in code but not in TM7 |
| **Total** | **[FILL]** | **[FILL]** | |

<!-- ⛔ POST-TABLE CHECK: Verify Flow Accounting:
  1. TM7 Flows total = Matched + TM7-Only
  2. Code Flows total = Matched + Code-Only
  3. No flow is unaccounted for (all flows classified)
  If ANY check fails → FIX NOW. -->

---

## Recommendations

### TM7 Model Updates

[CONDITIONAL: Include if TM7 updates are recommended]
[FILL-PROSE: Prioritized recommendations for updating the TM7 threat model to reflect code reality. Examples:
- "Add components X, Y, Z discovered in code but not modeled."
- "Remove component A which is no longer implemented."
- "Update data flow from B to C to match actual routing."]

| Priority | Recommendation | Affected Elements | Estimated Effort |
|----------|----------------|-------------------|------------------|
[REPEAT: one row per recommendation, sorted by priority]
| [FILL: High/Medium/Low] | [FILL] | [FILL: comma-separated element names] | [FILL: Low/Medium/High] |
[END-REPEAT]
[END-CONDITIONAL]

[CONDITIONAL: Include if no TM7 updates needed]
*No TM7 updates required. The threat model accurately represents the current codebase.*
[END-CONDITIONAL]

### Code Security Improvements

[CONDITIONAL: Include if code improvements are recommended]
[FILL-PROSE: Prioritized recommendations for improving code security to address TM7 threats and code-only risks. Examples:
- "Implement authentication for component X (TM7 threat T01.S currently Open)."
- "Add input validation to code-only component Y to address Tampering risk."
- "Document threat coverage for utility component Z."]

| Priority | Recommendation | Affected Components | Related Threats/Findings | Estimated Effort |
|----------|----------------|---------------------|------------------------|------------------|
[REPEAT: one row per recommendation, sorted by priority]
| [FILL: High/Medium/Low] | [FILL] | [FILL: comma-separated component names] | [FILL: e.g., "RECON-001 (Open)", "FIND-05"] | [FILL: Low/Medium/High] |
[END-REPEAT]
[END-CONDITIONAL]

[CONDITIONAL: Include if no code improvements needed]
*No code security improvements required based on gap analysis.*
[END-CONDITIONAL]

<!-- ⛔ POST-SECTION CHECK: Verify Recommendations:
  1. All Priority values are from: High, Medium, Low
  2. All Estimated Effort values are from: Low, Medium, High
  3. Related Threats/Findings reference actual RECON-NNN or FIND-NN IDs
  4. Recommendations are specific and actionable (not generic)
  If ANY check fails → FIX NOW. -->

---

## Gap Analysis Statistics

### Gap Distribution by Risk Level

| Risk Level | TM7-Only | Code-Only | Flow Mismatches | Total |
|-----------|----------|-----------|----------------|-------|
| High | [FILL] | [FILL] | [FILL] | [FILL] |
| Medium | [FILL] | [FILL] | [FILL] | [FILL] |
| Low | [FILL] | [FILL] | [FILL] | [FILL] |
| **Total** | **[FILL]** | **[FILL]** | **[FILL]** | **[FILL]** |

### Gap Resolution Priority

| Priority | Count | Gap Types | Next Steps |
|----------|-------|-----------|-----------|
| Critical (Address Immediately) | [FILL] | [FILL: comma-separated types] | [FILL: specific actions] |
| High (Address This Sprint) | [FILL] | [FILL: comma-separated types] | [FILL: specific actions] |
| Medium (Address Next Quarter) | [FILL] | [FILL: comma-separated types] | [FILL: specific actions] |
| Low (Backlog) | [FILL] | [FILL: comma-separated types] | [FILL: specific actions] |

---

## Analysis Notes

### Methodology

[FILL-PROSE: 1-2 paragraphs explaining gap analysis methodology. Examples:
- "Gap analysis compared TM7 element inventory (from phase9-context.txt) against code component inventory (from threat-inventory.json)."
- "TM7-only elements were classified based on mapping confidence scores (<0.50 = unmapped) and explicit reasons (external_only, out_of_scope)."
- "Code-only components were assessed for STRIDE risks using the Technology-Specific Security Checklist."]

### Limitations

[FILL-PROSE: 1-2 paragraphs describing analysis limitations. Examples:
- "Gap analysis is based on static code analysis and may not reflect runtime behavior or dynamic configurations."
- "Some code-only components may be internal utilities with minimal threat exposure but were flagged for completeness."
- "TM7 model may include future features or design-only elements not yet implemented, which is expected for design-ahead threat modeling."]

---

## Related Files

- See [1-element-mapping.md](1-element-mapping.md) for TM7 element → code component mappings
- See [2-threat-reconciliation.md](2-threat-reconciliation.md) for threat status and coverage
- See [comparison-dashboard.html](comparison-dashboard.html) for interactive gap visualization
- Raw gap analysis data: [comparison-metadata.json](comparison-metadata.json)
```

**Critical format rules baked into this skeleton:**
- Gap types are EXACT: TM7-Only Elements, Code-Only Components, TM7-Only Flows, Code-Only Flows
- STRIDE category names are CANONICAL (no variants allowed)
- Every code-only component has STRIDE Assessment OR explicit "NotApplicable: <reason>"
- Every code-only flow has STRIDE Tags OR explicit "NotApplicable: <reason>"
- Flow accounting must be complete: TM7 total = Matched + TM7-Only
- No element/component appears in both "mapped" and "gap" categories
- All sections are mandatory (no optional sections except conditionals marked with `[CONDITIONAL]`)
- Recommendations are specific and actionable (not generic)
- Gap counts match between markdown and comparison-metadata.json
- Risk Level values are from: High, Medium, Low
- Estimated Effort values are from: Low, Medium, High
