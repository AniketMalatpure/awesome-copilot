# Skeleton: 1-element-mapping.md

> **⛔ Copy the template content below VERBATIM (excluding the outer code fence). Replace `[FILL]` placeholders. Do NOT add/rename/reorder sections.**
> `[FILL]` = single value | `[FILL-PROSE]` = paragraphs | `[REPEAT]...[END-REPEAT]` = N copies | `[CONDITIONAL]...[END-CONDITIONAL]` = include if condition met

---

```markdown
# Element Mapping — TM7 to Code

This document maps TM7 threat model elements to code components with confidence scores and evidence.

---

## Mapping Summary

| Metric | Value |
|--------|-------|
| Total TM7 Elements | [FILL] |
| Mapped with High Confidence (≥0.80) | [FILL] ([FILL]%) |
| Mapped with Medium Confidence (0.50-0.79) | [FILL] ([FILL]%) |
| Mapped with Low Confidence (<0.50) | [FILL] ([FILL]%) |
| Unmapped (external/out-of-scope/unmappable) | [FILL] ([FILL]%) |
| Total Code Components | [FILL] |
| Code-Only Components (not in TM7) | [FILL] |

<!-- ⛔ POST-TABLE CHECK: Verify Mapping Summary:
  1. All percentages sum to 100% (or close due to rounding)
  2. Total TM7 Elements matches metadata.tm7_element_count
  3. Total Code Components matches metadata.code_component_count
  4. All metrics have integer values (no nulls)
  If ANY check fails → FIX NOW. -->

---

## Confidence Legend

| Level | Range | Meaning | Action Required |
|-------|-------|---------|-----------------|
| 🟢 High | ≥0.80 | Strong evidence of mapping | None — mapping confirmed |
| 🟡 Medium | 0.50-0.79 | Plausible mapping with some uncertainty | Review recommended |
| 🟠 Low | <0.50 | Weak evidence or multiple candidates | Manual verification required |
| ⚪ Unmapped | N/A | No code implementation found | Classify as external/out-of-scope/unmappable |

---

## Element Mapping Table

| TM7 Element | Type | Code Component(s) | Confidence | Status | Evidence |
|-------------|------|-------------------|------------|--------|----------|
[REPEAT: one row per TM7 element, sorted by confidence descending, then by element name]
| [FILL: TM7 element name] | [FILL: Process/DataStore/ExternalEntity/DataFlow/Boundary] | [FILL: code component name(s), comma-separated if multiple] | [FILL: 0.XX] 🟢/🟡/🟠 | [FILL: confirmed/pending/unmappable/external_only/out_of_scope] | [FILL: match reasons, e.g., "exact_name_match, file_path_similarity" or "No local code found"] |
[END-REPEAT]

<!-- ⛔ POST-TABLE CHECK: Verify Element Mapping Table:
  1. Row count equals Total TM7 Elements from summary
  2. Every row has a confidence value (0.00-1.00) OR status is unmapped/external_only/out_of_scope
  3. Confidence emoji matches range: 🟢 (≥0.80), 🟡 (0.50-0.79), 🟠 (<0.50), ⚪ (unmapped)
  4. Status values are from: confirmed, pending, unmappable, external_only, out_of_scope
  5. Type values are from: Process, DataStore, ExternalEntity, DataFlow, Boundary
  6. Evidence column is non-empty for all rows
  If ANY check fails → FIX NOW. -->

---

## Unmapped TM7 Elements

[CONDITIONAL: Include if unmapped elements exist]
| TM7 Element | Type | Reason | Recommendation |
|-------------|------|--------|----------------|
[REPEAT: one row per unmapped element]
| [FILL] | [FILL] | [FILL: e.g., "External Azure service, no local code", "Design-only element, not implemented", "Out of scope for this analysis"] | [FILL: e.g., "No action required", "Update TM7 if implementation planned", "Verify with team"] |
[END-REPEAT]
[END-CONDITIONAL]

[CONDITIONAL: Include if no unmapped elements]
*All TM7 elements successfully mapped to code components.*
[END-CONDITIONAL]

---

## Code-Only Components (Not in TM7)

[CONDITIONAL: Include if code-only components exist]
| Code Component | Type | Source Files | Reason Not in TM7 |
|----------------|------|--------------|-------------------|
[REPEAT: one row per code-only component]
| [FILL] | [FILL: e.g., Process, DataStore, Service] | [FILL: relative file paths, comma-separated] | [FILL: e.g., "Added after TM7 creation", "Internal implementation detail", "Not threat-relevant"] |
[END-REPEAT]
[END-CONDITIONAL]

[CONDITIONAL: Include if no code-only components]
*All code components are represented in the TM7 model.*
[END-CONDITIONAL]

<!-- ⛔ POST-SECTION CHECK: Verify Code-Only Components:
  1. If code-only components exist, they are listed in 3-gap-analysis.md
  2. Each code-only component has STRIDE assessment in gap analysis (or explicit NotApplicable rationale)
  3. Source Files contain at least one file path per component
  If ANY check fails → FIX NOW. -->

---

## Mapping Methodology

### Tier 1: Exact/Fuzzy Name Match (Confidence: 0.90-1.00)
[FILL-PROSE: Examples of exact or fuzzy name matches found, e.g., "TM7 'SQL Database' matched to code 'SqlDatabaseService' with 0.95 confidence."]

### Tier 2: Type + Attribute Match (Confidence: 0.70-0.89)
[FILL-PROSE: Examples of type-based matches, e.g., "TM7 Process element with auth=No matched to code class with no auth middleware at 0.82 confidence."]

### Tier 3: Boundary Containment (Confidence: 0.50-0.69)
[FILL-PROSE: Examples of boundary-based matches, e.g., "TM7 elements within 'Internal Network' boundary matched to code components in 'Internal' namespace at 0.65 confidence."]

### Tier 4: LLM Reasoning (Confidence: 0.30-0.49)
[FILL-PROSE: Examples of LLM-inferred matches, e.g., "TM7 'Authentication Service' mapped to code 'AuthHandler' based on architectural context at 0.45 confidence. Marked as pending for review."]

---

## Mapping Statistics

### Confidence Distribution

| Confidence Range | Count | Percentage | Status Summary |
|------------------|-------|-----------|----------------|
| 0.90-1.00 | [FILL] | [FILL]% | All confirmed |
| 0.80-0.89 | [FILL] | [FILL]% | All confirmed |
| 0.70-0.79 | [FILL] | [FILL]% | Confirmed or pending |
| 0.50-0.69 | [FILL] | [FILL]% | Pending review |
| 0.30-0.49 | [FILL] | [FILL]% | Low confidence, pending |
| <0.30 | [FILL] | [FILL]% | Unmappable |

### Mapping Granularity

| Pattern | Count | Examples |
|---------|-------|----------|
| 1-to-1 (TM7 → Code) | [FILL] | [FILL: 2-3 examples] |
| 1-to-many (TM7 → multiple Code) | [FILL] | [FILL: 2-3 examples with multi_element_note] |
| Many-to-1 (multiple TM7 → Code) | [FILL] | [FILL: 2-3 examples with consolidation note] |
| Many-to-many | [FILL] | [FILL: 2-3 examples with relationship note] |

<!-- ⛔ POST-SECTION CHECK: Verify Mapping Statistics:
  1. Confidence distribution sums to total mapped elements (excluding unmapped)
  2. Mapping granularity patterns sum to total mappings
  3. All examples include element names and confidence scores
  If ANY check fails → FIX NOW. -->

---

## Verification Notes

### High-Confidence Mappings (≥0.80)
[FILL-PROSE: Summary of high-confidence mappings and validation approach, e.g., "52 of 60 mappings (87%) achieved high confidence through exact name matching and file path correlation. All high-confidence mappings were cross-referenced against component inventories."]

### Medium-Confidence Mappings (0.50-0.79)
[FILL-PROSE: Summary of medium-confidence mappings and recommended actions, e.g., "8 mappings require manual review due to ambiguous naming or multiple candidate components. These are marked 'pending' in reconciliation."]

### Unmapped Elements
[FILL-PROSE: Summary of unmapped elements and justification, e.g., "5 TM7 elements are external Azure services with no local code implementation. 2 elements are design-only and not implemented in the current codebase version."]

---

## Related Files

- See [2-threat-reconciliation.md](2-threat-reconciliation.md) for threat status based on these mappings
- See [3-gap-analysis.md](3-gap-analysis.md) for bidirectional gap analysis
- See [comparison-dashboard.html](comparison-dashboard.html) for interactive mapping visualization
- Raw mapping data: [comparison-metadata.json](comparison-metadata.json)
```

**Critical format rules baked into this skeleton:**
- Confidence values are floats (0.00-1.00) with emoji indicators (🟢🟡🟠⚪)
- Status values are EXACT: confirmed, pending, unmappable, external_only, out_of_scope
- Type values are EXACT: Process, DataStore, ExternalEntity, DataFlow, Boundary
- Evidence column is ALWAYS non-empty (never "—" or null)
- Unmapped and code-only sections are conditional (present only if applicable)
- Mapping statistics tables are MANDATORY (even if all zeros)
- Verification Notes section provides prose summary (not just tables)
- Related Files section includes all 4 cross-references
