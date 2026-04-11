# Skeleton: 0-comparison-assessment.md

> **⛔ Copy the template content below VERBATIM (excluding the outer code fence). Replace `[FILL]` placeholders. Do NOT add/rename/reorder sections.**
> `[FILL]` = single value | `[FILL-PROSE]` = paragraphs | `[REPEAT]...[END-REPEAT]` = N copies | `[CONDITIONAL]...[END-CONDITIONAL]` = include if condition met

---

```markdown
# Comparative Threat Analysis — Assessment

---

## Report Files

| File | Description |
|------|-------------|
| [0-comparison-assessment.md](0-comparison-assessment.md) | This document — executive summary, risk comparison, action plan, metadata |
| [1-element-mapping.md](1-element-mapping.md) | TM7 element → code component mapping table with confidence scores |
| [1.1-element-mapping-diagram.mmd](1.1-element-mapping-diagram.mmd) | Mermaid diagram linking TM7 elements to code components |
| [2-threat-reconciliation.md](2-threat-reconciliation.md) | Per-threat status (Addressed/Mitigated/Open/NotApplicable/NotInCode/Deferred) with evidence |
| [3-gap-analysis.md](3-gap-analysis.md) | Bidirectional gaps: TM7-only elements, code-only components, flow mismatches, recommendations |
| [4-composite-threatmodel.md](4-composite-threatmodel.md) | Unified threat model merging TM7 and code perspectives |
| [4.1-composite-threatmodel.mmd](4.1-composite-threatmodel.mmd) | Composite DFD diagram (Mermaid source) |
| [5-findings.md](5-findings.md) | Unified findings (code findings + TM7 open threats) |
| [comparison-dashboard.html](comparison-dashboard.html) | Interactive HTML dashboard with heatmaps, status badges, evidence panels |
| [comparison-metadata.json](comparison-metadata.json) | Structured data: mappings, statuses, metrics, audit trail |

### Code Threat Model (Full Mode 1 Output)
| File | Description |
|------|-------------|
| [0.1-architecture.md](0.1-architecture.md) | Architecture overview, components, scenarios, tech stack |
| [1-threatmodel.md](1-threatmodel.md) | Code threat model DFD with element, flow, and boundary tables |
| [1.1-threatmodel.mmd](1.1-threatmodel.mmd) | Pure Mermaid DFD source file for code |
| [2-stride-analysis.md](2-stride-analysis.md) | Full STRIDE-A analysis for all code components |
| [3-findings.md](3-findings.md) | Prioritized code security findings with remediation |
| [0-assessment.md](0-assessment.md) | Code threat model executive summary |
| [threat-inventory.json](threat-inventory.json) | Structured code threat inventory |

### TM7 Threat Analysis (Full Mode 3 Output)
| File | Description |
|------|-------------|
| [threat-analysis-report.html](threat-analysis-report.html) | TM7 STRIDE threat report (KB + LLM threats) |
| [threat-analysis-data.json](threat-analysis-data.json) | Structured TM7 threat inventory |
| [phase9-context.txt](phase9-context.txt) | Pre-computed TM7 context (elements, flows, boundaries) |

<!-- ⛔ POST-TABLE CHECK: Verify Report Files:
  1. `0-comparison-assessment.md` is the FIRST row in the first table
  2. All 10 comparative files are listed
  3. Code threat model section lists all 7 Mode 1 files
  4. TM7 threat analysis section lists all 3 Mode 3 files
  If ANY check fails → FIX NOW. -->

---

## Executive Summary

[FILL-PROSE: 2-3 paragraph summary comparing TM7 design model against actual code implementation. Highlight alignment and gaps.]

This comparative analysis evaluated **[FILL: TM7 file name]** against the codebase at **[FILL: repo path]**. The TM7 model contains [FILL: N] elements and [FILL: M] threats. The code analysis identified [FILL: X] components and [FILL: Y] security findings.

### Component Mapping

**[FILL: NN]% of TM7 elements** successfully mapped to code components with high confidence (≥0.70). [FILL: N] elements remain unmapped ([FILL: reason summary — e.g., "external services", "design-only", "out of scope"]).

### Threat Reconciliation

**Coverage: [FILL: NN]%** — [FILL: N] of [FILL: M] TM7 threats are Addressed or Mitigated in the code.

| Status | Count | Percentage |
|--------|-------|-----------|
| Addressed | [FILL] | [FILL]% |
| Mitigated | [FILL] | [FILL]% |
| Open | [FILL] | [FILL]% |
| NotApplicable | [FILL] | [FILL]% |
| NotInCode | [FILL] | [FILL]% |
| Deferred | [FILL] | [FILL]% |
| **Total** | **[FILL]** | **100%** |

<!-- ⛔ POST-SECTION CHECK: Verify Threat Reconciliation Table:
  1. Status names match reconciliation schema EXACTLY: Addressed, Mitigated, Open, NotApplicable, NotInCode, Deferred
  2. Total count equals TM7 threat count from metadata
  3. Percentages sum to 100%
  If ANY check fails → FIX NOW. -->

### Risk Comparison

| Perspective | Risk Rating | Basis |
|------------|-------------|-------|
| TM7 Design Model | [FILL: Critical / Elevated / Moderate / Low] | [FILL: KB + LLM threat count and STRIDE distribution] |
| Code Implementation | [FILL: Critical / Elevated / Moderate / Low] | [FILL: Tier 1/2/3 finding distribution and exploitability] |
| Comparative Assessment | [FILL: Critical / Elevated / Moderate / Low] | [FILL: Open threat count + code-only attack surface] |

[FILL-PROSE: 1-2 paragraph risk comparison justification]

<!-- ⛔ POST-SECTION CHECK: Verify Risk Comparison:
  1. All three rows present: TM7 Design Model, Code Implementation, Comparative Assessment
  2. Risk Rating values are from: Critical, Elevated, Moderate, Low
  3. Basis column provides specific metrics (not generic text)
  If ANY check fails → FIX NOW. -->

---

## Component Coverage

### Mapping Quality

| Confidence Level | Count | Percentage | Example Mappings |
|------------------|-------|-----------|------------------|
| High (≥0.80) | [FILL] | [FILL]% | [FILL: 2-3 examples] |
| Medium (0.50-0.79) | [FILL] | [FILL]% | [FILL: 2-3 examples] |
| Low (<0.50) | [FILL] | [FILL]% | [FILL: 2-3 examples] |
| Unmapped | [FILL] | [FILL]% | [FILL: 2-3 examples with reasons] |

### Gap Summary

| Gap Type | Count | Impact |
|----------|-------|--------|
| TM7-Only Elements | [FILL] | [FILL: Design-reality gap, unimplemented features] |
| Code-Only Components | [FILL] | [FILL: Hidden attack surface, unmodeled risks] |
| TM7-Only Flows | [FILL] | [FILL: Planned data paths not implemented] |
| Code-Only Flows | [FILL] | [FILL: Actual data paths not in threat model] |

---

## Threat Coverage Summary

### STRIDE Distribution (TM7 vs. Code)

| Category | TM7 Threats | Code Findings | Status |
|----------|-------------|---------------|--------|
| Spoofing | [FILL] | [FILL] | [FILL: Coverage assessment] |
| Tampering | [FILL] | [FILL] | [FILL: Coverage assessment] |
| Repudiation | [FILL] | [FILL] | [FILL: Coverage assessment] |
| Information Disclosure | [FILL] | [FILL] | [FILL: Coverage assessment] |
| Denial of Service | [FILL] | [FILL] | [FILL: Coverage assessment] |
| Elevation of Privilege | [FILL] | [FILL] | [FILL: Coverage assessment] |
| Abuse (code-only) | — | [FILL] | [FILL: Code-specific abuse cases] |
| **Total** | **[FILL]** | **[FILL]** | |

<!-- ⛔ POST-TABLE CHECK: Verify STRIDE Distribution:
  1. Category names are CANONICAL: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
  2. NO variants allowed: "Denial Of Service", "DoS", "Info Disclosure", "Elevation Of Privilege"
  3. Abuse row is present for code-only findings (TM7 column is "—")
  4. Total row sums match threat counts from metadata
  If ANY check fails → FIX NOW. -->

### Open Threats by Priority

| Priority | Count | Risk Level | Top Examples |
|----------|-------|-----------|--------------|
| Tier 1 | [FILL] | 🔴 Critical | [FILL: 1-3 threat titles] |
| Tier 2 | [FILL] | 🟠 Elevated | [FILL: 1-3 threat titles] |
| Tier 3 | [FILL] | 🟡 Moderate | [FILL: 1-3 threat titles] |

---

## Action Plan

### Immediate Actions (Tier 1 Open Threats)

[CONDITIONAL: Include if Tier 1 open threats exist]
| Threat ID | Title | Component | Recommended Control | Effort |
|-----------|-------|-----------|---------------------|--------|
[REPEAT: one row per Tier 1 open threat, max 10]
| [FILL] | [FILL] | [FILL] | [FILL] | [FILL: Low / Medium / High] |
[END-REPEAT]
[END-CONDITIONAL]

[CONDITIONAL: Include if no Tier 1 open threats]
*No Tier 1 open threats identified. All directly exploitable risks are addressed or mitigated.*
[END-CONDITIONAL]

### Code Improvements (Code-Only Components)

[FILL-PROSE: or "No code-only components with unassessed STRIDE risks."]

| Component | STRIDE Risk | Recommended Action | Effort |
|-----------|-------------|-------------------|--------|
[REPEAT]
| [FILL] | [FILL] | [FILL] | [FILL: Low / Medium / High] |
[END-REPEAT]

### TM7 Updates (Design-Reality Gaps)

[FILL-PROSE: or "TM7 model is current and accurately represents the codebase."]

| TM7 Element/Flow | Issue | Recommended Update | Priority |
|------------------|-------|-------------------|----------|
[REPEAT]
| [FILL] | [FILL] | [FILL] | [FILL: High / Medium / Low] |
[END-REPEAT]

---

## Analysis Context & Assumptions

### Analysis Scope
| Constraint | Description |
|------------|-------------|
| TM7 Source | [FILL: TM7 file path] |
| Code Repository | [FILL: repo path] |
| Code Commit | [FILL: SHA] ([FILL: date]) |
| TM7 Surface Filter | [FILL: or "None (all surfaces analyzed)"] |
| Excluded Code Paths | [FILL: or "None"] |
| Focus Areas | [FILL: e.g., "Authentication, data flows, trust boundaries"] |

### Mapping Methodology
| Tier | Method | Confidence Range | Example |
|------|--------|-----------------|---------|
| 1 | Exact/fuzzy name match | 0.90-1.00 | TM7 "SQL Database" → Code "SqlDatabaseService" |
| 2 | Type + attribute match | 0.70-0.89 | TM7 Process(auth=No) → Code class with no auth middleware |
| 3 | Boundary containment | 0.50-0.69 | TM7 elements in "Internal Network" → Code classes in same namespace |
| 4 | LLM reasoning | 0.30-0.49 | LLM infers from architecture context |

### Needs Verification
| Item | Question | What to Check | Why Uncertain |
|------|----------|---------------|---------------|
[REPEAT]
| [FILL] | [FILL] | [FILL] | [FILL] |
[END-REPEAT]

[CONDITIONAL: Include if no verification items]
| — | — | — | No items require manual verification. |
[END-CONDITIONAL]

### Comparative Analysis Assumptions
[FILL-PROSE: 2-3 paragraphs describing assumptions made during mapping and reconciliation. Examples:
- External-only elements (e.g., Azure services) were not expected to have local code implementations
- TM7 elements marked as "out of scope" were excluded from mapping
- Infrastructure-level mitigations (OS permissions, firewall rules) were categorized as "Deferred"
- Code-only components discovered after TM7 creation were flagged for threat model update]

---

## References Consulted

### Security Standards
| Standard | URL | How Used |
|----------|-----|----------|
| Microsoft SDL Bug Bar | https://www.microsoft.com/en-us/msrc/sdlbugbar | Severity classification |
| STRIDE Threat Modeling | https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats | Threat categorization |
| TM7 KnowledgeBase | (embedded in .tm7 file) | KB-based threat generation |
[REPEAT: additional standards if used]
| [FILL] | [FILL] | [FILL] |
[END-REPEAT]

### Component Documentation
| Component | Documentation URL | Relevant Section |
|-----------|------------------|------------------|
[REPEAT]
| [FILL] | [FILL] | [FILL] |
[END-REPEAT]

---

## Report Metadata

| Field | Value |
|-------|-------|
| TM7 File | `[FILL]` |
| Code Repository | `[FILL]` |
| Git Branch | `[FILL]` |
| Git Commit | `[FILL: SHA from git rev-parse --short HEAD]` (`[FILL: date from git log -1 --format="%ai"]`) |
| TM7 Analysis Version | `[FILL: from phase9-context.txt or threat-analysis-data.json]` |
| Code Analysis Version | `[FILL: from threat-inventory.json]` |
| Model | `[FILL]` |
| Machine Name | `[FILL]` |
| Analysis Started | `[FILL]` |
| Analysis Completed | `[FILL]` |
| Duration | `[FILL]` |
| Output Folder | `[FILL]` |
| Prompt | `[FILL: the user's prompt text that triggered this comparative analysis]` |

<!-- ⛔ POST-TABLE CHECK: Verify Report Metadata:
  1. ALL values wrapped in backticks: `value`
  2. Git Commit includes date in parentheses: `SHA` (`date`)
  3. Duration field is present (not missing)
  4. Model field states the actual model name
  5. Analysis Started and Analysis Completed are real timestamps
  If ANY check fails → FIX NOW. -->

---

## Classification Reference

<!-- SKELETON INSTRUCTION: Copy the table below verbatim. Do NOT modify values. Do NOT copy this HTML comment into the output. -->

| Classification | Values |
|---------------|--------|
| **Reconciliation Status** | **Addressed** (code prevents threat) · **Mitigated** (code detects/responds) · **Open** (no defense found) · **NotApplicable** (scenario doesn't exist) · **NotInCode** (no code mapping) · **Deferred** (infrastructure/platform handles) |
| **Mapping Confidence** | **High** (≥0.80) · **Medium** (0.50-0.79) · **Low** (<0.50) · **Unmapped** |
| **Exploitability Tiers** | **T1** Direct Exposure (no prerequisites) · **T2** Conditional Risk (single prerequisite) · **T3** Defense-in-Depth (multiple prerequisites or infrastructure access) |
| **STRIDE + Abuse** | **S** Spoofing · **T** Tampering · **R** Repudiation · **I** Information Disclosure · **D** Denial of Service · **E** Elevation of Privilege · **A** Abuse (feature misuse) |
| **SDL Severity** | `Critical` · `Important` · `Moderate` · `Low` |
| **Remediation Effort** | `Low` · `Medium` · `High` |
```

**Critical format rules baked into this skeleton:**
- `0-comparison-assessment.md` is the FIRST row in Report Files table
- Three-section Report Files table: Comparative, Code, TM7
- Reconciliation status names are EXACT: Addressed, Mitigated, Open, NotApplicable, NotInCode, Deferred
- STRIDE category names are CANONICAL (no variants allowed)
- `## Analysis Context & Assumptions` uses `&` (never word "and")
- `---` horizontal rules between EVERY pair of `## ` sections
- `### Needs Verification` always present (even if empty with `—`)
- References has TWO subsections with THREE-column tables
- ALL metadata values wrapped in backticks
- Git Commit includes date in parentheses
- ALL sections are mandatory (no optional sections except conditionals marked with `[CONDITIONAL]`)
