# Comparative Orchestrator — TM7 + Code Threat Analysis Workflow

This file contains the complete orchestration logic for **Mode 4: TM7 + Code Comparative Threat Analysis**. It produces a unified comparative analysis report when given both a `.tm7` file (Microsoft Threat Modeling Tool diagram) and a code repository path.

## ⚡ Context Budget — Read Files Selectively

**Phase reading strategy (same as Mode 1/3):**
- **Phase 1 (TM7 Analysis):** Read `tm7-threat-generation.md` + run `Invoke-TM7ThreatAnalysis.ps1`
- **Phase 2 (Code Analysis):** Read `orchestrator.md` — follow Mode 1 workflow
- **Phase 3 (Component Mapping):** Read mapping schema (this file) + `mapping-context.txt`
- **Phase 4 (Threat Reconciliation):** Read reconciliation schema (this file) + `reconciliation-context.txt`
- **Phase 5 (Gap Analysis):** Read gap analysis rules (this file)
- **Phase 6 (Report Generation):** Read comparative skeletons one at a time before writing each file
- **Phase 7 (Verification):** Delegate to sub-agent with validation-checklist.md sections Y-AC

**Skeleton loading:**
- Before `0-comparison-assessment.md`: read `skeletons/skeleton-comparison-assessment.md`
- Before `1-element-mapping.md`: read `skeletons/skeleton-element-mapping.md`
- Before `2-threat-reconciliation.md`: read `skeletons/skeleton-threat-reconciliation.md`
- Before `3-gap-analysis.md`: read `skeletons/skeleton-gap-analysis.md`
- Before `comparison-dashboard.html`: read `skeletons/skeleton-comparison-dashboard.md`

---

## Activation

**Trigger:** User provides BOTH:
- A `.tm7` file path (Microsoft Threat Modeling Tool diagram)
- A code repository path

**Example invocations:**
```
/threat-model-analyst compare c:\models\webapp.tm7 against code at c:\repos\my-app
Analyze TM7 at EdgeRAG.tm7 vs repository c:\repos\Edge-RAG
TM7 + code analysis for model.tm7 and code at ./src
```

**Preflight validation (before Phase 1):**
1. TM7 file exists and is valid XML
2. Code repository path exists and contains source files (not empty)
3. Output folder is writable
4. PowerShell script `Invoke-TM7ThreatAnalysis.ps1` is available

**Output folder naming:** `threat-model-compare-tm7-code-YYYYMMDD-HHmmss` or user-specified path

---

## Workflow Architecture — 7 Phases

### Phase 1: TM7 Analysis (Reuse Mode 3)

**Purpose:** Extract structured TM7 threat inventory with KB-based + LLM-augmented threats

**Workflow:**
1. Run `Invoke-TM7ThreatAnalysis.ps1 -TM7Path <file> -OutputDir <folder> [-SurfaceFilter <name>]`
2. PS1 produces: `threat-analysis-report.html`, `threat-analysis-data.json`, `phase9-context.txt`
3. **Phase 9 LLM Augmentation (MANDATORY):**
   - Read `skeletons/skeleton-tm7-phase9-llm.md`
   - Read `phase9-context.txt` (compact TM7 summary: elements, flows, boundaries, KB threats)
   - Identify deployment-specific threats beyond KB rules (e.g., cloud-specific attacks, integration risks)
   - Add LLM threats to HTML STRIDE Threat Matrix tables with `[NEW - LLM]` badge and `llm-threat` CSS class
   - Update `threat-analysis-data.json` to include `llm_augmentations` array
   - Follow all 8 ⛔ POST-CHECK micro-validations from the skeleton

**Outputs:**
- `threat-analysis-report.html` (KB + LLM threats)
- `threat-analysis-data.json` (structured threat inventory with `origin: "KB"|"LLM"` field)
- `phase9-context.txt` (compact summary: ~2-15KB, replaces full JSON parsing)

**Stop condition:** If PS1 fails or Phase 9 does not produce `threat-analysis-data.json` with at least 1 threat, STOP and report error. Phase 3 cannot start without this file.

**Tool call budget:** ~6 (PS1 execution + Phase 9 LLM pass + HTML/JSON writes)

**⛔ POST-CHECK (Phase 1 — STRIDE Name Normalization):**
Before proceeding to Phase 2, normalize ALL STRIDE category names in `threat-analysis-data.json` through the canonical name map below. TM7 source data frequently contains non-canonical variants that MUST be corrected at ingestion time.

---

### STRIDE Name Normalization (MANDATORY — applies to ALL phases)

**Canonical STRIDE Name Map:**
| Non-Canonical Variant | → Canonical Name |
|---|---|
| `Denial Of Service` | `Denial of Service` |
| `Elevation Of Privilege` | `Elevation of Privilege` |
| `Elevation of Privileges` | `Elevation of Privilege` |
| `DoS` | `Denial of Service` |
| `Info Disclosure` | `Information Disclosure` |
| `Information disclosure` | `Information Disclosure` |
| `EoP` | `Elevation of Privilege` |
| `Eop` | `Elevation of Privilege` |

**The 6 allowed canonical STRIDE values are:**
1. `Spoofing`
2. `Tampering`
3. `Repudiation`
4. `Information Disclosure`
5. `Denial of Service`
6. `Elevation of Privilege`

**Normalization enforcement rules:**
1. **Before writing ANY STRIDE category to ANY output file** (JSON, markdown, or HTML), normalize it through the canonical name map above.
2. **Before writing ANY threat title to ANY output file** (JSON, markdown, or HTML), scan the title string for STRIDE abbreviations and replace them with canonical full names. Specifically:
   - Replace standalone "DoS" (as a word boundary or STRIDE label) with "Denial of Service" in title text
   - Replace standalone "EoP" / "Eop" with "Elevation of Privilege" in title text
   - Replace "Info Disclosure" with "Information Disclosure" in title text
   - This applies to ALL title fields including `threat_statuses[].tm7_threat.title`, threat table headings, markdown threat names, and HTML table cells containing threat titles.
3. After Phase 1 completes: scan `threat-analysis-data.json` for non-canonical variants in BOTH `category` AND `title` fields and replace them in-place.
4. After Phase 4 completes: scan `threat-reconciliation.json` for non-canonical variants in ALL fields including `threat_statuses[].tm7_threat.title`, `threat_statuses[].tm7_threat.category`, and `stride_category_breakdown` keys. Replace them in-place.
5. **Post-Phase-4 normalization sweep (MANDATORY — AC10):** After Phase 4 completes, perform a FULL normalization sweep across ALL JSON and markdown output files produced so far (`threat-analysis-data.json`, `threat-reconciliation.json`, `component-mapping.json`, and any markdown files). Search for and replace ALL instances of non-canonical STRIDE text — in category fields, title strings, table cells, and prose. This sweep catches abbreviations embedded in TM7 source data that propagated through the pipeline.
6. After Phase 6 completes: scan ALL markdown and HTML output files for non-canonical STRIDE variants and replace them (titles AND categories).
7. **Phase 7 verification MUST check:** `Select-String -Pattern "Denial Of Service|Elevation Of Privilege|Elevation of Privileges|\bDoS\b|Info Disclosure|\bEoP\b|\bEop\b" -Path *.json,*.md,*.html` returns zero matches. This checks both category fields and title strings.

**⛔ POST-CHECK (every phase that writes category names OR threat titles):**
After writing any file containing STRIDE category names or threat titles, run a case-sensitive search for the rejected variants listed above (including abbreviations in titles). If any are found, fix them before proceeding to the next phase.

---

### Phase 2: Code Analysis (Reuse Mode 1)

**Purpose:** Full STRIDE-A threat model of the code repository

**Workflow:**
1. Follow `orchestrator.md` workflow Steps 1-9 (skip Step 10 verification for now)
2. Produce standard Mode 1 outputs:
   - `0.1-architecture.md` (component inventory, exposure table, scenarios)
   - `1-threatmodel.md` (DFD + element tables)
   - `1.1-threatmodel.mmd` (Mermaid DFD source)
   - `2-stride-analysis.md` (per-component STRIDE tables with T1/T2/T3 sections)
   - `3-findings.md` (prioritized findings organized by tier)
   - `0-assessment.md` (executive summary, action plan)
   - `threat-inventory.json` (structured component/threat/finding inventory)
   - Optional: `1.2-threatmodel-summary.mmd` (if DFD is large)

**Code Inventory Summary Generation:**
After completing Mode 1 outputs, generate `code-inventory-summary.txt`:
```
Repository: <path>
Commit: <SHA> (<date>)
Boundaries: <count>
  - <boundary1>
  - <boundary2>
Components: <count>
  - <component1>: <type> (<file1>, <file2>, ...)
  - <component2>: <type> (<file1>, <file2>, ...)
Key Flows:
  - <source> → <target>: <data type>
Threat Summary:
  - Total threats: <N>
  - T1: <N1>, T2: <N2>, T3: <N3>
  - STRIDE distribution: S=<n>, T=<n>, R=<n>, I=<n>, D=<n>, E=<n>, A=<n>
Findings: <count>
  - T1: <count>, T2: <count>, T3: <count>
```

**Outputs:**
- All Mode 1 files (listed above)
- `code-inventory-summary.txt` (compact summary: ~3-10KB, replaces full JSON parsing)

**Stop condition:** If any required Mode 1 file is missing, STOP and report error. Phase 3 needs `threat-inventory.json`.

**Tool call budget:** ~15-20 (same as Mode 1)

---

### Phase 3: Component Mapping (NEW — LLM-driven)

**Purpose:** Map TM7 elements to code components with confidence scores

**Input files:**
- `phase9-context.txt` (TM7 element list with types, boundaries)
- `code-inventory-summary.txt` (code component list with types, files)
- Optional: `mapping-overrides.json` (user-provided manual corrections)

**Mapping Context Generation:**
Before starting LLM mapping, generate `mapping-context.txt`:
```
TM7 Element | Type | Boundary | Candidate Code Components | Confidence Hints
<tm7_name> | Process | <boundary> | <component1>, <component2> | exact_name_match=0.95
<tm7_name> | DataStore | <boundary> | <component1> | type_match=0.80, file_path_similarity=0.70
<tm7_name> | ExternalEntity | None | <component1> | external_service=true, confidence=0.60
```

**Matching Strategy (4 Tiers):**
| Tier | Method | Confidence Range | Example |
|------|--------|-----------------|---------|
| 1 | Exact/fuzzy name match | 0.90-1.00 | TM7 "SQL Database" → Code "SqlDatabaseService" |
| 2 | Type + attribute match | 0.70-0.89 | TM7 Process(auth=No) → Code class with no auth middleware |
| 3 | Boundary containment | 0.50-0.69 | TM7 elements in "Internal Network" → Code classes in same namespace |
| 4 | LLM reasoning | 0.30-0.49 | LLM infers from architecture context |

**Confidence Action Rules:**
- `confirmed`: confidence `>= 0.70` OR explicit user override → can support `Addressed`/`Mitigated` status
- `pending`: confidence `0.50-0.69` → requires analyst review, cannot justify `Addressed`/`Mitigated`
- `unmappable`/`external_only`/`out_of_scope`: confidence `< 0.50` OR no credible component candidate

**Mapping JSON Schema:**
```json
{
  "mapping_metadata": {
    "tm7_file": "string",
    "code_repo": "string",
    "code_repo_commit": "string",
    "tm7_element_count": "int",
    "code_component_count": "int",
    "tm7_analysis_version": "string",
    "llm_context_id": "string",
    "analysis_started": "ISO8601",
    "analysis_completed": "ISO8601",
    "timestamp": "ISO8601"
  },
  "element_mappings": [
    {
      "id": "MAP-001",
      "tm7_element": {
        "guid": "string",
        "name": "string",
        "type": "string",
        "generic_type": "Process|DataStore|ExternalEntity|DataFlow|Boundary"
      },
      "code_components": [
        {
          "name": "string",
          "confidence": 0.92,
          "match_reasons": ["exact_name_match", "file_path_similarity"],
          "source_files": ["src/auth/AuthService.cs", "src/auth/TokenValidator.cs"]
        }
      ],
      "status": "confirmed|pending|unmappable|external_only|out_of_scope",
      "multi_element_note": "string (required for 1-to-many or many-to-many mappings)"
    }
  ],
  "unmapped_tm7_elements": [
    { "name": "string", "type": "string", "reason": "string" }
  ],
  "unmapped_code_components": [
    { "name": "string", "reason": "string" }
  ],
  "mapping_summary": {
    "total_mapped": "int",
    "high_confidence": "int (>= 0.80)",
    "medium_confidence": "int (0.50-0.79)",
    "low_confidence": "int (< 0.50)"
  }
}
```

**Required constraints:**
- `generic_type` must be one of: `Process`, `DataStore`, `ExternalEntity`, `DataFlow`, `Boundary`
- `source_files` must resolve within `code_repo` (verify with `Test-Path` or `git ls-files`)
- `multi_element_note` is REQUIRED for 1-to-many or many-to-many mappings (>10 chars)
- High-confidence mappings (≥0.80) should be ≥50% of total for real validation pairs

**Granularity Handling:**
- **1-to-many:** TM7 "Web Application" → code has ApiServer + AuthMiddleware + ResponseFormatter (keep all, mark primary)
- **Many-to-1:** TM7 "Auth Service" + "Token Validator" → code has unified `AuthService` class (document consolidation)
- **Many-to-many:** Multiple TM7 elements → multiple code components (keep all links, rank by confidence)
- **External-only:** TM7 "Azure EventHubs" → no local code, mark `status: "external_only"`

**Duplicate Code Component Detection (MANDATORY — Z5):**
After generating all element_mappings, perform a MANDATORY scan for cases where the **same code component name** appears in `code_components` arrays of 2+ different element_mappings. This scan MUST cover ALL element_mappings, not just a subset. For each such duplicate group:
1. **Identify ALL groups:** Build a reverse index: `{code_component_name → [list of MAP-XXX IDs that reference it]}`. Any code component name appearing in 2+ MAP entries is a duplicate group.
2. **Add `multi_element_note` to EVERY member of EVERY group:** For EACH element_mapping in a duplicate group, add or update the `multi_element_note` field (>10 chars) explaining why this code component serves multiple TM7 elements. Do NOT skip any mapping entry — every member of every duplicate group must have this field.
3. Example: TM7 "Web Server" and TM7 "API Gateway" both map to code `HttpServer` → add `multi_element_note: "HttpServer serves both web frontend (TM7 'Web Server') and API routing (TM7 'API Gateway') responsibilities in a single class."` to both mappings.
4. If a mapping already has a `multi_element_note` from 1-to-many handling, append the duplicate-component note (do not replace).
5. **Common miss pattern:** Mappings where a code component like "ConfigurationManager" or "LoggingService" appears across many TM7 elements are frequently missed. The reverse-index approach catches these.

**⛔ POST-CHECK (Phase 3 — multi_element_note — ZERO TOLERANCE):**
After writing `component-mapping.json`, perform this verification with ZERO tolerance for missing notes:
1. Build the reverse index `{code_component_name → [MAP-IDs]}` from the written JSON.
2. For every code component that appears in 2+ element_mappings, verify EACH of those mappings has a non-empty `multi_element_note` (>10 chars).
3. If ANY mapping in ANY duplicate group is missing `multi_element_note`, FIX IT IMMEDIATELY by re-reading the JSON, adding the missing notes, and re-writing the file.
4. Do NOT proceed to Phase 4 until this check passes with zero violations.

**Outputs:**
- `component-mapping.json` (structured mapping with confidence scores)
- `mapping-context.txt` (intermediate handoff file for Phase 4)

**Stop condition:** If mapping confidence is unacceptably low (<30% confirmed), log warning but continue. Phase 4 will mark threats as `NotInCode`.

**Tool call budget:** ~3-4 (read context, LLM mapping pass, write JSON, write context file)

---

### Phase 4: Threat Reconciliation (NEW — LLM-driven)

**Purpose:** Determine status of each TM7 threat in the codebase

**Input files:**
- `component-mapping.json` (TM7 element → code component mappings)
- `threat-analysis-data.json` (TM7 threat inventory with KB + LLM threats)
- `threat-inventory.json` (code threat inventory with findings)
- `3-findings.md` (prioritized findings with FIND-XX IDs, STRIDE categories, and component references)

**Step 4.0 — Extract Code Findings Index (MANDATORY — AA13):**
Before starting reconciliation, read `3-findings.md` and build a lookup index of ALL FIND-XX entries:
1. Parse each finding entry to extract: `finding_id` (e.g., FIND-01), `title`, `STRIDE category`, `affected component(s)`, `tier` (T1/T2/T3).
2. Also parse `threat-inventory.json` for structured finding data if available.
3. Build an in-memory index:
   ```
   FIND-01 | Missing Authentication | Spoofing | WebServer, ApiGateway | T1
   FIND-02 | Input Validation Gap  | Tampering | DataProcessor         | T2
   FIND-03 | No Audit Logging      | Repudiation | AuthService          | T2
   ```
4. This index is used in Step 4.1 to populate `related_code_findings` for each TM7 threat.

**Reconciliation Context Generation:**
Before starting reconciliation, generate `reconciliation-context.txt`:
```
Mapped Pair | TM7 Threats | Code Findings | Evidence Hints
<tm7_element> → <code_component> (confidence=0.92) | T01.S: Spoofing via lack of auth | FIND-01: Missing Authentication | auth_middleware=absent
<tm7_element> → <code_component> (confidence=0.85) | T02.T: Input tampering | FIND-02: Input Validation | validation_pattern=present
<tm7_element> → unmapped (confidence=0.40) | T03.I: Data exposure | — | no_code_mapping
```

**Threat Status Definitions:**
| Status | Definition | How Determined |
|--------|-----------|----------------|
| **Addressed** | Code has explicit control preventing this threat | Auth middleware, input validation, encryption present. Requires mapping confidence ≥0.70 + evidence. |
| **Mitigated** | Code has detection/response (not prevention) | Logging, alerting, rate limiting. Requires mapping confidence ≥0.70 + evidence. |
| **Open** | No code defense found | Threat is actionable, needs remediation. Requires `remediation` object with `controls` array and `priority`. |
| **NotApplicable** | Threat scenario doesn't exist in this codebase | Wrong deployment type, external-only component. Requires justification. |
| **NotInCode** | TM7 element not mapped to any code component | Mapping failed (confidence <0.70) or element is design-only. |
| **Deferred** | Mitigated by infrastructure/platform, not app code | OS permissions, firewall, container isolation. Requires `infrastructure_mitigation` evidence. |

**Reconciliation JSON Schema:**
```json
{
  "reconciliation_metadata": {
    "tm7_threat_count": "int",
    "code_finding_count": "int",
    "code_repo_commit": "string",
    "tm7_analysis_version": "string",
    "threat_knowledge_base_version": "string",
    "llm_context_id": "string",
    "completion_status": "complete|partial",
    "timestamp": "ISO8601"
  },
  "threat_statuses": [
    {
      "id": "RECON-001",
      "tm7_threat": {
        "threat_id": "string",
        "title": "string",
        "category": "Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege",
        "interaction": "string",
        "source": "KB|LLM",
        "origin": "KB|LLM",
        "rule_id": "string (for KB threats)",
        "phase9_interaction": "string (for LLM threats)"
      },
      "mapping": {
        "source_code_component": "string|null",
        "target_code_component": "string|null",
        "mapping_confidence": "float"
      },
      "status": "Addressed|Mitigated|Open|NotApplicable|NotInCode|Deferred",
      "status_justification": "string (MANDATORY, non-empty)",
      "evidence": [
        {
          "type": "code_pattern|dependency|architecture|code_absence|infrastructure_mitigation",
          "location": "string (file:line or component name)",
          "pattern": "string",
          "confidence": "float",
          "origin": "KB|LLM",
          "rule_id": "string (for KB)",
          "phase9_interaction": "string (for LLM)"
        }
      ],
      "related_code_findings": [
        { "finding_id": "FIND-01", "title": "Missing Authentication" }
      ],
      "remediation": {
        "controls": ["string"],
        "effort": "Low|Medium|High",
        "priority": "Tier 1|Tier 2|Tier 3"
      }
    }
  ],
  "reconciliation_summary": {
    "total_tm7_threats": "int",
    "status_distribution": {
      "Addressed": "int",
      "Mitigated": "int",
      "Open": "int",
      "NotApplicable": "int",
      "NotInCode": "int",
      "Deferred": "int"
    },
    "coverage_percentage": "float ((Addressed + Mitigated) / total * 100)",
    "open_threat_tier_distribution": { "Tier1": "int", "Tier2": "int", "Tier3": "int" },
    "stride_category_breakdown": {
      "Spoofing": "int",
      "Tampering": "int",
      "Repudiation": "int",
      "Information Disclosure": "int",
      "Denial of Service": "int",
      "Elevation of Privilege": "int"
    },
    "kb_threat_count": "int",
    "llm_augmentation_count": "int"
  }
}
```

**Required constraints:**
- Every TM7 threat must have a status (no null/empty values)
- `Addressed` and `Mitigated` require `evidence.length > 0` AND mapping confidence `>= 0.70`
- `Deferred` requires `infrastructure_mitigation` evidence naming the protecting platform control
- `Open` threats require `remediation` object with `controls` array and `priority` (Tier 1/2/3)
- Every evidence entry must include lineage: `origin` (KB|LLM), `rule_id` (for KB), `phase9_interaction` (for LLM)
- Allowed `evidence.type` values: `code_pattern`, `dependency`, `architecture`, `code_absence`, `infrastructure_mitigation`
- Status distribution must sum to `total_tm7_threats`
- `coverage_percentage` must equal `(Addressed + Mitigated) / total_tm7_threats * 100`

**Reconciliation Summary Computation (MANDATORY — AA11, AA12):**
When building the `reconciliation_summary` object, compute and include ALL of the following fields:
1. **`coverage_percentage`** (MANDATORY — AA11): Calculate as `(status_distribution.Addressed + status_distribution.Mitigated) / total_tm7_threats * 100`, rounded to 1 decimal place (e.g., `72.3`). This field MUST be present in the `reconciliation_summary` object. If `total_tm7_threats` is 0, set to `0.0`.
2. **`kb_threat_count`** (MANDATORY — AA12): Count the number of threats in `threat_statuses` where `tm7_threat.source == "KB"` OR `tm7_threat.origin == "KB"`. This represents threats generated by the TM7 Knowledge Base rules.
3. **`llm_augmentation_count`** (MANDATORY — AA12): Count the number of threats in `threat_statuses` where `tm7_threat.source == "LLM"` OR `tm7_threat.origin == "LLM"`. This represents threats added by Phase 9 LLM augmentation.
4. Verify: `kb_threat_count + llm_augmentation_count == total_tm7_threats`. If not, investigate and fix the source field assignments.

**⛔ POST-CHECK (Phase 4 — reconciliation_summary completeness):**
After writing `threat-reconciliation.json`, verify the `reconciliation_summary` object contains ALL of these fields:
- `total_tm7_threats` (int)
- `status_distribution` (object with all 6 status keys)
- `coverage_percentage` (float, 1 decimal)
- `open_threat_tier_distribution` (object)
- `stride_category_breakdown` (object with 6 canonical STRIDE keys)
- `kb_threat_count` (int)
- `llm_augmentation_count` (int)
If any field is missing, add it with the correct computed value before proceeding.

**Canonical STRIDE Categories (MANDATORY):**
Use ONLY these 6 canonical names (no variants allowed):
- `Spoofing`
- `Tampering`
- `Repudiation`
- `Information Disclosure`
- `Denial of Service`
- `Elevation of Privilege`

**Rejected variants:** "Denial Of Service", "Elevation Of Privilege", "Elevation of Privileges", "DoS", "Info Disclosure", "Information disclosure"

**Threat Clustering:**
Multiple TM7 threats (per-flow granularity) → single code finding (per-control granularity):
- Example: 3 TM7 Spoofing threats → FIND-01: Missing Authentication
- Display in dashboard as: "3 TM7 threats addressed by FIND-01"
- Keep all relationships in `related_code_findings` array

**Step 4.1 — Populate related_code_findings (MANDATORY — AA13):**
For EACH TM7 threat in `threat_statuses`, populate the `related_code_findings` array by cross-referencing the findings index from Step 4.0:
1. **Identify the mapped code component:** From `component-mapping.json`, find which code component(s) the TM7 threat's element maps to.
2. **Match by component + STRIDE category:** For each FIND-XX in the index, check if:
   - The finding's affected component overlaps with the mapped code component (exact match or substring match), AND
   - The finding's STRIDE category matches the TM7 threat's category (after normalization).
3. **Match by STRIDE category alone (fallback):** If no component match is found, check if the finding's STRIDE category matches the TM7 threat's category and the components are in the same trust boundary.
4. **Populate the array:** For each match, add `{ "finding_id": "FIND-XX", "title": "<finding title>" }` to `related_code_findings`.
5. **Example linkage:**
   - TM7 threat: "Spoofing" on "Web Server" → mapped to code `HttpServer`
   - FIND-03: "Missing Authentication" covers `HttpServer` with category "Spoofing"
   - Result: `related_code_findings: [{ "finding_id": "FIND-03", "title": "Missing Authentication" }]`
6. **Status linkage:** Threats with status `Addressed` or `Mitigated` SHOULD have at least one related finding. Threats with status `Open` MAY have findings that describe the gap.

**⛔ POST-CHECK (Phase 4 — related_code_findings population):**
After writing `threat-reconciliation.json`, verify:
- At least 50% of threats with status `Addressed` or `Mitigated` have non-empty `related_code_findings` arrays.
- If fewer than 50% have linkages, re-examine the findings index and mapping to find missed connections before proceeding.

**⛔ POST-CHECK (Phase 4 — STRIDE name normalization):**
After writing `threat-reconciliation.json`, verify no non-canonical STRIDE variants exist in the `category` or `stride_category_breakdown` fields. Apply the canonical name map from the STRIDE Name Normalization section.

**Outputs:**
- `threat-reconciliation.json` (structured reconciliation with evidence)
- `reconciliation-context.txt` (intermediate handoff file for Phase 5)

**Stop condition:** If any threat has null/empty status, STOP and fix reconciliation. Phase 5 needs complete status data.

**Tool call budget:** ~4-5 (read context, LLM reconciliation pass, write JSON, write context file)

---

### Phase 5: Gap Analysis (NEW — LLM-driven)

**Purpose:** Identify bidirectional gaps between TM7 and code

**Gap Categories:**
1. **TM7-only elements:** In diagram but no code implementation (design-reality gap)
2. **Code-only components:** In code but not modeled in TM7 (hidden attack surface)
3. **TM7-only flows:** Data paths in diagram but not in code
4. **Code-only flows:** Code paths not in TM7 diagram
5. **TM7 threats not covered in code:** Threats with status `Open` or `NotInCode`

**Flow Accounting Rules:**
- Every TM7 flow from `phase9-context.txt` must be classified exactly once as `matched` or `tm7_only`
- Every code-only flow must record: source, target, data type, reason, STRIDE tags (or explicit `NotApplicable` rationale)
- No flow can appear in more than one category (matched, tm7_only, code_only)

**Code-Only Flow Completeness (MANDATORY — AC15):**
Every code-only flow MUST include ALL of these fields with non-empty values:
- `source`: The originating code component
- `target`: The destination code component
- `data_type`: The type of data flowing (e.g., "HTTP request", "database query", "configuration data")
- `reason`: A human-readable explanation of why this flow exists in code but not the TM7. Valid reasons include:
  - "Internal implementation detail" — flow is between sub-components of a single TM7 element
  - "Added after TM7 was created" — code has evolved beyond the TM7 design
  - "External API integration" — flow connects to a service not modeled in TM7
  - "Infrastructure/platform flow" — OS, container, or cloud platform communication
  - "Logging/telemetry pipeline" — observability flow not in threat model scope
  - "Configuration loading" — startup-time config reads not modeled as runtime flows
  - Custom reason describing the specific gap
- `stride_tags`: Array of applicable STRIDE categories OR `"NotApplicable: <reason>"`
If ANY code-only flow is missing `source`, `target`, `reason`, or `stride_tags`, the flow entry is INVALID and must be fixed before proceeding.

**Gap Analysis JSON Schema (embedded in `comparison-metadata.json`):**
```json
{
  "gap_analysis": {
    "tm7_only_elements": [
      { "name": "string", "type": "string", "reason": "string" }
    ],
    "code_only_components": [
      {
        "name": "string",
        "reason": "string",
        "stride_assessment": ["Spoofing", "Tampering", "..."] or "NotApplicable: <reason>"
      }
    ],
    "tm7_only_flows": [
      { "source": "string", "target": "string", "data_type": "string", "reason": "string" }
    ],
    "code_only_flows": [
      {
        "source": "string",
        "target": "string",
        "data_type": "string",
        "reason": "string",
        "stride_tags": ["Spoofing", "Tampering", "..."] or "NotApplicable: <reason>"
      }
    ],
    "recommendations": {
      "tm7_updates": ["string"],
      "code_improvements": ["string"]
    },
    "gap_summary": {
      "total_gaps": "int",
      "tm7_only_elements": "int",
      "code_only_components": "int",
      "tm7_only_flows": "int",
      "code_only_flows": "int"
    }
  }
}
```

**Output validation:**
- No TM7 element appears as both "mapped" (in `component-mapping.json`) and "TM7-only" (in gap analysis)
- Code-only components have STRIDE tags OR explicit `NotApplicable` rationale
- Gap counts in JSON match counts in `3-gap-analysis.md`
- Flow counts sum correctly: all TM7 flows = matched + tm7_only, no duplicates

**⛔ POST-CHECK (Phase 5 — AB8: No element in both mapped and TM7-only):**
After writing gap analysis data, perform this mandatory cross-reference check:
1. Read `component-mapping.json` and collect ALL TM7 element names from `element_mappings` (any status: confirmed, pending, unmappable, external_only, out_of_scope).
2. Read the `tm7_only_elements` list from the gap analysis.
3. Verify: NO element name appears in BOTH lists. If an element is mapped (even with low confidence or `pending`/`unmappable` status), it is NOT TM7-only.
4. If violations are found: REMOVE the element from `tm7_only_elements` and update `gap_summary.tm7_only_elements` count.
5. An element is truly "TM7-only" ONLY if it does not appear in `element_mappings` at all (not even as unmappable).

**⛔ POST-CHECK (Phase 5 — STRIDE name normalization):**
After writing `3-gap-analysis.md` and gap analysis JSON, verify no non-canonical STRIDE variants exist. Apply the canonical name map.

**⛔ POST-CHECK (Phase 5 — AC15: Code-only flow completeness):**
After writing gap analysis data, verify EVERY entry in `code_only_flows` has non-empty `source`, `target`, `reason`, and `stride_tags` fields. If any flow is missing `reason`, add an appropriate reason from the list in "Code-Only Flow Completeness" above. If any flow is missing `stride_tags`, add applicable STRIDE categories or `"NotApplicable: <reason>"`.

**Outputs:**
- `3-gap-analysis.md` (bidirectional gap narrative with recommendations)
- Gap data embedded in `comparison-metadata.json`

**Stop condition:** If flow accounting fails (TM7 flows ≠ matched + tm7_only), log error and document incomplete flows.

**Tool call budget:** ~2-3 (compute gaps from mapping + reconciliation, write markdown)

---

### Phase 6: Report Generation (NEW)

**Purpose:** Produce comparison markdown files + HTML dashboard

**MANDATORY: Coverage Percentage Source of Truth**
The coverage percentage in `0-comparison-assessment.md` MUST be computed from `threat-reconciliation.json`, not independently calculated. Read the `reconciliation_summary.coverage_percentage` value and use it directly. The headline numerator MUST equal `(status_distribution.Addressed + status_distribution.Mitigated)` from the reconciliation JSON. Do NOT re-derive or approximate these values.

**Output Files (11 total):**
| # | File | Skeleton | Purpose |
|---|------|----------|---------|
| 1 | `0-comparison-assessment.md` | `skeleton-comparison-assessment.md` | Executive summary, risk comparison, action plan |
| 2 | `1-element-mapping.md` | `skeleton-element-mapping.md` | TM7 element → code component mapping table |
| 3 | `1.1-element-mapping-diagram.mmd` | (generated) | Mermaid diagram linking TM7 to code |
| 4 | `2-threat-reconciliation.md` | `skeleton-threat-reconciliation.md` | Per-threat status with evidence |
| 5 | `3-gap-analysis.md` | `skeleton-gap-analysis.md` | Bidirectional gaps + recommendations |
| 6 | `4-composite-threatmodel.md` | (generated) | Unified threat model merging both perspectives |
| 7 | `4.1-composite-threatmodel.mmd` | (generated) | Composite DFD diagram |
| 8 | `5-findings.md` | (generated) | Unified findings (code + TM7 open threats) |
| 9 | `comparison-dashboard.html` | `skeleton-comparison-dashboard.md` | Interactive HTML with heatmaps, badges |
| 10 | `comparison-metadata.json` | (generated) | Structured data: mappings, statuses, metrics |
| 11 | `phase9-context.txt` | (retained from Phase 1) | Pre-computed TM7 context |

**Retained Artifacts (from Phase 1 and Phase 2):**
- Phase 1: `threat-analysis-report.html`, `threat-analysis-data.json`, `phase9-context.txt`
- Phase 2: `0.1-architecture.md`, `1-threatmodel.md`, `1.1-threatmodel.mmd`, `2-stride-analysis.md`, `3-findings.md`, `0-assessment.md`, `threat-inventory.json`
- Intermediate handoff files: `code-inventory-summary.txt`, `mapping-context.txt`, `reconciliation-context.txt`

**Dashboard Requirements:**
- Self-contained (no external CSS/JS)
- `@media print` styles for PDF export
- HTML markers for atomic edits:
  - `<!-- MAPPING_TABLE_END -->`
  - `<!-- RECONCILIATION_TABLE_END -->`
  - `<!-- GAP_ANALYSIS_END -->`
  - `<!-- FLOW_MISMATCH_TABLE_END -->`
  - `<!-- COMPOSITE_THREATMODEL_END -->`
  - `<!-- DANGER_FINDINGS_END -->`
- CSS classes for status badges:
  - `.badge-addressed` (green)
  - `.badge-mitigated` (blue)
  - `.badge-open` (red)
  - `.badge-notapplicable` (gray)
  - `.badge-notincode` (yellow)
  - `.badge-deferred` (purple)
- Metric cards: coverage %, threat status distribution, gap counts
- Confidence heatmap/visual indicators for mapping quality
- Threat reconciliation table with sortable columns
- Component mapping table with confidence bars

**comparison-metadata.json Structure:**
Consolidate all structured data from Phases 3-5:
```json
{
  "analysis_metadata": {
    "tm7_file": "string",
    "code_repo": "string",
    "code_repo_commit": "string",
    "analysis_started": "ISO8601",
    "analysis_completed": "ISO8601",
    "tm7_element_count": "int",
    "code_component_count": "int",
    "tm7_threat_count": "int",
    "code_finding_count": "int",
    "llm_context_id": "string",
    "completion_status": "complete|partial",
    "unresolved_blockers": ["string"] (if partial)
  },
  "component_mapping": { /* from component-mapping.json */ },
  "threat_reconciliation": { /* from threat-reconciliation.json */ },
  "gap_analysis": { /* from Phase 5 */ }
}
```

**Outputs:**
- All 11 files listed above
- All Phase 1 and Phase 2 retained artifacts in the output folder

**Stop condition:** If any required skeleton file is missing, STOP and report missing file.

**⛔ POST-CHECK (Phase 6 — AC6: Assessment Coverage Consistency):**
After writing `0-comparison-assessment.md`, verify:
1. The headline coverage percentage matches `reconciliation_summary.coverage_percentage` from `threat-reconciliation.json`
2. The headline numerator matches `(status_distribution.Addressed + status_distribution.Mitigated)` from the reconciliation JSON
3. The headline denominator matches `total_tm7_threats`
If ANY mismatch → recalculate from the JSON values and fix the assessment text before proceeding.

**Tool call budget:** ~3-4 per file (read skeleton, fill placeholders, write file) = ~12-16 total

---

### Phase 7: Verification

**Purpose:** Run 76 validation checks (sections Y-AC) and fix failures

**Validation Sections:**
- **Section Y:** File Structure & Metadata (12 checks)
- **Section Z:** Component Mapping Quality (16 checks)
- **Section AA:** Threat Reconciliation (17 checks)
- **Section AB:** Gap Analysis (11 checks)
- **Section AC:** Cross-Report Consistency (20 checks)

**Verification Strategy:**
Delegate to a sub-agent with `validation-checklist.md` sections Y-AC. The sub-agent:
1. Reads all output files
2. Runs each validation check
3. Returns PASS/FAIL results with evidence
4. Parent agent fixes failures and re-runs verification (max 3 cycles)

**Pass Thresholds:**
- Section Y: `12/12` (REQUIRED)
- Section Z: `>= 14/16`
- Section AA: `>= 15/17`
- Section AB: `>= 10/11`
- Section AC: `20/20` (REQUIRED)

**Categorical Failure Definition:**
A failure is categorical if:
- It occurs in section Y or AC (file structure or cross-consistency)
- The same check fails in both validation pairs (EdgeRAG and AzureLocal)
- The same check persists across iterations after a fix cycle

**Overnight Loop Rule:**
- Allow at most 3 automated fix cycles
- If categorical failures remain after cycle 3, STOP and report unresolved blockers
- Set `completion_status: "partial"` in metadata with `unresolved_blockers` array

**Stop condition:** Either all checks pass OR max 3 cycles reached with unresolved blockers documented.

**Tool call budget:** ~2 (delegate to sub-agent, read results)

---

## Scale Mitigation Strategy

**Problem:** Mode 4 combines Mode 1 + Mode 3 + new phases. Total tool calls could reach 50+.

**Solution:** Pre-computed context files (Hybrid A+B+D pattern from Mode 3)

| File | Content | Size | Replaces |
|------|---------|------|----------|
| `phase9-context.txt` | TM7 elements, flows, boundaries, KB threats (from PS1) | ~2-15KB | 75KB+ JSON parsing |
| `code-inventory-summary.txt` | Code components, key files, boundaries, flows, threats | ~3-10KB | Full threat-inventory.json parsing |
| `mapping-context.txt` | TM7 + code side-by-side with candidate matches | ~2-5KB | Separate reads of both inventories |
| `reconciliation-context.txt` | Mapped pairs + threats + findings per pair | ~5-15KB | Full JSON cross-referencing |

**Phase Budgets:**
| Phase | Tool Calls | Strategy |
|-------|------------|----------|
| Phase 1 (TM7) | ~6 | PS1 + Phase 9 with context file |
| Phase 2 (Code) | ~15-20 | Mode 1 workflow + summary generation |
| Phase 3 (Mapping) | ~3-4 | Read context, map, write JSON + context |
| Phase 4 (Reconciliation) | ~4-5 | Read context, reconcile, write JSON + context |
| Phase 5 (Gap Analysis) | ~2-3 | Compute gaps, write markdown |
| Phase 6 (Reports) | ~12-16 | 4 skeletons + 7 generated files |
| Phase 7 (Verification) | ~2 | Sub-agent delegation |
| **TOTAL** | **~44-56** | Within `--effort high` budget (60) |

**Context File Ownership:**
- `phase9-context.txt`: Generated by `Invoke-TM7ThreatAnalysis.ps1` (Mode 3)
- `code-inventory-summary.txt`: Generated by comparative orchestrator after Phase 2
- `mapping-context.txt`: Generated by comparative orchestrator before Phase 3
- `reconciliation-context.txt`: Generated by comparative orchestrator before Phase 4

**Format Rules:**
- Keep each handoff file under ~15KB
- Prefer compact text or compact JSON over full raw inventories
- Use line-oriented format for easy parsing
- Include only essential data needed by next phase

---

## Mandatory Rules (Mode 4 Specific)

These rules supplement the 34 mandatory rules in `orchestrator.md`:

35. **Every TM7 STRIDE category name must use the canonical 6 names** (no variants): Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. Reject "Denial Of Service", "DoS", "Info Disclosure", etc.
36. **Mapping confidence below 0.70 cannot justify `Addressed` or `Mitigated`** without explicit user override.
37. **Every threat in `threat-reconciliation.json` must have a non-empty `status_justification`** field.
38. **Evidence lineage is mandatory:** Every evidence entry must trace back to `origin: "KB"|"LLM"`, `rule_id` (for KB), or `phase9_interaction` (for LLM).
39. **Flow accounting must be complete:** Every TM7 flow = matched or tm7_only (no other category), every code-only flow has STRIDE tags or `NotApplicable` rationale.
40. **Comparison dashboard must be self-contained:** No external CSS/JS, no `https://` links to stylesheets or scripts.
41. **HTML markers are required** for atomic dashboard edits: MAPPING_TABLE_END, RECONCILIATION_TABLE_END, GAP_ANALYSIS_END, FLOW_MISMATCH_TABLE_END, COMPOSITE_THREATMODEL_END, DANGER_FINDINGS_END.
42. **Status badges use exact CSS classes:** badge-addressed, badge-mitigated, badge-open, badge-notapplicable, badge-notincode, badge-deferred (lowercase, hyphenated).
43. **Overnight runs terminate after max 3 fix cycles** if categorical failures persist. Set `completion_status: "partial"` with `unresolved_blockers` array.
44. **No TM7 element appears as both mapped and TM7-only** (cross-reference mapping JSON vs gap analysis).

---

## Sub-Agent Governance (MANDATORY)

**Rule 1 — Parent owns ALL file creation.** Parent agent calls `create_file` for all 11 comparison output files + retained artifacts. Sub-agents NEVER write report files.

**Rule 2 — Sub-agents are READ-ONLY helpers.** Sub-agents may:
- Run verification checks and return PASS/FAIL results
- Search code for evidence patterns and return structured data
- Parse JSON and compute metrics (e.g., confidence distribution)

**Rule 3 — Sub-agent prompts must be NARROW and SPECIFIC.** Never tell a sub-agent to "perform comparative analysis." Instead:
- ✅ "Read `component-mapping.json` and verify every element has confidence in [0.0, 1.0]. Return list of violations."
- ✅ "Run validation checks Y1-Y12 from `validation-checklist.md` section Y. Return PASS/FAIL per check."
- ❌ "Perform Mode 4 comparative analysis" (sub-agent will duplicate entire workflow)

**Rule 4 — Sub-agents have NO memory of parent state.** Include all context in the sub-agent prompt:
- Output folder path
- File names to check
- Expected schemas/formats
- Success criteria

**Rule 5 — Verification ONLY in Phase 7.** Do not run verification checks during Phases 1-6. Complete all file generation first, then delegate verification to a sub-agent.

---

## Troubleshooting

**Issue: Mapping confidence too low (<50% confirmed)**
- Check if TM7 elements have generic names ("Web Server", "Database") vs. code has specific names ("AuthService", "PostgreSqlClient")
- Use fuzzy matching with Levenshtein distance
- Leverage boundary containment (elements in same TM7 boundary → same code namespace)
- Mark as `pending` and continue; Phase 4 will classify as `NotInCode`

**Issue: Threat reconciliation finds no evidence**
- Check if component mapping failed (confidence <0.70)
- Check if code finding addresses the TM7 threat but with different terminology (e.g., TM7 "Spoofing" vs. code "Missing Authentication")
- Use `NotInCode` status for unmapped elements
- Use `Deferred` status for infrastructure-mitigated threats

**Issue: Gap analysis shows 100% code-only components**
- TM7 file may be outdated or incomplete
- Document in recommendations: "Update TM7 to include components X, Y, Z"
- Proceed with analysis; gap analysis is informative, not blocking

**Issue: HTML dashboard doesn't render**
- Verify HTML is self-contained (no external CSS/JS)
- Verify HTML markers are present (MAPPING_TABLE_END, etc.)
- Validate HTML with `Select-String -Pattern "<html"` (must find opening tag)
- Check CSS class names match skeleton (badge-addressed, not badge-Addressed)

**Issue: Verification fails on AC10 (STRIDE canonical names)**
- Search all output files for variants: "Denial Of Service", "DoS", "Info Disclosure", "Elevation Of Privilege"
- Replace with canonical names: "Denial of Service", "Information Disclosure", "Elevation of Privilege"
- Re-run verification

**Issue: Overnight run stuck in infinite loop**
- Check if categorical failures are being fixed (compare iteration N vs. N+1)
- If same failures persist after cycle 3, STOP and set `completion_status: "partial"`
- Document unresolved blockers in `unresolved_blockers` array

---

## Testing with Available TM7 + Code Pairs

| # | TM7 File | Code Repo | Complexity |
|---|----------|-----------|-----------|
| T1 | `EdgeRAG-PublicPreviewSharePoint.tm7` | `c:\repos\Edge-RAG\` | Medium-Complex |
| T2 | `AzureLocal-Observability_Win_TelemetryAndDiagnosticsExtension_v4.tm7` | `c:\repos\AzureLocal-Operator-Copilot\` | Medium-Complex |
| T3 | `K8s Connect Threat Model_ArcA_20231006.tm7` | `c:\repos\Aks-Arc-Assembly\` | Complex |

**Execution order:** T1 (EdgeRAG) → T2 (AzureLocal) → Regression: Re-run T1 → T3 (K8s scale test)

**Success criteria per pair:**
1. All 76 validation checks pass OR meets section thresholds with documented non-categorical failures
2. Component mapping ≥80% confirmed or explicitly classified
3. Threat reconciliation coverage ≥70% (Addressed + Mitigated)
4. Gap analysis identifies ≥1 code-only component (expected for real repos)
5. HTML dashboard renders correctly in Edge/Chrome
6. No STRIDE canonical name variants in any output file

---

## Success Criteria (Overall)

1. Given any TM7 + code pair, produce comparison report within CLI step budget (44-56 tool calls)
2. Component mapping: ≥80% of TM7 elements mapped or explicitly classified
3. Threat reconciliation: every TM7 threat has a non-null status
4. Open threats have actionable remediation paths (controls, effort, priority)
5. Gap analysis identifies code components not in TM7 (hidden attack surface)
6. HTML dashboard renders correctly with all tables and metrics
7. All existing Mode 1/2/3 functionality unchanged (regression)
8. Zero TM7 STRIDE canonical-name variants across all outputs
9. Overnight automation terminates cleanly within 3 fix cycles or reports unresolved blockers

---

## Example Invocation

```powershell
# Mode 4: TM7 + Code Comparative Analysis
/threat-model-analyst compare c:\models\EdgeRAG-PublicPreviewSharePoint.tm7 against code at c:\repos\Edge-RAG

# Expected workflow:
# Phase 1: Run Invoke-TM7ThreatAnalysis.ps1 + Phase 9 LLM augmentation
# Phase 2: Run Mode 1 code analysis + generate code-inventory-summary.txt
# Phase 3: Map TM7 elements to code components with confidence scores
# Phase 4: Reconcile TM7 threats vs. code findings (Addressed/Mitigated/Open/etc.)
# Phase 5: Identify bidirectional gaps (TM7-only, code-only)
# Phase 6: Generate 11 comparison files + HTML dashboard
# Phase 7: Run 76 validation checks (sections Y-AC)

# Output folder: threat-model-compare-tm7-code-YYYYMMDD-HHmmss/
# Key files: 0-comparison-assessment.md, comparison-dashboard.html, comparison-metadata.json
```
