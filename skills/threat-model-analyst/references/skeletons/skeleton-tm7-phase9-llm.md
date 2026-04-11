# Skeleton: TM7 Phase 9 — LLM-Augmented Threat Analysis

> **⛔ This skeleton governs ONLY Phase 9 (LLM-augmented threats). Sections 1-7 and 9 are produced deterministically by `Invoke-TM7ThreatAnalysis.ps1` and are NOT covered here.**
> **⛔ Every HTML snippet, CSS class name, badge label, JSON field name, and metric card ID in this file is a BINDING CONTRACT. Use them VERBATIM. Do NOT paraphrase, rename, reorder, or invent alternatives.**
> **⛔ Micro-validation checkpoints (marked ⛔ POST-CHECK) are MANDATORY. Run each check IMMEDIATELY at the indicated point. If ANY check fails → FIX before continuing to the next step.**

---

## 1. Threat Row Format Contract

### 1.1 NEW-LLM Row (threat not in KB)

```html
<tr style="background: #fdf6ec;">
  <td>{next_number}</td>
  <td><code style="background:#e67e22;color:white;padding:2px 6px;border-radius:3px">NEW-LLM</code></td>
  <td><span class="badge badge-{category}">{Category}</span></td>
  <td>{Threat title — specific, citing component names and flow names from TM7}</td>
  <td><span class="badge badge-llm-new">NEW - LLM</span></td>
</tr>
```

### 1.2 EXTENDS-KB Row (LLM-identified variant of existing KB threat)

> **⛔ CRITICAL: The EXTENDS row MUST use `background: #edf6fd` (blue) — NOT `#e8e8e8` (gray), NOT the KB row color, NOT any other hex value. This is the #1 most common LLM deviation detected in testing. Copy the template below CHARACTER FOR CHARACTER.**

```html
<tr style="background: #edf6fd;">
  <td>{next_number}</td>
  <td><code style="background:#3498db;color:white;padding:2px 6px;border-radius:3px">EXTENDS {ruleId}</code></td>
  <td><span class="badge badge-{category}">{Category}</span></td>
  <td>{Threat title — must state how this EXTENDS the KB rule, not just restate it}</td>
  <td><span class="badge badge-llm-extends">EXTENDS KB</span></td>
</tr>
```

### 1.3 Format Rules (MANDATORY — no exceptions)

| Rule | Correct | WRONG (do NOT use) |
|------|---------|---------------------|
| Row numbering | Continue from last KB row. If last KB threat is row 43, next LLM row is 44, 45, 46... | Do NOT restart at 1. Do NOT use `LLM-01` in the `#` column. |
| Status badge (NEW) | `<span class="badge badge-llm-new">NEW - LLM</span>` | `NEW (LLM)`, `NEW`, `Added by LLM`, `[NEW-LLM]`, `NEW - AI` |
| Status badge (EXTENDS) | `<span class="badge badge-llm-extends">EXTENDS KB</span>` | `EXTENDS`, `Extends KB`, `EXTENDS_KB`, `KB Extension` |
| Row background (NEW) | `style="background: #fdf6ec;"` inline on `<tr>` | `class="llm-new-row"`, `bgcolor="#fdf6ec"`, `rgb(253,246,236)` |
| Row background (EXTENDS) | `style="background: #edf6fd;"` inline on `<tr>` | `class="llm-extends-row"`, `bgcolor="#edf6fd"` |
| Rule ID cell (NEW) | `<code style="background:#e67e22;color:white;padding:2px 6px;border-radius:3px">NEW-LLM</code>` | `NEW-LLM` without `<code>` tag, different colors, missing padding |
| Rule ID cell (EXTENDS) | `<code style="background:#3498db;color:white;padding:2px 6px;border-radius:3px">EXTENDS {ruleId}</code>` | Omitting ruleId, wrong color, missing `<code>` tag |
| Category badge class | `badge-spoofing`, `badge-tampering`, `badge-repudiation`, `badge-info`, `badge-dos`, `badge-elevation`, `badge-compliance`, `badge-custom` | `badge-s`, `badge-spoofed`, `badge-tampering-llm`, any invented names |
| Table columns | 5 columns: `#` \| `Rule` \| `Category` \| `Threat` \| `Status` | Do NOT add `Evidence`, `Affected Components`, `Severity`, `Flow`, or any extra columns |
| Threat title | Specific: cites actual component/flow names from TM7 (e.g., "KQL injection via unsanitized parameters in ADX Ingestion flow") | Generic: "SQL injection vulnerability", "potential data leak" |

<!-- ⛔ POST-CHECK: ROW FORMAT REVIEW
After writing ALL LLM threat rows (before moving to Section 8 update), verify:
  1. Every NEW-LLM row has EXACTLY: `style="background: #fdf6ec;"` on <tr>
  2. Every EXTENDS row has EXACTLY: `style="background: #edf6fd;"` on <tr>
  3. Status column uses EXACT badge text: `NEW - LLM` or `EXTENDS KB` (match character-for-character)
  4. Row numbers are sequential continuing from last KB row (no gaps, no restarts)
  5. Category badge uses ONLY the 8 allowed class names listed above
  6. Table still has exactly 5 columns per row (count <td> tags)
  7. No extra columns added (Evidence, Component, Flow, etc.)
If ANY check fails → FIX the rows NOW before updating Section 8. -->

---

## 2. Threat Row Placement Rules

### 2.1 Where to Insert Rows

LLM threat rows are inserted into **existing** Section 6 STRIDE Threat Matrix tables.

| Scenario | Where to Insert |
|----------|----------------|
| Threat maps to a specific interaction (source → [flow] → target) | Append row(s) at the end of that interaction's `<table>`, just before `</table>` |
| Threat spans multiple interactions | Pick the PRIMARY interaction (the one most directly affected) and insert there |
| Threat is system-wide (no single interaction) | Create a new `<h3>System-Wide Threats</h3>` group AFTER all interaction groups, with its own `<table>` using the same 5-column header |

### 2.2 System-Wide Table Format (only if needed)

```html
<h3>System-Wide Threats</h3>
<table><tr><th>#</th><th>Rule</th><th>Category</th><th>Threat</th><th>Status</th></tr>
[LLM threat rows here]
</table>
```

<!-- ⛔ POST-CHECK: ROW PLACEMENT REVIEW
After all rows are placed, verify:
  1. No LLM row was placed OUTSIDE a <table> (every row is inside <table>...</table>)
  2. Rows are appended BEFORE the closing </table> tag, not after it
  3. If System-Wide table was created, it has the exact 5-column <th> header
  4. No duplicate rows — each LLM threat appears exactly once
If ANY check fails → FIX NOW before updating Section 8. -->

---

## 3. Section 8 Placeholder Replacement

### 3.1 What to Replace

Find the existing placeholder content inside the `<div id="llm-threats-placeholder">` and replace it.

**FIND** (the placeholder paragraph):
```html
<p style="color: var(--gray); font-style: italic;">
The AI analyzes the architecture, deployment context, and element properties to identify
threats beyond what the KnowledgeBase template rules detect. These threats are added directly
into the STRIDE Threat Matrix (Section 6) above, tagged with <code style="background:#e67e22;color:white;padding:2px 6px;border-radius:3px">NEW-LLM</code>
or <code style="background:#3498db;color:white;padding:2px 6px;border-radius:3px">EXTENDS</code>.
A summary will appear here after analysis completes.
</p>
```

**REPLACE WITH** (exact format):
```html
<h3>LLM-Augmented Threats Summary</h3>
<p><strong>{new_count}</strong> new threats and <strong>{extends_count}</strong> KB extensions
were identified through AI analysis of the architecture, deployment context, and element properties.
These threats have been added directly into the STRIDE Threat Matrix (Section 6) above.</p>
<p><strong>{duplicate_count}</strong> duplicate candidates were filtered out during deduplication
against the {kb_count} existing KB-generated threats.</p>
<table><tr><th>Metric</th><th>Count</th></tr>
<tr><td>KB-Generated Threats</td><td>{kb_count}</td></tr>
<tr><td><span class="badge badge-llm-new">NEW - LLM</span></td><td>{new_count}</td></tr>
<tr><td><span class="badge badge-llm-extends">EXTENDS KB</span></td><td>{extends_count}</td></tr>
<tr><td>Duplicates Excluded</td><td>{duplicate_count}</td></tr>
<tr style="font-weight:bold;"><td>Total Threats</td><td>{total_count}</td></tr>
</table>
```

### 3.2 Replacement Rules

| Rule | Detail |
|------|--------|
| `{new_count}` | Count of `badge-llm-new` badges inserted in Section 6 |
| `{extends_count}` | Count of `badge-llm-extends` badges inserted in Section 6 |
| `{duplicate_count}` | Number of LLM candidates that matched KB threats and were excluded |
| `{kb_count}` | Value from `llm_augmentation_context.kb_threat_count` in the JSON |
| `{total_count}` | `{kb_count}` + `{new_count}` + `{extends_count}` |
| Placeholder detection | Text `"Phase 9 will analyze"` or `"A summary will appear here"` must NOT remain after replacement |

<!-- ⛔ POST-CHECK: SECTION 8 REPLACEMENT
After replacing the placeholder, verify:
  1. No text containing "will analyze" or "will appear here" remains in the HTML
  2. The summary table has EXACTLY 5 rows (KB-Generated, NEW-LLM, EXTENDS KB, Duplicates, Total)
  3. The Total row value = KB + NEW + EXTENDS
  4. Counts in the summary table match actual badge counts in Section 6
If ANY check fails → FIX NOW before updating metric cards. -->

---

## 4. Section 5 Metric Card Updates

### 4.1 Metric Card IDs (EXACT — do not change)

| Card | HTML `id` attribute | What to set |
|------|-------------------|-------------|
| Total Threats | `total-threats-count` | `{kb_count}` + `{new_count}` + `{extends_count}` |
| LLM New | `llm-new-count` | Count of `badge-llm-new` badges in Section 6 |
| LLM Extends | `llm-extends-count` | Count of `badge-llm-extends` badges in Section 6 |

### 4.2 Update Method

These are updated by the Step 6 validation script (see tm7-threat-generation.md Phase 9 Step 6).
Do NOT manually edit metric card values — the script counts actual badges and sets the values.

<!-- ⛔ POST-CHECK: METRIC CARDS (run after Step 6 validation script)
Verify by reading the Step 6 script output:
  1. `total-threats-count` = KB threats + LLM NEW + LLM EXTENDS
  2. `llm-new-count` = exact count of `<span class="badge badge-llm-new">` in HTML
  3. `llm-extends-count` = exact count of `<span class="badge badge-llm-extends">` in HTML
  4. Card values are INTEGERS (not "0" strings or empty)
If ANY check fails → the Step 6 script will report the error. Fix and re-run. -->

---

## 5. JSON Augmentation Schema

### 5.1 `llm_threats` Array (MANDATORY — append to existing JSON)

```json
{
  "llm_threats": [
    {
      "id": "LLM-01",
      "tag": "NEW",
      "category": "[FILL: Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege]",
      "title": "[FILL: specific threat title matching what was inserted in HTML]",
      "affected_components": ["[FILL: element name 1]", "[FILL: element name 2]"],
      "affected_flow": "[FILL: flow name or 'System-Wide']",
      "evidence": "[FILL: specific architectural evidence — file paths, protocols, component properties]",
      "extends_kb_rule": null
    }
  ]
}
```

### 5.2 `llm_dedup_summary` Object (MANDATORY)

```json
{
  "llm_dedup_summary": {
    "total_candidates": "[FILL: int — total LLM threats considered before dedup]",
    "new": "[FILL: int — threats tagged NEW]",
    "extends_kb": "[FILL: int — threats tagged EXTENDS_KB]",
    "duplicates_excluded": "[FILL: int — threats excluded as duplicates]"
  }
}
```

### 5.3 Field Rules

| Field | Type | Valid Values | WRONG |
|-------|------|-------------|-------|
| `id` | string | `LLM-01`, `LLM-02`, ... (sequential, zero-padded to 2 digits) | `1`, `NEW-1`, `llm_threat_1`, `LLM-A` |
| `tag` | string | Exactly `"NEW"` or `"EXTENDS_KB"` (case-sensitive) | `"new"`, `"NEW-LLM"`, `"EXTENDED"`, `"extends"`, `"EXTENDS"` |
| `category` | string | Exact STRIDE names: `"Spoofing"`, `"Tampering"`, `"Repudiation"`, `"Information Disclosure"`, `"Denial of Service"`, `"Elevation of Privilege"` | `"S"`, `"DoS"`, `"Info Disclosure"`, `"EoP"`, abbreviated forms |
| `affected_components` | string[] | Array of element names from the TM7 (must match `elements[].name` in the JSON) | Empty array, generic names not in TM7, component IDs instead of names |
| `affected_flow` | string | Flow name from TM7 OR `"System-Wide"` | Empty string, flow GUID, generic description |
| `evidence` | string | Specific: cites architecture details, properties, protocols, paths | Vague: "could be vulnerable", "should be investigated" |
| `extends_kb_rule` | string\|null | KB rule ID (e.g., `"TH96"`, `"S3"`) for EXTENDS_KB; `null` for NEW | Missing for EXTENDS_KB, non-null for NEW |
| `total_candidates` | int | Must equal `new` + `extends_kb` + `duplicates_excluded` | String, float, or incorrect sum |

<!-- ⛔ POST-CHECK: JSON AUGMENTATION
After writing llm_threats and llm_dedup_summary to the JSON file, verify:
  1. JSON is valid (parseable by `ConvertFrom-Json` without errors)
  2. `llm_threats` count = `llm_dedup_summary.new` + `llm_dedup_summary.extends_kb`
  3. `total_candidates` = `new` + `extends_kb` + `duplicates_excluded`
  4. Every `tag` value is exactly `"NEW"` or `"EXTENDS_KB"` (no other values)
  5. Every `category` is a full STRIDE name (not abbreviated)
  6. Every `affected_components` entry matches an element name in `elements[].name`
  7. Every EXTENDS_KB threat has a non-null `extends_kb_rule`; every NEW threat has null
Run: `$j = Get-Content "<data.json>" -Raw | ConvertFrom-Json; $j.llm_threats.Count; $j.llm_dedup_summary`
If ANY check fails → FIX the JSON NOW. -->

---

## 6. Deduplication Rules

### 6.1 Classification Criteria

For each LLM-generated threat candidate, compare its **attack surface and root cause** (not just title words) against the KB threat titles in `llm_augmentation_context.kb_threat_titles`:

| Classification | Criteria | Action | HTML Badge | JSON `tag` |
|---------------|----------|--------|------------|------------|
| **NEW** | No KB threat covers this attack surface OR root cause. The vulnerability mechanism is fundamentally different from all KB threats. | Include in Section 6 with NEW-LLM row | `badge-llm-new` | `"NEW"` |
| **EXTENDS_KB** | A KB threat covers the general category, but the LLM identifies a **more specific technology variant** (e.g., KB="SQL injection" → LLM="KQL injection via ADX") or a **deployment-specific instance** (e.g., KB="credential exposure" → LLM="Key Vault SAS token logged to ETW trace") | Include in Section 6 with EXTENDS row, cite the KB rule ID | `badge-llm-extends` | `"EXTENDS_KB"` |
| **DUPLICATE** | The KB threat already covers this exact scenario at the same specificity level. The LLM threat is just a rewording. | **Exclude** — do NOT insert into HTML or JSON `llm_threats` | (none) | (not in array) |

### 6.2 Deduplication Decision Examples

| LLM Candidate | KB Threats Present | Decision | Why |
|--------------|-------------------|----------|-----|
| "KQL injection via user search parameters" | "SQL Injection for SQL Database" | EXTENDS_KB (cite T7) | Same injection class but different query language |
| "ETW session hijacking to intercept diagnostic telemetry" | (no ETW-related KB threats) | NEW | Novel attack surface not covered by any KB rule |
| "Spoofing the User External Entity" | "Spoofing the User External Entity" (S3) | DUPLICATE | Exact same threat, same specificity |
| "Unsigned binary replacement in Provisioning Agent install path" | "Remote Code Execution" (99f62073) | EXTENDS_KB (cite 99f62073) | Same category but with specific supply-chain vector |
| "Denial of service via log flooding to disk exhaustion" | "Process Crash/Stop" (D3) | NEW | Different DoS mechanism (resource exhaustion vs crash) |

<!-- ⛔ POST-CHECK: DEDUPLICATION QUALITY
After classifying all LLM threat candidates, verify:
  1. At least 1 NEW threat was found (if 0, analysis may be too conservative)
  2. No EXTENDS_KB threat has an `extends_kb_rule` that doesn't exist in the KB threat list
  3. No DUPLICATE classification was used for a threat with a genuinely different attack mechanism
  4. Every NEW threat cites specific architectural evidence (not generic risk statements)
  5. Dedup math: total_candidates = NEW + EXTENDS_KB + DUPLICATE
If NEW count is 0 → reconsider: are there really no deployment-specific risks beyond template rules? -->

---

## 7. CSS Classes Required

These CSS classes MUST exist in the HTML `<style>` block. The PS1 script does NOT generate them — they must be injected during Phase 9 if not already present.

```css
.badge-llm-new { background: #e67e22; color: white; }
.badge-llm-extends { background: #3498db; color: white; }
```

**Check before injecting:** Search the HTML for `badge-llm-new` in the `<style>` block. If already present, do NOT add duplicates.

<!-- ⛔ POST-CHECK: CSS VALIDATION
After all HTML edits, verify:
  1. `badge-llm-new` class defined exactly once in <style> block
  2. `badge-llm-extends` class defined exactly once in <style> block
  3. Colors match: `#e67e22` (orange) for NEW, `#3498db` (blue) for EXTENDS
  4. No duplicate CSS class definitions
Run: `(Select-String -Path "<report.html>" -Pattern 'badge-llm-new').Count` — should be >= 2 (1 in style + 1+ in badges)
If badge-llm-new appears 0 times in <style> → CSS injection was missed. -->

---

## 8. End-to-End Phase 9 Validation Sequence

Run these checks IN ORDER after all Phase 9 work is complete. This is the FINAL gate.

### 8.1 HTML Structure Checks

```powershell
$html = Get-Content "<report.html>" -Raw

# Check 1: LLM rows exist
$newRows = ([regex]::Matches($html, '<span class=[''"]badge badge-llm-new[''"]>')).Count
$extRows = ([regex]::Matches($html, '<span class=[''"]badge badge-llm-extends[''"]>')).Count
Write-Host "LLM NEW rows: $newRows  |  EXTENDS rows: $extRows"
# PASS: newRows > 0

# Check 2: Section 8 placeholder replaced
$placeholder = ([regex]::Matches($html, 'will analyze|will appear here|A summary will appear')).Count
Write-Host "Placeholder remnants: $placeholder"
# PASS: placeholder == 0

# Check 3: Section 8 summary table present
$summaryTable = ([regex]::Matches($html, 'LLM-Augmented Threats Summary')).Count
Write-Host "Section 8 summary heading: $summaryTable"
# PASS: summaryTable == 1

# Check 4: Row backgrounds correct (spot check)
$orangeBg = ([regex]::Matches($html, 'background: #fdf6ec')).Count
$blueBg   = ([regex]::Matches($html, 'background: #edf6fd')).Count
Write-Host "Orange bg rows: $orangeBg  |  Blue bg rows: $blueBg"
# PASS: orangeBg == newRows, blueBg == extRows

# Check 5: CSS classes present
$cssNew = ([regex]::Matches($html, '\.badge-llm-new\s*\{')).Count
$cssExt = ([regex]::Matches($html, '\.badge-llm-extends\s*\{')).Count
Write-Host "CSS badge-llm-new defined: $cssNew  |  badge-llm-extends defined: $cssExt"
# PASS: cssNew >= 1, cssExt >= 1

# Check 6: No extra columns in LLM rows (each row should have exactly 5 <td>)
# Extract LLM rows by background color, count tds
$llmRowPattern = '<tr style="background: #(?:fdf6ec|edf6fd);">.*?</tr>'
$llmRows = [regex]::Matches($html, $llmRowPattern, 'Singleline')
$badColumnCount = 0
foreach ($row in $llmRows) {
    $tdCount = ([regex]::Matches($row.Value, '<td>')).Count
    if ($tdCount -ne 5) { $badColumnCount++; Write-Host "  BAD: row has $tdCount columns (expected 5)" }
}
Write-Host "Rows with wrong column count: $badColumnCount"
# PASS: badColumnCount == 0

# Check 7: Row numbering continuity
$allRowNumbers = [regex]::Matches($html, '<tr[^>]*>\s*<td>(\d+)</td>') | ForEach-Object { [int]$_.Groups[1].Value }
$sorted = $allRowNumbers | Sort-Object
for ($i = 1; $i -lt $sorted.Count; $i++) {
    if ($sorted[$i] -ne $sorted[$i-1] + 1 -and $sorted[$i] -ne $sorted[$i-1]) {
        Write-Host "  GAP: row $($sorted[$i-1]) -> $($sorted[$i])" -ForegroundColor Yellow
    }
}
# PASS: no gaps reported
```

### 8.2 JSON Checks

```powershell
$j = Get-Content "<data.json>" -Raw | ConvertFrom-Json

# Check 8: llm_threats array exists
$llmCount = if ($j.llm_threats) { $j.llm_threats.Count } else { 0 }
Write-Host "JSON llm_threats: $llmCount"
# PASS: llmCount > 0

# Check 9: tag values valid
$badTags = @($j.llm_threats | Where-Object { $_.tag -notin @('NEW','EXTENDS_KB') })
Write-Host "Invalid tags: $($badTags.Count)"
# PASS: badTags.Count == 0

# Check 10: dedup math
$ds = $j.llm_dedup_summary
$expectedTotal = $ds.new + $ds.extends_kb + $ds.duplicates_excluded
Write-Host "Dedup math: $($ds.total_candidates) == $expectedTotal (new=$($ds.new) + ext=$($ds.extends_kb) + dup=$($ds.duplicates_excluded))"
# PASS: ds.total_candidates == expectedTotal

# Check 11: category values are full STRIDE names
$validCats = @('Spoofing','Tampering','Repudiation','Information Disclosure','Denial of Service','Elevation of Privilege')
$badCats = @($j.llm_threats | Where-Object { $_.category -notin $validCats })
Write-Host "Invalid categories: $($badCats.Count)"
# PASS: badCats.Count == 0

# Check 12: EXTENDS_KB threats have rule IDs, NEW threats have null
$badExtends = @($j.llm_threats | Where-Object { $_.tag -eq 'EXTENDS_KB' -and -not $_.extends_kb_rule })
$badNew = @($j.llm_threats | Where-Object { $_.tag -eq 'NEW' -and $null -ne $_.extends_kb_rule })
Write-Host "EXTENDS without rule: $($badExtends.Count)  |  NEW with rule: $($badNew.Count)"
# PASS: both == 0
```

### 8.3 Cross-Validation

```powershell
# Check 13: HTML LLM row count matches JSON llm_threats count
$htmlLlmTotal = $newRows + $extRows
$jsonLlmTotal = $llmCount
Write-Host "HTML LLM rows: $htmlLlmTotal  |  JSON llm_threats: $jsonLlmTotal"
# PASS: htmlLlmTotal == jsonLlmTotal

# Check 14: Metric cards match (run AFTER Step 6 validation script)
$cardTotal = if($html -match "id='total-threats-count'>(\d+)"){[int]$Matches[1]}else{-1}
$cardNew   = if($html -match "id='llm-new-count'>(\d+)"){[int]$Matches[1]}else{-1}
$cardExt   = if($html -match "id='llm-extends-count'>(\d+)"){[int]$Matches[1]}else{-1}
$kbThreats = $j.threats.Count
$expectedCardTotal = $kbThreats + $newRows + $extRows
Write-Host "Card total=$cardTotal (expected $expectedCardTotal)  |  Card new=$cardNew (expected $newRows)  |  Card ext=$cardExt (expected $extRows)"
# PASS: all three match
```

<!-- ⛔ FINAL GATE: ALL 14 CHECKS MUST PASS.
If ANY check fails, identify the root cause and fix:
  - Check 1 fail (0 LLM rows) → Phase 9 Step 4 insertion failed. Re-do the edit.
  - Check 2 fail (placeholder remnants) → Section 8 replacement was incomplete.
  - Check 4 fail (bg mismatch) → Row format doesn't match template in Section 1.
  - Check 5 fail (CSS missing) → CSS injection in Section 7 was skipped.
  - Check 6 fail (wrong columns) → Extra <td> cells added. Match 5-column format.
  - Check 7 fail (numbering gap) → Row numbering didn't continue from last KB threat.
  - Check 9 fail (invalid tags) → JSON tag values don't match exact enum.
  - Check 13 fail (HTML≠JSON) → HTML edit and JSON update are out of sync.
  - Check 14 fail (card mismatch) → Step 6 script wasn't run or failed silently.
DO NOT mark Phase 9 complete until all 14 checks pass. -->
