# Knowledge Integration Reference

> This file defines how the threat model analyst skill loads, matches, and uses security pattern knowledge during analysis. Read this file when performing **Step 1.5** (single analysis) or **Step 0.5** (incremental analysis).

## Overview

The skill can optionally leverage a library of security patterns derived from anonymized threat model reviews. This library exists in two tiers:

1. **Public tier** (`security-patterns/`): Anonymized component archetypes with generic security patterns. Safe for external use. Always available.
2. **Internal tier** (`../internal-knowledge/`): Full institutional memory with per-system details. Opt-in, never published. Only available when a valid internal manifest exists.

Pattern knowledge is **advisory** — it enriches analysis but never overrides code-based evidence. All threats still require code verification per `analysis-principles.md` "Verify Before Flagging" rules.

---

## When to Load Patterns

- **Single analysis (orchestrator.md):** Execute Step 1.5 after Step 1 (context gathering) completes and before Step 2 (STRIDE analysis) begins.
- **Incremental analysis (incremental-orchestrator.md):** Execute Step 0.5 in Phase 0 after loading the baseline report, to maintain archetype consistency with the prior analysis.
- **Skip entirely** if `security-patterns/patterns-manifest.json` does not exist.

---

## Matching Rules

### Step 1: Read the Manifest

Read `security-patterns/patterns-manifest.json`. This contains the archetype index with tech indicators for each archetype.

### Step 2: Match Components to Archetypes

For each component identified in Step 1 of the analysis:

1. **Coarse filter (deterministic):** Compare the component's tech stack, deployment model, and behavioral patterns against each archetype's `tech_indicators` object. Score = count of matching indicators across all indicator categories.

2. **LLM rerank:** For archetypes with ≥2 indicator matches, use your reasoning to assess whether the component genuinely fits the archetype. Consider:
   - Does the component's *purpose* align with the archetype description?
   - Are the matching indicators core to the component or incidental?
   - Could the match be a false positive (e.g., a service uses Kubernetes but isn't a "K8s extension")?

3. **Confidence scoring:**
   - **≥ 0.7 (High):** Strong match — load the archetype and use patterns proactively in analysis.
   - **0.4–0.7 (Medium):** Plausible match — load the archetype but note lower confidence. Use patterns as secondary reference only.
   - **< 0.4 (Low):** Abstain — do not load the archetype. Do not reference it in output.

4. **No artificial limits:** Load ALL archetypes that meet the ≥ 0.4 threshold. With 128K+ context windows, there is no need to cap the number of matched archetypes.

### Step 3: Load Archetype Files

For each matched archetype, read the full `.md` file from `security-patterns/archetypes/`. These files contain:
- Review Questions → surface these during analysis to ensure coverage
- Common Threat Patterns → use as hints during STRIDE analysis
- Decision Patterns → reference in findings remediation sections
- Acceptable Risk Patterns → flag in assessment if same conditions apply
- Common Action Items → inform remediation recommendations

---

## Internal Mode Gating

Internal mode provides access to detailed per-system security reviews. **⛔ Checking whether internal mode is available is MANDATORY (Rule 37).** The orchestrator requires you to attempt the directory check and record `INTERNAL_MODE_RESULT` before any output files are written. The activation itself is gated by health checks — but the *attempt* to check is not optional.

### Activation Requirements (ALL must be true)

1. Directory `../internal-knowledge/` exists
2. File `../internal-knowledge/internal-manifest.json` exists and is valid JSON
3. Manifest field `status` equals `"complete"`
4. Manifest field `schema_version` equals `"1.0"` (must match expected version)
5. Manifest field `generated_at` is within the last 30 days
6. Manifest field `source_count` is > 0

If ANY check fails → record `INTERNAL_MODE_RESULT = "inactive: health check failed — [which check]"` and fall back to public-only mode.
If the directory does not exist → record `INTERNAL_MODE_RESULT = "inactive: directory not found"`.
If ALL checks pass → record `INTERNAL_MODE_RESULT = "active: N systems loaded from M archetypes"` after completing the Internal Matching steps below.

### Internal Matching

When internal mode is active:

1. Read `archetype_systems` from the manifest — this maps each archetype ID to an array of system IDs.
2. For each matched archetype (from Step 2), find the systems that share that archetype.
3. For each candidate system, load the system JSON from `../internal-knowledge/systems/{system_id}.json`.
4. Score similarity:
   - Same archetype match = base score
   - Overlapping tech stack indicators = bonus
   - Similar deployment model = bonus
5. Load the top 3 most similar systems above a similarity threshold of 0.5.
6. Extract from each system:
   - **Approved threats** that may apply to the current analysis target
   - **Approved decisions** that show how similar issues were resolved
   - **Accepted risks** that document what conditions made a risk acceptable
   - **Review questions** that proved valuable in a similar context

---

## How Patterns Influence Analysis

### During STRIDE Analysis (Steps 2–4)

- Pattern threats are used as **hints** — they suggest areas to investigate, not conclusions to adopt.
- For each pattern threat, verify whether the same condition exists in the current codebase before including it.
- If a pattern threat IS confirmed in the code, note it as "consistent with known pattern for [archetype]" in the threat description.
- If a pattern threat is NOT confirmed, do not include it. Patterns do not create threats — code does.

### In Findings (5-securityfindings.md)

- Add an optional **"Pattern References"** section (see output-formats.md for template).
- For each component with matched archetypes, list the archetype, confidence score, and which pattern threats were referenced during analysis.
- This section is omitted entirely if no pattern matches were made.

### In Assessment (1-assessment.md)

- Add an optional **"Pattern Context"** section showing matched archetypes and surfaced review questions.
- In **internal mode only**, add an **"Institutional Context"** section with:
  - Similar system references (system name, key insight, relevance)
  - Prior decisions applicable to the current analysis
- The Institutional Context section **MUST NOT** appear if internal mode was not active.

### In Threat Inventory (threat-inventory.json)

- Add a `pattern_context` object at the top level:
  ```json
  {
    "pattern_context": {
      "format_version": "2.0",
      "archetypes_matched": [
        {
          "id": "edge-appliance",
          "confidence": 0.85,
          "pattern_threats_referenced": ["T-EDGE-001", "T-EDGE-003"]
        }
      ],
      "mode": "public",
      "internal_systems_referenced": []
    }
  }
  ```
- `mode` is `"public"` or `"internal"` depending on which tier was active.
- `internal_systems_referenced` is empty in public mode; contains system IDs in internal mode.

---

## Output Rules

1. **Pattern References section** is optional — omit if no archetypes matched (confidence ≥ 0.4).
2. **Institutional Context section** is present ONLY in internal mode — never in public mode.
3. **Mode consistency:** If `pattern_context.mode` is `"public"` in threat-inventory.json, then NO internal system references may appear anywhere in the output.
4. **Attribution:** Pattern-informed threats must be clearly labeled as such. Never present a pattern hint as an original finding without code verification.
5. **Verification-checklist compliance:** All new sections must pass the checks defined in verification-checklist.md.

---

## Archetype Version Stability

- Archetype IDs are **stable identifiers** — they do not change between manifest versions.
- New archetypes may be added; existing archetypes are never removed (they may be deprecated with a `deprecated: true` flag and a `successor_id`).
- The manifest `schema_version` is bumped only for breaking changes to the manifest structure.
