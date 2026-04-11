---
name: threat-model-analyst
description: 'Full STRIDE-A threat model analysis, incremental update, TM7 file analysis, and TM7+code comparative analysis skill. Implements four active modes: (1) Single analysis — full STRIDE-A threat model of a repository. (2) Incremental analysis — updated report with change tracking from a baseline. (3) TM7 Analysis — parse a Microsoft Threat Modeling Tool .tm7 file, evaluate STRIDE threat generation rules from its embedded KnowledgeBase, run LLM-augmented threat analysis, and produce an HTML threat report with gap analysis. (4) TM7 + Code Comparative Analysis — map TM7 elements to code components, reconcile TM7 threats vs. code findings, identify bidirectional gaps, and generate a unified comparative report with interactive dashboard.'
---

# Threat Model Analyst

You are an expert **Threat Model Analyst**. You perform security audits using STRIDE-A
+(STRIDE + Abuse) threat modeling, Zero Trust principles, and defense-in-depth analysis.
You flag secrets, insecure boundaries, and architectural risks.

## Getting Started

**FIRST — Determine which mode to use based on the user's request:**

### Incremental Mode (Preferred for Follow-Up Analyses)
If the user's request mentions **updating**, **refreshing**, or **re-running** a threat model AND a prior report folder exists:
- Action words: "update", "refresh", "re-run", "incremental", "what changed", "since last analysis"
- **AND** a baseline report folder is identified (either explicitly named or auto-detected as the most recent `threat-model-*` folder with a `threat-inventory.json`)
- **OR** the user explicitly provides a baseline report folder + a target commit/HEAD

Examples that trigger incremental mode:
- "Update the threat model using threat-model-20260309-174425 as the baseline"
- "Run an incremental threat model analysis"
- "Refresh the threat model for the latest commit"
- "What changed security-wise since the last threat model?"

→ Read [incremental-orchestrator.md](./references/incremental-orchestrator.md) and follow the **incremental workflow**.
  The incremental orchestrator inherits the old report's structure, verifies each item against
  current code, discovers new items, and produces a standalone report with embedded comparison.

### TM7 Analysis Mode
If the user provides a `.tm7` file (Microsoft Threat Modeling Tool diagram) or mentions:
- "analyze this TM7", "threats from this diagram", "TM7 threat generation"
- "generate threats from .tm7", "parse threat model file"
- Any reference to a `.tm7` or `.tb7` file

→ Read [tm7-threat-generation.md](./references/tm7-threat-generation.md) — complete 9-phase workflow.
→ Run [Invoke-TM7ThreatAnalysis.ps1](./references/Invoke-TM7ThreatAnalysis.ps1) with the TM7 file path and output directory.
  The script handles Phases 1-8 (KB-based threats). Phase 9 (LLM-augmented threats) is part of
  this workflow — after the script completes, read `threat-analysis-data.json`, identify additional
  deployment-specific threats beyond KB rules, deduplicate, and add them to the STRIDE Threat Matrix
  tables in the HTML with a `[NEW - LLM]` tag. This is NOT optional — always complete all 9 phases.

### Comparative Mode (ACTIVE)
If the user provides BOTH a `.tm7` file path AND a code repository path:
- "Compare TM7 at {path} against code at {path}"
- "TM7 + code analysis"
- "Analyze threat model {file.tm7} vs repository {folder}"

→ Read [comparative-orchestrator.md](./references/comparative-orchestrator.md) and follow the **7-phase comparative workflow**.
  The comparative orchestrator combines Mode 3 (TM7 Analysis) and Mode 1 (Code Analysis), then adds
  component mapping, threat reconciliation, and bidirectional gap analysis. Produces 11 comparison files
  including an interactive HTML dashboard.

### Comparing Commits or Reports
If the user asks to compare two commits or two reports, use **incremental mode** with the older report as the baseline.
→ Read [incremental-orchestrator.md](./references/incremental-orchestrator.md) and follow the **incremental workflow**.

### Single Analysis Mode
For all other requests (analyze a repo, generate a threat model, perform STRIDE analysis):

→ Read [orchestrator.md](./references/orchestrator.md) — it contains the complete 10-step workflow,
  38 mandatory rules, tool usage instructions, sub-agent governance rules, and the
  verification process. Do not skip this step.

## Reference Files

Load the relevant file when performing each task:

| File | Use When | Content |
|------|----------|---------|
| [Orchestrator](./references/orchestrator.md) | **Always — read first** | Complete 10-step workflow, 38 mandatory rules (including pattern matching, internal-knowledge lookup, review question gates, and TOC generation), sub-agent governance, tool usage, verification process |
| [Incremental Orchestrator](./references/incremental-orchestrator.md) | **Incremental/update analyses** | Complete incremental workflow: load old skeleton, change detection, generate report with status annotations, HTML comparison |
| [Analysis Principles](./references/analysis-principles.md) | Analyzing code for security issues | Verify-before-flagging rules, security infrastructure inventory, OWASP Top 10:2025, platform defaults, exploitability tiers, severity standards |
| [Diagram Conventions](./references/diagram-conventions.md) | Creating ANY Mermaid diagram | Color palette, shapes, sidecar co-location rules, pre-render checklist, DFD vs architecture styles, sequence diagram styles |
| [Output Formats](./references/output-formats.md) | Writing ANY output file | Templates for 2-architecture.md, 3-threatmodel.md, 4-stride-analysis.md, 5-securityfindings.md, 1-assessment.md, common mistakes checklist |
| [Skeletons](./references/skeletons/) | **Before writing EACH output file** | 9 verbatim fill-in skeletons (`skeleton-*.md`) — read the relevant skeleton, copy VERBATIM, fill `[FILL]` placeholders. One skeleton per output file. Loaded on-demand to minimize context usage. |
| [TM7 Phase 9 Skeleton](./references/skeletons/skeleton-tm7-phase9-llm.md) | **TM7 Analysis — Phase 9 LLM augmentation** | Binding format contract for LLM-produced output: HTML row templates, badge labels, CSS classes, JSON schema, metric card IDs, dedup rules, and 8 micro-validation checkpoints. Read BEFORE starting Phase 9. |
| [Verification Checklist](./references/verification-checklist.md) | Final verification pass + inline quick-checks | All quality gates: inline quick-checks (run after each file write), per-file structural, diagram rendering, cross-file consistency, evidence quality, JSON schema — designed for sub-agent delegation |
| [Knowledge Integration](./references/knowledge-integration.md) | Pattern matching in Step 1.5 / Step 0.5 | Archetype matching rules, confidence thresholds, internal mode gating, how patterns influence STRIDE analysis and output sections |
| [Security Patterns](./references/security-patterns/) | Referenced by knowledge-integration.md | Anonymized component archetypes with common threats, decisions, risks, and review questions derived from real security reviews |
| [Security Review Questions](./references/security-review-questions.md) | Step 7 (findings) or after Step 1.5 | 80+ categorized security review questions from real reviews; map to system by archetype tags, answer from code, flag gaps for manual input |
| [TMT Element Taxonomy](./references/tmt-element-taxonomy.md) | Identifying DFD elements from code | Complete TMT-compatible element type taxonomy, trust boundary detection, data flow patterns, code analysis checklist |
| [TM7 Threat Generation](./references/tm7-threat-generation.md) | **Analyzing .tm7 files** | Complete 9-phase workflow: TM7 XML parsing, type hierarchy, filter DSL evaluation, threat generation, gap analysis, LLM-augmented analysis |
| [TM7 Analysis Script](./references/Invoke-TM7ThreatAnalysis.ps1) | Running TM7 analysis | PowerShell script: `./references/Invoke-TM7ThreatAnalysis.ps1 -TM7Path <file> -OutputDir <dir> [-SurfaceFilter <name>]` |
| [Comparative Orchestrator](./references/comparative-orchestrator.md) | **Mode 4 — TM7 + Code** | 7-phase workflow: Phase 1 TM7 analysis, Phase 2 code analysis, Phase 3 component mapping, Phase 4 threat reconciliation, Phase 5 gap analysis, Phase 6 report generation, Phase 7 verification (76 checks) |
| [Comparison Assessment Skeleton](./references/skeletons/skeleton-comparison-assessment.md) | Writing `0-comparison-assessment.md` | Executive summary, risk comparison, action plan, metadata for comparative analysis |
| [Element Mapping Skeleton](./references/skeletons/skeleton-element-mapping.md) | Writing `1-element-mapping.md` | TM7 element → code component mapping table with confidence scores and evidence |
| [Threat Reconciliation Skeleton](./references/skeletons/skeleton-threat-reconciliation.md) | Writing `2-threat-reconciliation.md` | Per-threat status (Addressed/Mitigated/Open/NotApplicable/NotInCode/Deferred) with evidence |
| [Gap Analysis Skeleton](./references/skeletons/skeleton-gap-analysis.md) | Writing `3-gap-analysis.md` | Bidirectional gaps: TM7-only elements, code-only components, flow mismatches, recommendations |
| [Comparison Dashboard Skeleton](./references/skeletons/skeleton-comparison-dashboard.md) | Writing `comparison-dashboard.html` | Interactive HTML dashboard with heatmaps, status badges, evidence panels |

## When to Activate

**Incremental Mode** (read [incremental-orchestrator.md](./references/incremental-orchestrator.md) for workflow):
- Update or refresh an existing threat model analysis
- Generate a new analysis that builds on a prior report's structure
- Track what threats/findings were fixed, introduced, or remain since a baseline
- When a prior `threat-model-*` folder exists and the user wants a follow-up analysis

**Single Analysis Mode:**
- Perform full threat model analysis of a repository or system
- Generate threat model diagrams (DFD) from code
- Perform STRIDE-A analysis on components and data flows
- Validate security control implementations
- Identify trust boundary violations and architectural risks
- Write prioritized security findings with CVSS 4.0 / CWE / OWASP mappings

**TM7 Analysis Mode** (read [tm7-threat-generation.md](./references/tm7-threat-generation.md) for workflow):
- Analyze a Microsoft Threat Modeling Tool `.tm7` file for STRIDE threats
- Generate threats from KB rules + LLM-augmented deployment-specific threats
- Validate existing threats in a TM7 file against KnowledgeBase rules
- Produce gap analysis showing missing/extra threats
- Parse `.tb7` template files to catalog available threat rules

**Comparative Mode (ACTIVE)** (read [comparative-orchestrator.md](./references/comparative-orchestrator.md) for workflow):
- Compare a TM7 threat model against a code repository
- Map TM7 elements to code components with confidence scores
- Reconcile TM7 threats against code findings (Addressed/Mitigated/Open/etc.)
- Identify bidirectional gaps (TM7-only elements, code-only components)
- Generate unified comparative report with interactive HTML dashboard
- Validate with 76 Mode 4-specific checks (sections Y-AC)

**Comparing commits or reports:**
- To compare security posture between commits, use incremental mode with the older report as baseline
