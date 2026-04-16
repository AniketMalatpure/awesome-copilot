# Skeleton: 3-threatmodel.md

> **⛔ Copy the template content below VERBATIM (excluding the outer code fence). Replace `[FILL]` placeholders. Diagram in `.md` and `.mmd` must be IDENTICAL.**
> **⛔ Data Flow Table columns: `ID | Source | Target | Protocol | Description`. DO NOT rename `Target` to `Destination`. DO NOT reorder columns.**
> **⛔ Trust Boundary Table columns: `Boundary | Description | Contains` (3 columns). DO NOT add a `Name` column or rename `Contains` to `Components Inside`.**

---

````markdown
# Threat Model

[TOC: Generate a flat bullet list of all `## ` headings in this file as Markdown anchor links. Example:
- [Threat Model](#threat-model-1)
- [Expanded Threat Model](#expanded-threat-model)
- [Security Review Questions](#security-review-questions)
- [Basic to Expanded Threat Model Mapping](#basic-to-expanded-threat-model-mapping)
- [Element Table](#element-table)
- ...one entry per `## ` heading in the final file.
Include conditional sections (Threat Model, Basic to Expanded Threat Model Mapping, Security Review Questions) only if they are present in the output.]

[CONDITIONAL: Include ONLY if summary diagram was generated (elements > 15 OR boundaries > 4)]

## Threat Model

```mermaid
[FILL: Copy EXACT content from 3.2-threatmodel-summary.mmd]
```

[END-CONDITIONAL]

## Expanded Threat Model

```mermaid
[FILL: Copy EXACT content from 3.1-threatmodel.mmd]
```

[CONDITIONAL: Include ONLY if Step 7c produced Security Review Questions output]

## Security Review Questions

[FILL: mapped Q&A from security-review-questions.md — organize under area-specific `###` headings with one table per area, such as Authentication & Identity, Secrets & Credential Management, Input Validation & Prompt Injection, and Network Exposure]

[END-CONDITIONAL]

[CONDITIONAL: Include ONLY if summary diagram was generated (elements > 15 OR boundaries > 4)]

## Basic to Expanded Threat Model Mapping

| Basic Element | Contains | Basic Flows | Maps to Expanded Flows |
|---------------|----------|-------------|------------------------|
[REPEAT]
| [FILL] | [FILL] | [FILL: SDF##] | [FILL: DF##, DF##] |
[END-REPEAT]

[END-CONDITIONAL]

## Element Table

| Element | Type | TMT Category | Description | Trust Boundary |
|---------|------|--------------|-------------|----------------|
[CONDITIONAL: For K8s apps with sidecars, add a `Co-located Sidecars` column after Trust Boundary]
[REPEAT: one row per element]
| [FILL] | [FILL: Process / External Interactor / Data Store] | [FILL: SE.P.TMCore.* / SE.EI.TMCore.* / SE.DS.TMCore.*] | [FILL] | [FILL] |
[END-REPEAT]

## Data Flow Table

| ID | Source | Target | Protocol | Description |
|----|--------|--------|----------|-------------|
[REPEAT: one row per data flow]
| [FILL: DF##] | [FILL] | [FILL] | [FILL] | [FILL] |
[END-REPEAT]

## Trust Boundary Table

| Boundary | Description | Contains |
|----------|-------------|----------|
[REPEAT: one row per trust boundary]
| [FILL] | [FILL] | [FILL: comma-separated component list] |
[END-REPEAT]
````

**Fixed rules:**
- Use `DF01`, `DF02` for detailed flows; `SDF01`, `SDF02` for summary flows
- Element Type: exactly `Process`, `External Interactor`, or `Data Store`
- TMT Category: must be a specific ID from tmt-element-taxonomy.md (e.g., `SE.P.TMCore.WebSvc`)
