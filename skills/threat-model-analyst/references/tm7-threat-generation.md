# TM7 Threat Generation — STRIDE Analysis from TM7 Diagrams

This file contains the complete instructions for extracting a threat model from an existing
Microsoft Threat Modeling Tool `.tm7` file and generating STRIDE-based threats from its diagram.
It is self-contained — all element types, attributes, and threat rules come from the TM7's own
embedded KnowledgeBase (or an associated `.tb7` template file).

---

## When to Use

Activate this workflow when the user:
- Provides a `.tm7` file and asks for threat analysis, STRIDE analysis, or threat generation
- Asks to "analyze threats in this TM7 file" or "generate STRIDE analysis from this threat model"
- Wants to validate whether a TM7 file's existing threats are complete
- Provides a `.tb7` template and asks what threats it would generate for a given diagram

**Do NOT use** this workflow for code-based threat modeling (use `orchestrator.md` instead).

---

## TM7 File Format Reference

### XML Namespaces

Every TM7 file uses these namespaces:

| Prefix | URI | Used For |
|--------|-----|----------|
| `m` | `http://schemas.datacontract.org/2004/07/ThreatModeling.Model` | Top-level model elements |
| `a` | `http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts` | Element properties (Guid, TypeId, GenericTypeId, position) |
| `kb` | `http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase` | KnowledgeBase types, attributes, threat rules |
| `arr` | `http://schemas.microsoft.com/2003/10/Serialization/Arrays` | Array containers (KeyValueOfguidanyType, etc.) |

### Top-Level Structure

```
ThreatModel
├── DrawingSurfaceList          # Diagram pages
│   └── DrawingSurfaceModel[]   # Each page
│       ├── Borders             # Stencil elements (processes, EIs, DSs, border boundaries)
│       │   └── KeyValueOfguidanyType[]
│       │       ├── Key         # Element GUID
│       │       └── Value       # StencilRectangle | StencilEllipse | StencilParallelLines | BorderBoundary
│       ├── Lines               # Connectors (data flows) and line boundaries
│       │   └── KeyValueOfguidanyType[]
│       │       ├── Key         # Flow/boundary GUID
│       │       └── Value       # Connector | LineBoundary
│       └── Header              # Page name
├── ThreatInstances             # Existing identified threats
│   └── KeyValueOfstringThreatpc_P0_PhOB[]
│       ├── Key                 # ThreatTypeId + SourceGuid + FlowGuid + TargetGuid (concatenated)
│       └── Value               # Threat details (FlowGuid, InteractionKey, State, Priority, Properties)
├── KnowledgeBase               # Embedded template (types + rules)
│   ├── StandardElements        # Element type definitions
│   │   └── ElementType[]       # Id, Name, ParentId, Attributes, Representation
│   ├── ThreatCategories        # STRIDE + custom categories
│   │   └── ThreatCategory[]    # Id (S/T/R/I/D/E), Name, ShortDescription
│   └── ThreatTypes             # Threat generation rules
│       └── ThreatType[]        # Id, Category, ShortTitle, Description, GenerationFilters
├── ThreatMetaData              # Per-flow threat metadata
└── MetaInformation             # Model metadata (name, owner, reviewer)
```

### Element Types in Borders

Elements stored in `Borders` have these shapes:

| Shape | `i:type` attribute | Generic Type | DFD Category |
|-------|-------------------|-------------|-------------|
| Rectangle | `StencilRectangle` | `GE.EI` | External Interactor |
| Ellipse | `StencilEllipse` | `GE.P` | Process |
| Parallel Lines | `StencilParallelLines` | `GE.DS` | Data Store |
| Border Boundary | `BorderBoundary` | `GE.TB.B` or custom (e.g., `63e7829e-...` for General Network) | Trust Boundary (border) |

### Data Flows and Line Boundaries in Lines

Items stored in `Lines`:

| Type | `i:type` attribute | Generic Type | Purpose |
|------|-------------------|-------------|---------|
| Connector | `Connector` | `GE.DF` | Data flow with `SourceGuid` and `TargetGuid` |
| Line Boundary | `LineBoundary` (TypeId starts with `SE.TB.L` or generic `GE.TB.L`) | `GE.TB.L` | Trust boundary line |

**Key flow fields:**
- `SourceGuid` — GUID of the source element
- `TargetGuid` — GUID of the target element
- `TypeId` — Specific flow type (e.g., `SE.DF.TMCore.HTTPS`)
- `GenericTypeId` — Generic flow type (always `GE.DF` for data flows)

### Element Properties

Properties are stored as typed attributes in each element's `Properties` collection:

| Attribute Type | XML Type | How to Read Value |
|---------------|---------|------------------|
| `StringDisplayAttribute` | `<Value>` | Direct string value |
| `ListDisplayAttribute` | `<Value>` (array) + `<SelectedIndex>` | `Value[SelectedIndex]` — the selected option |
| `HeaderDisplayAttribute` | N/A | Section header only, no value |
| `BooleanDisplayAttribute` | `<Value i:type="c:boolean">` | Direct boolean value (`true` / `false`) |

**Common property names** (used in threat generation filters):

| Property Name | Found On | Example Values |
|---------------|----------|---------------|
| `authenticatesSource` | Data Flows | `Yes` / `No` |
| `authenticatesDestination` | Data Flows | `Yes` / `No` |
| `providesConfidentiality` | Data Flows | `Yes` / `No` |
| `providesIntegrity` | Data Flows | `Yes` / `No` |
| `XMLenc` | Data Flows | `Yes` / `No` |
| `implementsAuthenticationScheme` | Processes | `Yes` / `No` |
| `hasInputSanitizers` | Processes | `Yes` / `No` |
| `codeType` | Processes | `Managed` / `Unmanaged` |
| `storesLogData` | Data Stores | `Yes` / `No` |
| `storesCredentials` | Data Stores | `Yes` / `No` |
| `authenticatesItself` | External Interactors | `Yes` / `No` |
| `Out Of Scope` | Any | `true` / `false` (BooleanDisplayAttribute, Name GUID: `71f3d9aa-...`) |
| `Reason For Out Of Scope` | Any | Free-text string (Name GUID: `752473b6-...`) |

**Important:** Some property names in the filter DSL are the `Name` attribute of the property element, and some use GUID names (e.g., `87300e8a-8c16-4887-a717-585b34bcac1f`). When evaluating filters, match against both the `Name` field and the `DisplayName` field of each property.

**Namespace prefix note:** The prefix assignments in the table above are *suggested XPath prefixes* for querying, NOT the literal namespace prefixes used in the raw XML. The actual TM7 XML may use different prefix letters (e.g., `a:` for Arrays in one context, `b:` for KnowledgeBase in another). Always bind by full URI, not by prefix letter.

---

## Workflow — 8-Phase Threat Generation

### Phase 1 — Parse the TM7 XML

1. Load the file as XML.
2. Identify the root `ThreatModel` element and its namespaces.
3. For each `DrawingSurfaceModel` in `DrawingSurfaceList`:
   - Record the surface GUID and Header (page name).
   - Extract all items from `Borders` (elements + border boundaries).
   - Extract all items from `Lines` (data flows + line boundaries).

**For each element in Borders**, extract:

| Field | XPath (relative to Value) | Description |
|-------|--------------------------|-------------|
| GUID | `a:Guid` | Unique element identifier |
| GenericTypeId | `a:GenericTypeId` | Generic DFD category (`GE.P`, `GE.EI`, `GE.DS`, `GE.TB.B`, or custom) |
| TypeId | `a:TypeId` | Specific element type |
| Name | First `StringDisplayAttribute` where `DisplayName` is the header text | Human-readable name |
| Properties | All `ListDisplayAttribute` / `StringDisplayAttribute` entries | Key-value pairs |
| Position | `a:Left`, `a:Top`, `a:Width`, `a:Height` | For boundary crossing detection |
| Out Of Scope | Property named `Out Of Scope` | If `true`, exclude from threat generation |
| i:type | Attribute on the Value element | Shape type (StencilRectangle, StencilEllipse, etc.) |

**For each item in Lines**, extract:

| Field | XPath (relative to Value) | Description |
|-------|--------------------------|-------------|
| GUID | `a:Guid` | Unique identifier |
| GenericTypeId | `a:GenericTypeId` | `GE.DF` for flows, `GE.TB.L` for line boundaries |
| TypeId | `a:TypeId` | Specific type |
| SourceGuid | `a:SourceGuid` | Source element (only for data flows) |
| TargetGuid | `a:TargetGuid` | Target element (only for data flows) |
| Properties | All attribute entries | Key-value pairs |
| Coordinates | `a:SourceX`, `a:SourceY`, `a:TargetX`, `a:TargetY`, `a:HandleX`, `a:HandleY` | For boundary crossing geometry |

**Distinguish flows from line boundaries:**
- If `GenericTypeId` is `GE.DF` → Data Flow (Connector)
- If `GenericTypeId` is `GE.TB.L` or TypeId starts with `SE.TB.L` → Line Boundary
- Line boundaries have `SourceGuid` and `TargetGuid` as all-zeros (`00000000-0000-0000-0000-000000000000`)

### Phase 2 — Build the Type Hierarchy

The KnowledgeBase's `StandardElements` section defines all element types and their inheritance via `ParentId`.

1. Extract every `ElementType` from `KnowledgeBase.StandardElements`:
   - `Id` — the type identifier (e.g., `SE.P.TMCore.WebApp`, `GE.P`, `b29c6647-...`)
   - `Name` — human-readable name
   - `ParentId` — the parent type (`ROOT` means top-level)

2. Build a type tree. Example hierarchy:

```
ROOT
├── GE.P (Generic Process)
│   ├── SE.P.TMCore.WebApp (Web Application)
│   ├── SE.P.TMCore.WebSvc (Web Service)
│   ├── SE.P.TMCore.WebServer (Web Server)
│   ├── SE.P.TMCore.NetApp (Managed Application)
│   ├── SE.P.TMCore.ThickClient (Thick Client)
│   └── 37324599-... (My Special Application)
├── GE.EI (Generic External Interactor)
│   ├── SE.EI.TMCore.Browser (Browser)
│   ├── SE.EI.TMCore.WebApp (External Web Application)
│   ├── b29c6647-... (Security Gateway)
│   └── 1801258c-... (User)
├── GE.DS (Generic Data Store)
│   ├── SE.DS.TMCore.SQL (SQL Database)
│   ├── SE.DS.TMCore.NoSQL (NoSQL Database)
│   └── SE.DS.TMCore.FS (File System)
├── GE.DF (Generic Data Flow)
│   ├── SE.DF.TMCore.HTTPS (HTTPS)
│   ├── SE.DF.TMCore.HTTP (HTTP)
│   └── SE.DF.TMCore.ALPC (SQL)
├── GE.TB.L (Generic Trust Line Boundary)
│   ├── SE.TB.L.TMCore.Internet (Internet Boundary)
│   └── SE.TB.L.TMCore.Machine (Machine Trust Boundary)
├── GE.TB.B (Generic Trust Border Boundary)
│   ├── SE.TB.B.TMCore.CorpNet (Company Trust Boundary)
│   └── SE.TB.B.TMCore.Sandbox (Sandbox Trust Boundary)
└── 63e7829e-... (General Network)  ← custom top-level category
    ├── b5d57773-... (Internet DMZ)
    ├── 57608f78-... (Office Net)
    └── 86a6b066-... (Shared)
```

3. Implement a `typeMatches(elementTypeId, filterTypeId)` function:
   - Returns `true` if `elementTypeId == filterTypeId`
   - OR if `filterTypeId` is an ancestor of `elementTypeId` in the type tree
   - Example: `typeMatches('SE.P.TMCore.WebApp', 'GE.P')` → `true` (WebApp's parent is GE.P)
   - Example: `typeMatches('b29c6647-...', 'GE.EI')` → `true` (Security Gateway's parent is GE.EI)
   - Special case: `typeMatches(anything, 'ROOT')` → `true` (ROOT is the universal ancestor)

### Phase 3 — Build the Element Registry

Create a lookup map of every element by GUID:

```
ElementRegistry = {
  "guid-1": {
    guid: "guid-1",
    name: "Web Application",
    genericTypeId: "GE.P",
    typeId: "SE.P.TMCore.WebApp",
    properties: { implementsAuthenticationScheme: "No", codeType: "Managed", ... },
    position: { left: 449, top: 94, width: 100, height: 100 },
    outOfScope: false,
    drawingSurfaceGuid: "surface-guid"
  },
  ...
}
```

**Property resolution rules:**
- For `ListDisplayAttribute`: value = `Value[SelectedIndex]` (the selected string from the array)
- For `StringDisplayAttribute`: value = `Value` (direct string)
- Store properties indexed by **both** the `Name` field AND the `DisplayName` field for lookup
- Some properties use GUID-based names (e.g., `b4a78958-4157-479f-b7e2-94f06b43bf2b` for "Security Classification")

**Multi-surface deduplication:**
- The same logical element can appear on multiple drawing surfaces
- Elements on different surfaces that share the same `TypeId` AND the same `Name` are the same logical element
- Keep all surface appearances but generate threats only once per logical element

### Phase 4 — Build the Boundary Containment Map

Determine which elements are inside which trust boundaries, and which flows cross which boundaries.

#### 4.1 Border Boundaries (Rectangles)

For each `BorderBoundary` in `Borders`:
1. Get its bounding box: (`Left`, `Top`, `Width`, `Height`)
2. An element is **inside** the boundary if the element's center point falls within the bounding box:
   - `elementCenterX = element.Left + element.Width / 2`
   - `elementCenterY = element.Top + element.Height / 2`
   - Inside if: `boundary.Left ≤ centerX ≤ boundary.Left + boundary.Width` AND
     `boundary.Top ≤ centerY ≤ boundary.Top + boundary.Height`
3. A data flow **crosses** a border boundary if exactly one of {source, target} is inside the boundary

#### 4.2 Line Boundaries

Line boundaries (in `Lines` with `GenericTypeId = GE.TB.L`) represent trust boundary lines.

For line boundaries:
1. Get the line's coordinates: (`SourceX`, `SourceY`) → (`TargetX`, `TargetY`)
2. A data flow **crosses** a line boundary if the flow's path segment from source element center to target element center intersects the line boundary segment
3. **Simplified heuristic**: If the line boundary runs roughly horizontally or vertically, check if source and target elements are on opposite sides of the line

#### 4.3 Build the Crossing Map

Produce a map: `FlowGUID → [list of boundary TypeIds that the flow crosses]`

This includes both the **specific** TypeId (e.g., `SE.TB.L.TMCore.Internet`) and the **generic** TypeId (e.g., `GE.TB.L`) and all ancestor types in the hierarchy.

**Also include border boundary ancestors.** For example, if a flow crosses boundary `b5d57773-...` (Internet DMZ), it also crosses its parent type `63e7829e-...` (General Network). Resolve the full ancestor chain using the type hierarchy from Phase 2.

### Phase 5 — Enumerate Interaction Triples

For every data flow (Connector) in the diagram:
1. Skip if `GenericTypeId` is NOT `GE.DF` (skip line boundaries)
2. Look up the source element by `SourceGuid`
3. Look up the target element by `TargetGuid`
4. Skip if source OR target is `Out Of Scope`
5. Create the interaction triple:

```
Interaction = {
  source: ElementRegistry[SourceGuid],
  flow: { guid, typeId, genericTypeId, properties },
  target: ElementRegistry[TargetGuid],
  crossesBoundaries: BoundaryCrossingMap[flowGuid]
}
```

### Phase 6 — Extract and Parse Threat Generation Rules

#### 6.1 Extract Rules from KnowledgeBase

From `KnowledgeBase.ThreatTypes`, extract each `ThreatType`:

| Field | Description |
|-------|-------------|
| `Id` | Rule identifier (e.g., `S1`, `T7`, `e4a031c7-...`) |
| `Category` | STRIDE category identifier (e.g., `S`, `T`, `R`, `I`, `D`, `E`, or custom GUID) |
| `ShortTitle` | Threat name template with `{source.Name}`, `{target.Name}`, `{flow.Name}` placeholders |
| `Description` | Full description template with same placeholders |
| `GenerationFilters.Include` | Expression that must match for threat to fire |
| `GenerationFilters.Exclude` | Expression that must NOT match (suppresses the threat) |

#### 6.2 Skip Umbrella Rules

Rules with `Include = "source is 'ROOT'"` are **umbrella/informational headers** (e.g., `SU` = "Spoofing (v3)", `TU` = "Tampering (v3)"). They match everything and are used as category headers in the TMT UI.

**Skip these during generation.** They do not produce actionable threats.

Known umbrella rule IDs: `SU`, `TU`, `RU`, `IU`, `DU`, `EU` (pattern: single letter + `U`).

#### 6.3 Parse the Filter Expression DSL

The Include/Exclude fields contain expressions in this grammar:

```
expression     := or_expr
or_expr        := and_expr ('or' and_expr)*
and_expr       := not_expr ('and' not_expr)*
not_expr       := 'not' atom | atom
atom           := '(' expression ')' | predicate
predicate      := type_check | attribute_check | crosses_check

type_check     := ('source' | 'target' | 'flow') 'is' QUOTED_STRING
attribute_check:= ('source' | 'target' | 'flow') '.' ATTRIBUTE_NAME 'is' QUOTED_STRING
crosses_check  := 'flow' 'crosses' QUOTED_STRING

QUOTED_STRING  := "'" [^']+ "'"
ATTRIBUTE_NAME := [a-zA-Z0-9_\-]+  (may also be a GUID like '87300e8a-...')
```

**Operator precedence:** `not` > `and` > `or` (standard boolean precedence).

#### 6.4 Evaluate Predicates

**Type check** — `source is 'TypeId'`:
1. Get the element's `TypeId` (specific type)
2. Call `typeMatches(element.TypeId, filterTypeId)` using the hierarchy from Phase 2
3. If `typeMatches` returns `true`, the predicate is `true`
4. Also check `genericTypeId` — `typeMatches(element.GenericTypeId, filterTypeId)`

Examples:
- `source is 'GE.P'` — matches ANY process (Web App, Web Service, etc.)
- `target is 'SE.DS.TMCore.SQL'` — matches only SQL Database
- `source is 'b29c6647-...'` — matches only Security Gateway
- `flow is 'SE.DF.TMCore.HTTPS'` — matches only HTTPS flows

**Attribute check** — `source.attributeName is 'Value'`:
1. Look up the property named `attributeName` on the element (check both `Name` and `DisplayName`)
2. For `ListDisplayAttribute`: resolve to `Values[SelectedIndex]`
3. Compare the resolved value to `'Value'` (case-insensitive)
4. If the property doesn't exist on the element, the predicate is `false`

Examples:
- `flow.authenticatesSource is 'Yes'` — true if the flow has authenticatesSource set to Yes
- `target.codeType is 'Unmanaged'` — true if the target process code type is Unmanaged
- `source.87300e8a-... is 'Yes'` — GUID-named attribute check

**Crosses check** — `flow crosses 'BoundaryTypeId'`:
1. Look up the flow in the BoundaryCrossingMap from Phase 4
2. For each boundary the flow crosses, call `typeMatches(boundaryTypeId, filterBoundaryTypeId)`
3. If any crossed boundary matches, the predicate is `true`

Examples:
- `flow crosses 'SE.TB.L.TMCore.Internet'` — flow crosses the Internet boundary
- `flow crosses 'GE.TB.L'` — flow crosses ANY line boundary
- `flow crosses 'GE.TB.B'` — flow crosses ANY border boundary
- `flow crosses 'b5d57773-...'` — flow crosses the Internet DMZ border specifically

### Phase 7 — Generate Threats

For each interaction triple from Phase 5, evaluate every threat rule from Phase 6:

```
for each interaction in interactions:
    for each rule in threatRules:
        if rule is umbrella (Include == "source is 'ROOT'"): skip
        
        includeResult = evaluate(rule.Include, interaction)
        excludeResult = evaluate(rule.Exclude, interaction)
        
        if includeResult == true AND excludeResult == false:
            threat = instantiate(rule, interaction)
            add threat to generatedThreats
```

**Instantiate** the threat:
1. Replace `{source.Name}` with the source element's name
2. Replace `{target.Name}` with the target element's name
3. Replace `{flow.Name}` with the flow's name (from its header/name property)
4. Generate a unique threat key: `rule.Id + source.Guid + flow.Guid + target.Guid`

**Empty Exclude handling:** If `rule.Exclude` is empty or blank, treat it as always `false` (never excludes).

### Phase 8 — Compare with Existing Threats (Gap Analysis)

If the TM7 file has threats in `ThreatInstances`:

1. **Extract existing threats:**
   - Each threat is stored as a `KeyValueOfstringThreatpc_P0_PhOB` under `ThreatInstances`
   - Key: concatenation of ThreatTypeId + SourceGuid + FlowGuid + TargetGuid
   - Value contains:
     - `FlowGuid` — the data flow
     - `InteractionKey` — format: `sourceGuid:flowGuid:targetGuid`
     - `State` — `AutoGenerated`, `NeedsInvestigation`, `Mitigated`, `NotApplicable`
     - `Priority` — `High`, `Medium`, `Low`
     - `Id` — numeric sequential ID
     - `DrawingSurfaceGuid` — which diagram page the threat belongs to
     - `ModifiedAt` — timestamp of last modification
     - `ChangedBy` — username who last modified
     - `Properties` — key-value pairs including:
       - `Title` — instantiated threat title
       - `UserThreatCategory` — STRIDE category name
       - `UserThreatShortDescription` — category description
       - `UserThreatDescription` — full threat description
       - GUID-keyed entries for Justification, Priority label, Team assignment

2. **Match generated threats to existing threats** by comparing threat keys (ThreatTypeId + Source + Flow + Target).

3. **Classify each threat:**

| Status | Meaning |
|--------|---------|
| ✅ **Matched** | Generated threat has a matching existing threat |
| ⚠️ **Missing** | Generated threat has NO matching existing threat — coverage gap |
| ➕ **Extra** | Existing threat has NO matching generated rule — custom/manual threat |

4. **Produce gap analysis summary.**

---

### ⛔ POST-SCRIPT VALIDATION GATE (MANDATORY — run after Phases 1-8)

After the PS1 script completes, validate the output before proceeding to Phase 9:

**1. File existence check:**
```powershell
Test-Path "<OutputDir>\threat-analysis-report.html"   # Must be True
Test-Path "<OutputDir>\threat-analysis-data.json"      # Must be True
```

**2. JSON integrity check:**
```powershell
$j = Get-Content "<OutputDir>\threat-analysis-data.json" -Raw | ConvertFrom-Json
$j.elements.Count     # Must be > 0
$j.flows.Count        # Must be > 0
$j.threats.Count      # Must be >= 0 (could be 0 for mismatched KB)
```

**3. Mermaid DFD syntax and boundary validation:**
```powershell
$html = "<OutputDir>\threat-analysis-report.html"
$j = Get-Content "<OutputDir>\threat-analysis-data.json" -Raw | ConvertFrom-Json

# 3a. Subgraph balance: every subgraph must have a matching end
$opens = (Select-String -Path $html -Pattern '^\s*subgraph ').Count
$ends = (Select-String -Path $html -Pattern '^\s*end\s*$').Count
# PASS: opens == ends

# 3b. No unescaped special characters in Mermaid node labels
# Parentheses must be #lpar;/#rpar; — raw () inside [] breaks Mermaid
$rawParens = (Select-String -Path $html -Pattern '\[.*\((?!#)' | Where-Object { $_.LineNumber -lt 300 }).Count
# PASS: rawParens == 0

# 3c. No raw newlines inside edge labels or node labels
# All labels must be single-line (newlines replaced with spaces by MermaidLabel)
$multiLineLabels = (Select-String -Path $html -Pattern '-->\|"[^"]*$' | Where-Object { $_.LineNumber -lt 300 }).Count
# PASS: multiLineLabels == 0

# 3d. Init block present (white background for dark theme safety)
$initBlock = (Select-String -Path $html -Pattern "theme.*base.*background.*#ffffff").Count
# PASS: initBlock >= 1

# 3e. linkStyle default present
$linkStyle = (Select-String -Path $html -Pattern "linkStyle default").Count
# PASS: linkStyle >= 1

# 3f. Trust boundary completeness
# Every boundary in the JSON must appear as a subgraph in the Mermaid diagram
$boundaryCount = $j.boundaries.Count
$subgraphCount = $opens
# PASS: subgraphCount >= boundaryCount (line boundaries with no inside elements may be skipped)

# 3g. All boundary subgraphs have the red dashed style applied
$styledSubgraphs = (Select-String -Path $html -Pattern 'style n_.*stroke:#e74c3c.*stroke-dasharray').Count
# PASS: styledSubgraphs == subgraphCount

# 3h. No element appears in multiple subgraphs (would break Mermaid)
# Each element node ID should appear exactly once in a subgraph or as a standalone node

# 3i. Line boundary heuristic validation
# For each line boundary: at least one element is inside the subgraph
# External Interactors should be OUTSIDE line boundary subgraphs
# Processes and Data Stores connected via crossing flows should be INSIDE
```

**4. KB threat count matches HTML:**
The JSON `threats.Count` must equal the number of `THREAT-NNN` headings in the HTML.

⛔ **If ANY check fails: DO NOT proceed to Phase 9.** Report the error and investigate.

---

### Phase 9 — LLM-Augmented Threat Analysis

> **⛔ BEFORE starting Phase 9, read [skeleton-tm7-phase9-llm.md](./skeletons/skeleton-tm7-phase9-llm.md).**
> It is the BINDING FORMAT CONTRACT for all LLM-produced output: HTML row templates, badge labels,
> CSS class names, JSON field names, metric card IDs, and deduplication rules. Every micro-validation
> checkpoint in the skeleton is MANDATORY — run each ⛔ POST-CHECK at the indicated point.

**Purpose:** The KB-based rules (Phases 1–8) only generate threats that the template author defined.
This phase uses the LLM to identify **additional threats** based on the actual architecture context
that template rules cannot detect — deployment-specific risks, technology-specific attack vectors,
operational threats, supply chain risks, and privilege escalation paths.

**When to run:** Always run Phase 9 after the PS1 script completes. Read the generated
`threat-analysis-data.json` file which contains the full architecture context.

⚠️ **STEP BUDGET WARNING — Phase 9 must complete in ≤ 6 tool calls:**
1. ONE shell command to gather all JSON context (Step 1)
2. ONE file edit to insert LLM threats into Section 6 STRIDE tables + update Section 8 (Steps 2-4)
3. ONE shell command to update the JSON with llm_threats array (Step 5)
4. ONE shell command to run the metrics fix + validation script (Step 6)
Do NOT read the JSON or HTML in multiple separate commands. Do NOT explore the file structure.
You already know the exact format from the instructions above.

#### Step 1 — Read Pre-computed Context (SINGLE COMMAND)

The PS1 script generates `phase9-context.txt` alongside the HTML and JSON. This file contains
ALL architecture context needed for Phase 9 in compact form (~2-3KB). It includes elements,
flows with DF labels and crossings, boundaries, element properties, notes, KB threat titles
(for dedup), and interactions with zero KB threats (priority gaps).

```powershell
Get-Content "<OutputDir>\phase9-context.txt" -Raw
```

⚠️ **This is ONE command.** Do NOT also read the JSON or HTML file — everything you need is
in phase9-context.txt. Do NOT run additional commands to re-read the same data.
Read the output, then proceed directly to Step 2.

#### Step 2 — Analyze for Additional Threats

For each interaction triple (source → flow → target), and for the system as a whole, consider:

| Threat Category | What to Look For |
|----------------|-----------------|
| **Deployment-specific** | File path permissions, registry key manipulation, service configuration, disk locations, environment variables, hardcoded paths |
| **Technology-specific** | Container escape (Docker), query injection (SQL, KQL, NoSQL), ETW session hijacking, notebook code injection, parser vulnerabilities (ETL, Parquet, log formats) |
| **Privilege & access** | Unnecessary admin privileges, principle of least privilege violations, service account over-permissions, WDAC/AppLocker bypass paths |
| **Data exposure** | Sensitive data in diagnostic logs, unencrypted data at rest, config files with credentials, queryable data stores without access control |
| **Operational** | Resource exhaustion (disk, memory, CPU), decompression bombs, log injection/forgery, race conditions in multi-step workflows |
| **Supply chain** | Unsigned binaries, checksum bypass, tampered Docker images, dependency confusion, untrusted download sources |

**IMPORTANT rules:**
1. Generate each threat with a STRIDE category (S, T, R, I, D, E)
2. Identify the affected components (source element, target element, flow)
3. Be specific — reference actual component names, flow names, file paths, and technologies from the TM7
4. Do NOT generate vague/generic threats — every threat must cite specific architectural evidence

#### Step 3 — Deduplicate Against KB Threats

For each LLM-generated threat, compare it against the KB-generated threat titles:

| Classification | Criteria | Action |
|---------------|----------|--------|
| **NEW** | No KB threat covers this attack surface or root cause | Include with `[NEW - LLM]` tag |
| **PARTIAL_OVERLAP** | A KB threat covers the general category but the LLM identifies a more specific variant (e.g., KB has "SQL injection" but LLM finds "KQL injection") | Include with `[EXTENDS KB: {ruleId}]` tag |
| **DUPLICATE** | The KB threat already covers this exact scenario | Exclude — do not include |

#### Step 4 — Insert LLM Threats into HTML (SINGLE EDIT OPERATION)

After deduplication, add the LLM threats **directly into the existing STRIDE Threat Matrix**
(Section 6) in the HTML report AND update Section 8 summary in the **same edit**.

⚠️ **Use ONE file edit that includes ALL LLM threat rows + Section 8 update.**
Do NOT do multiple separate edits. Do NOT read the HTML first — you already know the format.

For each LLM threat, find the matching interaction group in the STRIDE Threat Matrix
(or create a new "System-Wide" group if the threat spans the entire architecture).
Append a new row to the interaction table:

```html
<tr style="background: #fdf6ec;">
  <td>{next_number}</td>
  <td><code style="background:#e67e22;color:white;padding:2px 6px;border-radius:3px">NEW-LLM</code></td>
  <td><span class="badge badge-{category}">{Category}</span></td>
  <td>{Threat title}</td>
  <td><span class="badge badge-llm-new">NEW - LLM</span></td>
</tr>
```

For EXTENDS_KB threats, use:
```html
<tr style="background: #edf6fd;">
  <td>{next_number}</td>
  <td><code style="background:#3498db;color:white;padding:2px 6px;border-radius:3px">EXTENDS {ruleId}</code></td>
  <td><span class="badge badge-{category}">{Category}</span></td>
  <td>{Threat title}</td>
  <td><span class="badge badge-llm-extends">EXTENDS KB</span></td>
</tr>
```

The light orange/blue background row color distinguishes LLM threats from KB threats visually.

**Finding insertion points:** The HTML report contains these markers from the PS1 script:
- `<!-- LAST_KB_THREAT_NUMBER={N} -->` — the last KB threat row number. Continue LLM numbering from N+1.
- `<!-- LLM_THREATS_SECTION_END -->` — end of the Section 6 STRIDE tables. Insert a System-Wide threat `<table>` before this marker if needed.
- `id="llm-threats-placeholder"` — the Section 8 placeholder div. Replace its inner content.
- `<!-- LLM_SECTION8_END -->` — end marker for Section 8.

Use these markers to locate insertion points precisely — do NOT read or parse the full HTML.

Also update the Section 8 placeholder div with a summary count of LLM threats added:

```html
<h3>LLM-Augmented Threats Summary</h3>
<p><strong>{new_count}</strong> new threats and <strong>{extends_count}</strong> KB extensions
were identified and added to the STRIDE Threat Matrix above.
<strong>{excluded_count}</strong> duplicate candidates were filtered out.</p>
```

Add these CSS classes to the `<style>` block if not present:
```css
.badge-llm-new { background: #e67e22; color: white; }
.badge-llm-extends { background: #3498db; color: white; }
```

#### Step 5 — Update JSON Output

Append an `llm_threats` array to `threat-analysis-data.json`:

```json
{
  "llm_threats": [
    {
      "id": "LLM-01",
      "tag": "NEW",
      "category": "Tampering",
      "title": "Log file tampering before ingestion",
      "affected_components": ["File Processor", "Parse Engine"],
      "affected_flow": "Extract Data",
      "evidence": "Input directory is writable; no integrity check on input files",
      "extends_kb_rule": null
    },
    {
      "id": "LLM-02",
      "tag": "EXTENDS_KB",
      "category": "Tampering",
      "title": "KQL injection via user parameters",
      "affected_components": ["Client Application", "Query Engine"],
      "affected_flow": "Execute Queries",
      "evidence": "User-supplied parameters flow into query execution without sanitization",
      "extends_kb_rule": "TH96"
    }
  ],
  "llm_dedup_summary": {
    "total_candidates": 15,
    "new": 10,
    "extends_kb": 3,
    "duplicates_excluded": 2
  }
}
```

#### Step 6 — Final Metrics Fix & Validation (MANDATORY — LAST STEP)

After ALL Phase 9 HTML/JSON edits are done, you **MUST** run this single PowerShell script
as the absolute last step. It counts the actual LLM badges in the HTML, fixes the
Section 5 metric cards, and validates everything. Copy-paste and run it exactly:

```powershell
$htmlPath = "<report.html>"   # Replace with actual path
$jsonPath = "<data.json>"     # Replace with actual path
$html = Get-Content $htmlPath -Raw

# ── COUNT actual LLM badges in Section 6 ONLY (avoid double-counting Section 8 summary) ──
$s6Start = $html.IndexOf('<h2>6. STRIDE Threat Matrix</h2>')
$s7Start = $html.IndexOf('<h2>7. Threat Detail Cards</h2>')
if ($s6Start -ge 0 -and $s7Start -gt $s6Start) {
    $s6Html = $html.Substring($s6Start, $s7Start - $s6Start)
} else {
    $s6Html = $html  # Fallback to full HTML if section markers missing
}
$newLlm  = ([regex]::Matches($s6Html, '<span class=[''"]badge badge-llm-new[''"]>')).Count
$extends = ([regex]::Matches($s6Html, '<span class=[''"]badge badge-llm-extends[''"]>')).Count

# ── EXTRACT KB threat count from footer ──
$kbThreats = 0
if ($html -match 'Threats:\s*(\d+)\s*</p>\s*</div>\s*</body>') { $kbThreats = [int]$Matches[1] }
$total = $kbThreats + $newLlm + $extends

# ── FIX Section 5 metric cards ──
$html = $html -replace "(<div class='value' id='total-threats-count'>)[^<]+(</div>)", "`${1}$total`${2}"
$html = $html -replace "(<div class='value' id='llm-new-count'>)[^<]+(</div>)",      "`${1}$newLlm`${2}"
$html = $html -replace "(<div class='value' id='llm-extends-count'>)[^<]+(</div>)",   "`${1}$extends`${2}"

# ── Mark Phase 9 as complete ──
$html = $html -replace '<!-- PHASE9_STATUS=PENDING -->', '<!-- PHASE9_STATUS=COMPLETE -->'

$html | Set-Content $htmlPath -Encoding UTF8

# ── VALIDATE ──
$html2 = Get-Content $htmlPath -Raw
$cardTotal = if($html2 -match "id='total-threats-count'>(\d+)"){[int]$Matches[1]}else{-1}
$cardNew   = if($html2 -match "id='llm-new-count'>(\d+)"){[int]$Matches[1]}else{-1}
$cardExt   = if($html2 -match "id='llm-extends-count'>(\d+)"){[int]$Matches[1]}else{-1}
$placeholder = ([regex]::Matches($html2, 'Phase 9 will analyze')).Count

$errors = @()
if ($newLlm  -eq 0) { $errors += "NO NEW-LLM rows found in STRIDE tables" }
if ($cardNew -ne $newLlm)  { $errors += "LLM-New card ($cardNew) != actual rows ($newLlm)" }
if ($cardExt -ne $extends) { $errors += "LLM-Extends card ($cardExt) != actual rows ($extends)" }
if ($cardTotal -ne $total) { $errors += "Total card ($cardTotal) != expected ($total)" }
if ($placeholder -gt 0)    { $errors += "Section 8 placeholder still present" }

Write-Host "`n=== POST-PHASE-9 VALIDATION ===" -ForegroundColor Cyan
Write-Host "KB Threats:    $kbThreats"
Write-Host "LLM NEW rows:  $newLlm"
Write-Host "LLM EXT rows:  $extends"
Write-Host "Total (fixed): $total"
Write-Host "Cards -> Total=$cardTotal  New=$cardNew  Ext=$cardExt"

if ($errors.Count -eq 0) {
    Write-Host "`n✅ ALL CHECKS PASSED" -ForegroundColor Green
} else {
    Write-Host "`n❌ VALIDATION FAILURES:" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}

# Also validate JSON
if (Test-Path $jsonPath) {
    $j = Get-Content $jsonPath -Raw | ConvertFrom-Json
    $jLlm = if($j.llm_threats){$j.llm_threats.Count}else{0}
    Write-Host "JSON llm_threats: $jLlm"
    if ($jLlm -eq 0) { Write-Host "  ⚠️  JSON missing llm_threats array" -ForegroundColor Yellow }
}
```

⛔ **If ANY validation fails**, fix the issue and re-run this script until all pass.
⛔ **If `NO NEW-LLM rows found`**, Phase 9 threat insertion failed — go back to Step 4.
⛔ **If cards mismatch**, the regex replacement failed — check the HTML id attributes.

---

## Output Format

### 1. Architecture Summary

```markdown
## Architecture Summary

| # | Element | Type | Generic | Key Attributes |
|---|---------|------|---------|----------------|
| 1 | Web Application | SE.P.TMCore.WebApp | Process | auth=No, sanitizers=No, codeType=Managed |
| 2 | SQL Database | SE.DS.TMCore.SQL | Data Store | encrypted=No, storesLogs=No |
| 3 | User | 1801258c-... | External Interactor | authenticatesItself=No |
```

### 2. Data Flow Inventory

```markdown
## Data Flow Inventory

| # | Flow Name | Type | Source → Target | Crosses Boundaries |
|---|-----------|------|----------------|-------------------|
| 1 | HTTPS Request | SE.DF.TMCore.HTTPS | User → Web App | Internet Boundary |
| 2 | SQL Query | SE.DF.TMCore.ALPC | Web App → SQL DB | (none) |
```

### 3. Trust Boundary Map

```markdown
## Trust Boundaries

| # | Boundary | Type | Generic | Elements Inside |
|---|----------|------|---------|----------------|
| 1 | Internet Boundary | SE.TB.L.TMCore.Internet | Trust Line | (line boundary) |
| 2 | Corp Network | SE.TB.B.TMCore.CorpNet | Trust Border | Web App, SQL DB |
```

### 4. STRIDE Threat Matrix

```markdown
## STRIDE Threat Matrix

### Interaction: User → [HTTPS] → Web Application

| # | Rule ID | Category | Threat Title | Priority |
|---|---------|----------|-------------|----------|
| 1 | S3 | Spoofing | Spoofing the User External Entity | High |
| 2 | T1 | Tampering | Potential Lack of Input Validation for Web Application | High |
| 3 | T13.1 | Tampering | Cross-Site Scripting | High |
| 4 | R6 | Repudiation | Potential Data Repudiation by Web Application | High |
| 5 | D3 | DoS | Potential Process Crash or Stop for Web Application | High |
| 6 | E5 | Elevation | Elevation Using Impersonation | High |
```

Repeat per interaction triple.

### 5. Gap Analysis (when existing threats are present)

```markdown
## Gap Analysis

### Summary
- Total generated threats: 15
- Matched to existing: 10
- Missing (coverage gaps): 5
- Extra (custom/manual): 2

### Missing Threats (Coverage Gaps)

| # | Rule ID | Category | Threat | Interaction | Why Missing |
|---|---------|----------|--------|-------------|-------------|
| 1 | T1 | Tampering | Lack of Input Validation for Web App | User → HTTPS → Web App | Not in ThreatInstances |

### Extra Threats (Custom/Manual)

| # | Existing Title | Category | Interaction | Notes |
|---|---------------|----------|-------------|-------|
| 1 | Custom org-specific threat | Custom | Web App → SQL → DB | User-added, not from KnowledgeBase rules |
```

### 6. Threat Detail Cards

For each generated threat, produce a detail card:

```markdown
### THREAT-001: Spoofing the User External Entity

| Attribute | Value |
|-----------|-------|
| **Rule ID** | S3 |
| **Category** | Spoofing |
| **Interaction** | User → HTTPS → Web Application |
| **Source** | User (External Interactor) |
| **Target** | Web Application (Process) |
| **Flow** | HTTPS |
| **Boundaries Crossed** | Internet Boundary |
| **Include Filter** | `source is 'GE.EI' and target is 'GE.P' and (flow crosses 'SE.TB.L.TMCore.Internet' or flow crosses 'SE.TB.B.TMCore.CorpNet')` |
| **Exclude Filter** | `source.authenticatesItself is 'Yes' or flow.authenticatesSource is 'Yes'` |
| **Why it fires** | Source (User) is GE.EI, target (Web App) is GE.P, flow crosses Internet Boundary. Source does not authenticate itself. |
| **Existing in TM7** | ✅ Yes — State: AutoGenerated, Priority: High |

**Description:** {Full description from KnowledgeBase with placeholders resolved}
```

---

## STRIDE-per-Element Validation Matrix

Use this matrix as a sanity check after generation. Every DFD element type should have threats
in these STRIDE categories (at minimum, when trust boundaries are crossed):

| DFD Element Type | S | T | R | I | D | E |
|-----------------|---|---|---|---|---|---|
| **External Interactor** (GE.EI) | ✓ | | ✓ | | | |
| **Process** (GE.P) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Data Store** (GE.DS) | | ✓ | ✓ | ✓ | ✓ | |
| **Data Flow** (GE.DF) | | ✓ | | ✓ | ✓ | |

If a process element has zero Elevation of Privilege threats, or an external interactor has zero
Spoofing threats — and the flow crosses a trust boundary — investigate whether the KnowledgeBase
rules have appropriate coverage or if a gap should be flagged.

---

## Threat Category Reference

Standard STRIDE categories:

| Id | Category | Description |
|----|----------|-------------|
| `S` | Spoofing | Impersonating something or someone else |
| `T` | Tampering | Modifying data or code |
| `R` | Repudiation | Claiming to have not performed an action |
| `I` | Information Disclosure | Exposing information to unauthorized entities |
| `D` | Denial Of Service | Denying or degrading service to users |
| `E` | Elevation Of Privilege | Gaining capabilities without proper authorization |

Custom categories may also appear (identified by GUID-based Ids):
- `432593f8-3972-4893-95da-98ae55662223` — Compliance
- `A` — Abuse

Map custom category IDs to their names via `KnowledgeBase.ThreatCategories`.

---

## Edge Cases and Special Rules

### 1. Empty or Missing KnowledgeBase
If the TM7 has no embedded KnowledgeBase (or it's minimal), check if the user has provided a `.tb7` template file. Load threat rules from the TB7 instead. A TB7 has the same `KnowledgeBase` structure as a TM7.

### 2. Bidirectional Flows
TMT represents bidirectional communication as **two separate Connector elements** (one in each direction). Each is an independent interaction triple — generate threats for both directions independently.

### 3. Line Boundaries in the Lines Section
Trust boundary lines appear in the `Lines` collection alongside data flows. Distinguish them by:
- `SourceGuid` and `TargetGuid` are all-zeros (`00000000-0000-0000-0000-000000000000`)
- `GenericTypeId` is `GE.TB.L` (or a child type)
- Do NOT treat these as data flows

### 4. Nested Boundaries
Border boundaries can be nested (a smaller boundary inside a larger one). An element can be inside multiple boundaries simultaneously. A flow can cross multiple boundaries at once. Track ALL boundary crossings per flow.

### 5. Custom Element Types with GUID IDs
Some element types use GUID-based IDs instead of the `SE.*` naming convention (e.g., `b29c6647-371d-48d9-830e-9e7f3056d496` for Security Gateway). These are custom types added to the template. They participate in the type hierarchy via `ParentId` just like standard types.

### 6. Attribute Names as GUIDs
Some filter expressions use GUID-based attribute names (e.g., `source.87300e8a-8c16-4887-a717-585b34bcac1f is 'Yes'`). These correspond to custom properties defined in the KnowledgeBase. Match them against the `Name` field of the property in the element's Properties collection.

### 7. Multi-Surface Models
Complex models have multiple drawing surfaces. The same logical element may appear on multiple surfaces (same TypeId and Name, different surface GUIDs). Generate threats once per unique logical element, not per surface appearance.

### 8. ThreatGenerationEnabled Flag
The TM7 has a `ThreatGenerationEnabled` boolean. If `false`, the TMT UI would not auto-generate threats, but our analysis should still generate them (we are performing a comprehensive analysis regardless of this flag).

### 9. Out-of-Scope Elements
Elements with the `Out Of Scope` property set to `true` (or equivalent selected index) should be excluded from all threat generation. Flows to/from out-of-scope elements produce no threats.

---

## Example Walkthrough — Simple HTTPS Model

Given a model with: **User** (EI) → **HTTPS** → **Web App** (Process) → **SQL** → **SQL DB** (DS), with an **Internet Boundary** between User and Web App:

### Step 1: Elements
| Element | GenericType | TypeId |
|---------|------------|--------|
| User | GE.EI | 1801258c-... |
| Web Application | GE.P | SE.P.TMCore.WebApp |
| SQL Database | GE.DS | SE.DS.TMCore.SQL |

### Step 2: Flows
| Flow | Type | Source → Target | Crosses |
|------|------|----------------|---------|
| HTTPS (→) | SE.DF.TMCore.HTTPS | User → Web App | Internet Boundary |
| HTTPS (←) | SE.DF.TMCore.HTTPS | Web App → User | Internet Boundary |
| SQL (→) | SE.DF.TMCore.ALPC | Web App → SQL DB | (none) |
| SQL (←) | SE.DF.TMCore.ALPC | SQL DB → Web App | (none) |

### Step 3: Evaluate Rules

**Rule S3** (Spoofing External Entity): `source is 'GE.EI' and target is 'GE.P' and (flow crosses 'SE.TB.L.TMCore.Internet' or flow crosses 'SE.TB.B.TMCore.CorpNet')`

- Interaction: User → HTTPS → Web App
  - `source is 'GE.EI'` → User's parent chain: `1801258c → GE.EI → ROOT` → ✅ matches
  - `target is 'GE.P'` → Web App's parent chain: `SE.P.TMCore.WebApp → GE.P → ROOT` → ✅ matches
  - `flow crosses 'SE.TB.L.TMCore.Internet'` → HTTPS crosses Internet Boundary → ✅ matches
  - Result: **INCLUDE = true**

- Exclude: `source.authenticatesItself is 'Yes' or flow.authenticatesSource is 'Yes'`
  - User.authenticatesItself = `No` → false
  - HTTPS.authenticatesSource = `No` → false
  - Result: **EXCLUDE = false**

- **→ Threat S3 fires: "Spoofing the User External Entity"**

**Rule T7** (SQL Injection): `target is 'SE.DS.TMCore.SQL' and source is 'GE.P'`

- Interaction: Web App → SQL → SQL DB
  - `target is 'SE.DS.TMCore.SQL'` → SQL DB TypeId matches exactly → ✅
  - `source is 'GE.P'` → Web App parent chain includes GE.P → ✅
  - Result: **INCLUDE = true**, Exclude is empty → **EXCLUDE = false**

- **→ Threat T7 fires: "Potential SQL Injection Vulnerability for SQL Database"**

**Rule T7** on Interaction: User → HTTPS → Web App
  - `target is 'SE.DS.TMCore.SQL'` → Web App TypeId is SE.P.TMCore.WebApp, parent chain: WebApp → GE.P → ROOT. None match SE.DS.TMCore.SQL → ❌
  - Result: **INCLUDE = false** → Rule does NOT fire.

---

## TB7 Template-Only Analysis

When a user provides only a `.tb7` file (no `.tm7` diagram):

1. Parse the TB7 as the KnowledgeBase (same XML structure, without DrawingSurfaceList)
2. Extract all element types, threat categories, and threat rules
3. Instead of generating threats against a diagram, produce a **threat rule catalog**:

```markdown
## Threat Rule Catalog

### Spoofing Rules (Category: S)
| Rule ID | Title Template | Include Filter | Exclude Filter |
|---------|---------------|----------------|----------------|
| S1 | Spoofing the {source.Name} Process | source is 'GE.P' and ... | flow.authenticatesSource is 'Yes' or ... |
| S3 | Spoofing the {source.Name} External Entity | source is 'GE.EI' and ... | source.authenticatesItself is 'Yes' or ... |

### Tampering Rules (Category: T)
...
```

This catalog helps users understand what threats their template can generate and identify rule gaps.

---

## Integration Notes

- This file is **self-contained** — it does not depend on `tmt-element-taxonomy.md` or any other taxonomy mapping. All type information comes from the TM7/TB7's embedded KnowledgeBase.
- The output can optionally feed into the existing skill's `2-stride-analysis.md` format (using `output-formats.md` templates) for consistency with code-based analyses.
- When both a TM7 diagram and source code are available, results from this TM7 analysis can be cross-referenced with the code-based analysis from `orchestrator.md`.

