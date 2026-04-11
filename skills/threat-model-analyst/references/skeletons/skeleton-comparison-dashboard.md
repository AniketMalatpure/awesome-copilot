# Skeleton: comparison-dashboard.html

> **⛔ This skeleton defines the fill instructions for generating comparison-dashboard.html. The HTML structure below is the TEMPLATE. Replace `[FILL]` placeholders with actual data. Do NOT add/rename/reorder major sections.**
> `[FILL]` = single value | `[REPEAT]...[END-REPEAT]` = N rows/blocks

---

**Fill Instructions:**

1. Copy the HTML template below VERBATIM (excluding this instruction block and outer code fence)
2. Replace all `[FILL]` placeholders with actual data from JSON files
3. Preserve all HTML markers (e.g., `<!-- MAPPING_TABLE_END -->`) at their exact locations
4. Preserve all CSS classes exactly as written (e.g., `badge-addressed`, not `badge-Addressed`)
5. Ensure HTML is self-contained (no external CSS/JS, no `https://` links)
6. Include `@media print` styles for PDF export
7. Use canonical STRIDE names (no variants)
8. All status badges use exact CSS classes: badge-addressed, badge-mitigated, badge-open, badge-notapplicable, badge-notincode, badge-deferred

---

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TM7 + Code Comparative Analysis — [FILL: Project Name]</title>
    <style>
        /* Base Styles */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        /* Header */
        header {
            border-bottom: 3px solid #0078d4;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        
        h1 {
            font-size: 2em;
            color: #0078d4;
            margin-bottom: 10px;
        }
        
        .metadata {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin-top: 15px;
            font-size: 0.9em;
            color: #666;
        }
        
        .metadata-item {
            padding: 8px;
            background: #f9f9f9;
            border-left: 3px solid #0078d4;
        }
        
        .metadata-label {
            font-weight: 600;
            color: #333;
        }
        
        /* Metric Cards */
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .metric-card.coverage {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }
        
        .metric-card.mapping {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }
        
        .metric-card.gaps {
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
        }
        
        .metric-card.open {
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }
        
        .metric-label {
            font-size: 0.9em;
            opacity: 0.9;
            margin-bottom: 8px;
        }
        
        .metric-value {
            font-size: 2.5em;
            font-weight: 700;
            line-height: 1;
        }
        
        .metric-subtitle {
            font-size: 0.85em;
            opacity: 0.8;
            margin-top: 8px;
        }
        
        /* Section Headers */
        h2 {
            font-size: 1.5em;
            color: #0078d4;
            margin-top: 40px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e0e0e0;
        }
        
        /* Status Badges */
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .badge-addressed {
            background: #d4edda;
            color: #155724;
        }
        
        .badge-mitigated {
            background: #cce5ff;
            color: #004085;
        }
        
        .badge-open {
            background: #f8d7da;
            color: #721c24;
        }
        
        .badge-notapplicable {
            background: #e2e3e5;
            color: #383d41;
        }
        
        .badge-notincode {
            background: #fff3cd;
            color: #856404;
        }
        
        .badge-deferred {
            background: #e7d6f5;
            color: #5a2a8a;
        }
        
        /* Mapping Status Badges (distinct from threat status badges above) */
        .badge-confirmed {
            background: #b8e6d0;
            color: #0d5b2e;
            border: 1px solid #0d5b2e;
        }
        
        .badge-pending {
            background: #fde8c8;
            color: #7a4a0a;
            border: 1px solid #c77c1a;
        }
        
        .badge-unmappable {
            background: #d5d5d5;
            color: #4a4a4a;
            border: 1px solid #4a4a4a;
        }
        
        .badge-external-only {
            background: #c8dcf0;
            color: #1a3a5c;
            border: 1px solid #1a3a5c;
        }
        
        .badge-out-of-scope {
            background: #e0d0e8;
            color: #4a2a6a;
            border: 1px solid #6a4a8a;
        }
        
        .badge-high {
            background: #28a745;
            color: white;
        }
        
        .badge-medium {
            background: #ffc107;
            color: #333;
        }
        
        .badge-low {
            background: #dc3545;
            color: white;
        }
        
        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 0.9em;
        }
        
        th {
            background: #0078d4;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        
        td {
            padding: 10px 12px;
            border-bottom: 1px solid #e0e0e0;
            word-wrap: break-word;
            overflow-wrap: break-word;
            max-width: 400px;
        }
        
        tr:hover {
            background: #f9f9f9;
        }
        
        /* Confidence Bars */
        .confidence-bar {
            width: 100%;
            height: 8px;
            background: #e0e0e0;
            border-radius: 4px;
            overflow: hidden;
        }
        
        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, #dc3545 0%, #ffc107 50%, #28a745 100%);
            transition: width 0.3s ease;
        }
        
        /* Progress Rings (for coverage visualization) */
        .progress-ring {
            display: inline-block;
            width: 120px;
            height: 120px;
            position: relative;
        }
        
        .progress-ring svg {
            transform: rotate(-90deg);
        }
        
        .progress-ring circle {
            fill: none;
            stroke-width: 8;
        }
        
        .progress-ring .bg {
            stroke: #e0e0e0;
        }
        
        .progress-ring .progress {
            stroke: #0078d4;
            stroke-linecap: round;
            transition: stroke-dashoffset 0.5s ease;
        }
        
        .progress-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 1.5em;
            font-weight: 700;
            color: #0078d4;
        }
        
        /* Print Styles */
        @media print {
            body {
                background: white;
                padding: 0;
            }
            
            .container {
                box-shadow: none;
                padding: 0;
            }
            
            nav {
                display: none;
            }
            
            h2 {
                page-break-after: avoid;
            }
            
            table {
                page-break-inside: avoid;
            }
            
            td {
                max-width: 300px;
            }
            
            .metric-card {
                break-inside: avoid;
            }
            
            tr {
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header>
            <h1>TM7 + Code Comparative Threat Analysis</h1>
            <p style="font-size: 1.1em; color: #666; margin-top: 10px;">
                [FILL: Project Name] — [FILL: Analysis Date]
            </p>
            
            <div class="metadata">
                <div class="metadata-item">
                    <div class="metadata-label">TM7 File:</div>
                    <div>[FILL: TM7 file name]</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Code Repository:</div>
                    <div>[FILL: repo path]</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Code Commit:</div>
                    <div>[FILL: SHA] ([FILL: date])</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Analysis Duration:</div>
                    <div>[FILL: duration]</div>
                </div>
            </div>
        </header>
        
        <!-- Table of Contents -->
        <nav style="background: #f0f4f8; padding: 15px 20px; border-radius: 8px; margin-bottom: 30px; border-left: 4px solid #0078d4;">
            <strong style="font-size: 1.1em; color: #0078d4;">Contents</strong>
            <ol style="margin: 10px 0 0 20px; line-height: 1.8;">
                <li><a href="#overview" style="color: #0078d4; text-decoration: none;">Overview &amp; Metrics</a></li>
                <li><a href="#component-mapping" style="color: #0078d4; text-decoration: none;">Component Mapping</a></li>
                <li><a href="#threat-reconciliation" style="color: #0078d4; text-decoration: none;">Threat Reconciliation</a></li>
                <li><a href="#stride-distribution" style="color: #0078d4; text-decoration: none;">STRIDE Threat Distribution</a></li>
                <li><a href="#gap-analysis" style="color: #0078d4; text-decoration: none;">Gap Analysis</a></li>
                <li><a href="#flow-mismatches" style="color: #0078d4; text-decoration: none;">Flow Mismatches</a></li>
                <li><a href="#composite-model" style="color: #0078d4; text-decoration: none;">Composite Threat Model</a></li>
                <li><a href="#critical-threats" style="color: #0078d4; text-decoration: none;">Critical Open Threats (Tier 1)</a></li>
                <li><a href="#methodology" style="color: #0078d4; text-decoration: none;">Methodology &amp; Metadata</a></li>
            </ol>
        </nav>
        
        <!-- Metric Cards -->
        <h2 id="overview">Overview &amp; Metrics</h2>
        <div class="metrics">
            <div class="metric-card coverage">
                <div class="metric-label">Threat Coverage</div>
                <div class="metric-value">[FILL: NN]%</div>
                <div class="metric-subtitle">
                    [FILL: N] of [FILL: M] threats addressed or mitigated
                </div>
            </div>
            
            <div class="metric-card mapping">
                <div class="metric-label">Component Mapping</div>
                <div class="metric-value">[FILL: NN]%</div>
                <div class="metric-subtitle">
                    [FILL: N] of [FILL: M] elements mapped with high confidence
                </div>
            </div>
            
            <div class="metric-card gaps">
                <div class="metric-label">Total Gaps</div>
                <div class="metric-value">[FILL: N]</div>
                <div class="metric-subtitle">
                    [FILL: N1] TM7-only, [FILL: N2] Code-only
                </div>
            </div>
            
            <div class="metric-card open">
                <div class="metric-label">Open Threats</div>
                <div class="metric-value">[FILL: N]</div>
                <div class="metric-subtitle">
                    [FILL: N1] Tier 1, [FILL: N2] Tier 2, [FILL: N3] Tier 3
                </div>
            </div>
        </div>
        
        <!-- Component Mapping -->
        <h2 id="component-mapping">Component Mapping</h2>
        <table id="mapping-table">
            <thead>
                <tr>
                    <th>TM7 Element</th>
                    <th>Type</th>
                    <th>Code Component(s)</th>
                    <th>Confidence</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                [REPEAT: one row per TM7 element]
                <tr>
                    <td>[FILL: TM7 element name]</td>
                    <td>[FILL: Process/DataStore/ExternalEntity/DataFlow/Boundary]</td>
                    <td>[FILL: code component name(s)]</td>
                    <td>
                        <div>[FILL: 0.XX] <span class="badge badge-high/medium/low">[FILL: High/Medium/Low]</span></div>
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: [FILL: XX]%;"></div>
                        </div>
                    </td>
                    <td><span class="badge badge-[FILL: confirmed/pending/unmappable/external-only/out-of-scope]">[FILL: Confirmed/Pending/Unmappable/External Only/Out of Scope]</span></td>
                </tr>
                [END-REPEAT]
            </tbody>
        </table>
        <!-- MAPPING_TABLE_END -->
        
        <!-- Threat Reconciliation -->
        <h2 id="threat-reconciliation">Threat Reconciliation</h2>
        <table id="reconciliation-table">
            <thead>
                <tr>
                    <th>Threat ID</th>
                    <th>Category</th>
                    <th>Title</th>
                    <th>Status</th>
                    <th>Evidence</th>
                    <th>Code Finding(s)</th>
                </tr>
            </thead>
            <tbody>
                [REPEAT: one row per TM7 threat]
                <tr>
                    <td>[FILL: RECON-NNN]</td>
                    <td>[FILL: Spoofing/Tampering/Repudiation/Information Disclosure/Denial of Service/Elevation of Privilege]</td>
                    <td>[FILL: threat title]</td>
                    <td><span class="badge badge-[FILL: status]">[FILL: Addressed/Mitigated/Open/NotApplicable/NotInCode/Deferred]</span></td>
                    <td>[FILL: evidence summary or "—"]</td>
                    <td>[FILL: FIND-NN links or "—"]</td>
                </tr>
                [END-REPEAT]
            </tbody>
        </table>
        <!-- RECONCILIATION_TABLE_END -->
        
        <!-- STRIDE Distribution Chart (optional visualization) -->
        <h2 id="stride-distribution">STRIDE Threat Distribution</h2>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Total</th>
                    <th>Addressed</th>
                    <th>Mitigated</th>
                    <th>Open</th>
                    <th>Other</th>
                </tr>
            </thead>
            <tbody>
                [REPEAT: one row per STRIDE category]
                <tr>
                    <td>[FILL: Spoofing/Tampering/Repudiation/Information Disclosure/Denial of Service/Elevation of Privilege]</td>
                    <td>[FILL: N]</td>
                    <td>[FILL: N]</td>
                    <td>[FILL: N]</td>
                    <td>[FILL: N]</td>
                    <td>[FILL: N]</td>
                </tr>
                [END-REPEAT]
            </tbody>
        </table>
        
        <!-- Gap Analysis -->
        <h2 id="gap-analysis">Gap Analysis</h2>
        
        <h3>TM7-Only Elements</h3>
        <table>
            <thead>
                <tr>
                    <th>TM7 Element</th>
                    <th>Type</th>
                    <th>Reason</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
                [REPEAT: one row per TM7-only element, or "No TM7-only elements" message]
                <tr>
                    <td>[FILL: element name]</td>
                    <td>[FILL: type]</td>
                    <td>[FILL: reason]</td>
                    <td>[FILL: recommendation]</td>
                </tr>
                [END-REPEAT]
            </tbody>
        </table>
        
        <h3>Code-Only Components</h3>
        <table>
            <thead>
                <tr>
                    <th>Code Component</th>
                    <th>STRIDE Assessment</th>
                    <th>Risk Level</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
                [REPEAT: one row per code-only component, or "No code-only components" message]
                <tr>
                    <td>[FILL: component name]</td>
                    <td>[FILL: STRIDE categories or "NotApplicable"]</td>
                    <td><span class="badge badge-[FILL: high/medium/low]">[FILL: High/Medium/Low]</span></td>
                    <td>[FILL: recommendation]</td>
                </tr>
                [END-REPEAT]
            </tbody>
        </table>
        <!-- GAP_ANALYSIS_END -->
        
        <!-- Flow Mismatches -->
        <h2 id="flow-mismatches">Flow Mismatches</h2>
        
        <h3>TM7-Only Flows</h3>
        <table>
            <thead>
                <tr>
                    <th>Source</th>
                    <th>Target</th>
                    <th>Data Type</th>
                    <th>Reason</th>
                </tr>
            </thead>
            <tbody>
                [REPEAT: one row per TM7-only flow, or "All TM7 flows are implemented" message]
                <tr>
                    <td>[FILL: source]</td>
                    <td>[FILL: target]</td>
                    <td>[FILL: data type]</td>
                    <td>[FILL: reason]</td>
                </tr>
                [END-REPEAT]
            </tbody>
        </table>
        
        <h3>Code-Only Flows</h3>
        <table>
            <thead>
                <tr>
                    <th>Source</th>
                    <th>Target</th>
                    <th>Data Type</th>
                    <th>STRIDE Tags</th>
                    <th>Risk Level</th>
                </tr>
            </thead>
            <tbody>
                [REPEAT: one row per code-only flow, or "All code flows are modeled" message]
                <tr>
                    <td>[FILL: source]</td>
                    <td>[FILL: target]</td>
                    <td>[FILL: data type]</td>
                    <td>[FILL: STRIDE categories or "NotApplicable"]</td>
                    <td><span class="badge badge-[FILL: high/medium/low]">[FILL: High/Medium/Low]</span></td>
                </tr>
                [END-REPEAT]
            </tbody>
        </table>
        <!-- FLOW_MISMATCH_TABLE_END -->
        
        <!-- Composite Threat Model Summary (optional) -->
        <h2 id="composite-model">Composite Threat Model</h2>
        <p>[FILL-PROSE: Summary of unified threat model merging TM7 and code perspectives. Example: "The composite threat model includes all TM7 elements plus N code-only components discovered during analysis."]</p>
        <!-- COMPOSITE_THREATMODEL_END -->
        
        <!-- Critical Open Threats -->
        <h2 id="critical-threats">Critical Open Threats (Tier 1)</h2>
        <table>
            <thead>
                <tr>
                    <th>Threat ID</th>
                    <th>Category</th>
                    <th>Title</th>
                    <th>Component</th>
                    <th>Recommended Controls</th>
                </tr>
            </thead>
            <tbody>
                [REPEAT: one row per Tier 1 open threat, or "No Tier 1 open threats" message]
                <tr>
                    <td>[FILL: RECON-NNN]</td>
                    <td>[FILL: STRIDE category]</td>
                    <td>[FILL: threat title]</td>
                    <td>[FILL: component]</td>
                    <td>[FILL: comma-separated controls]</td>
                </tr>
                [END-REPEAT]
            </tbody>
        </table>
        <!-- DANGER_FINDINGS_END -->
        
        <!-- Footer -->
        <footer id="methodology" style="margin-top: 50px; padding-top: 20px; border-top: 2px solid #e0e0e0; color: #666; font-size: 0.9em;">
            <h2 style="font-size: 1.2em; color: #0078d4; margin-bottom: 10px;">Methodology &amp; Metadata</h2>
            <p>This analysis follows a 7-phase comparative workflow: (1) TM7 Analysis with KB + LLM threat augmentation, (2) Code Analysis using STRIDE-A methodology, (3) Component Mapping with confidence scoring, (4) Threat Reconciliation with evidence linkage, (5) Gap Analysis for bidirectional coverage, (6) Report Generation, (7) Verification against 76 validation checks.</p>
            <p style="margin-top: 10px;"><strong>Analysis Metadata:</strong></p>
            <p>Generated: [FILL: timestamp]</p>
            <p>Model: [FILL: model name]</p>
            <p>Output Folder: [FILL: folder path]</p>
            <p><strong>Related Files:</strong> 0-comparison-assessment.md, 1-element-mapping.md, 2-threat-reconciliation.md, 3-gap-analysis.md, comparison-metadata.json</p>
        </footer>
    </div>
</body>
</html>
```

**⛔ POST-GENERATION CHECKS:**

After generating the HTML file, verify:

1. **Self-contained:** No external CSS/JS, no `https://` links to stylesheets or scripts
2. **HTML markers present:** MAPPING_TABLE_END, RECONCILIATION_TABLE_END, GAP_ANALYSIS_END, FLOW_MISMATCH_TABLE_END, COMPOSITE_THREATMODEL_END, DANGER_FINDINGS_END at their exact locations
3. **CSS classes exact:** badge-addressed, badge-mitigated, badge-open, badge-notapplicable, badge-notincode, badge-deferred (all lowercase, hyphenated) for THREAT statuses; badge-confirmed, badge-pending, badge-unmappable, badge-external-only, badge-out-of-scope for MAPPING statuses
4. **STRIDE canonical names:** Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege (no variants)
5. **@media print styles:** Present in `<style>` block
6. **Confidence bars:** Width percentage matches confidence value (0-100%)
7. **Status badges:** Threat and mapping statuses use DISTINCT CSS class names (no overlap)
8. **Metric cards:** All 4 cards present with correct data
9. **Tables:** All expected tables present (mapping, reconciliation, STRIDE distribution, gap analysis, flow mismatches, critical threats)
10. **No broken placeholders:** All `[FILL]` tags replaced with actual data
11. **Table of Contents:** Navigation `<nav>` element present with anchor links to all sections
12. **Anchor IDs:** Every `<h2>` section heading has a matching `id` attribute (overview, component-mapping, threat-reconciliation, stride-distribution, gap-analysis, flow-mismatches, composite-model, critical-threats, methodology)
13. **Table cell readability:** `td` elements have `word-wrap: break-word` and `max-width: 400px` in CSS

If ANY check fails → FIX NOW before finalizing.

**Critical format rules baked into this skeleton:**
- HTML is self-contained (no external dependencies)
- All HTML markers are present and preserved
- CSS classes are lowercase with hyphens (never camelCase or spaces)
- STRIDE category names are canonical (no variants)
- Threat status badges use exact 6 values: Addressed, Mitigated, Open, NotApplicable, NotInCode, Deferred (classes: badge-addressed, badge-mitigated, badge-open, badge-notapplicable, badge-notincode, badge-deferred)
- Mapping status badges use DISTINCT classes: badge-confirmed, badge-pending, badge-unmappable, badge-external-only, badge-out-of-scope (these have bordered styling to visually distinguish from threat badges)
- Confidence visualization includes both numeric value and bar
- @media print styles ensure clean PDF export
- Table of Contents with anchor links is present at the top
- All section headings have id attributes for anchor navigation
- Table cells use word-wrap: break-word and max-width: 400px for readability
- Footer includes methodology description and related file references
- All sections are mandatory (no optional sections except empty state messages in table bodies)
