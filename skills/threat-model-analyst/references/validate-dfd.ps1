#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Deterministic post-write validator for `3.1-threatmodel.mmd` files
    produced by the threat-model-analyst skill.

.DESCRIPTION
    Enforces the skill's mandatory DFD conventions that a markdown
    self-attestation checklist cannot reliably enforce:

      1. Line 1 must start with `%%{init:`
      2. Init block must contain `'background': '#ffffff'`
      3. Diagram direction must be `flowchart LR` (never TB)
      4. classDef process / external / datastore lines must exist
      5. Every `:::process` node must use a circle    `(("Name"))`
         Every `:::external` node must use a rectangle `["Name"]`
         Every `:::datastore` node must use a cylinder `[("Name")]`
         Every `:::newComponent` / `:::removedComponent` node must use a circle
      6. No foreign palette colors (Chakra / Material) appear
      7. themeVariables must not contain `secondaryColor` / `tertiaryColor`

.PARAMETER Path
    Path to the `3.1-threatmodel.mmd` (or `3.2-threatmodel-summary.mmd`) file.

.OUTPUTS
    Exit code 0 on success, 1 on any violation. Errors are written to stderr.

.EXAMPLE
    pwsh -File references/validate-dfd.ps1 -Path .\threat-model-baseline-XYZ\3.1-threatmodel.mmd
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path
)

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Error "validate-dfd: file not found: $Path"
    exit 1
}

$content = Get-Content -LiteralPath $Path -Raw
$lines   = Get-Content -LiteralPath $Path
$errors  = New-Object System.Collections.Generic.List[string]

# ---- 1. Init block on line 1 ------------------------------------------------
if (-not $lines -or $lines[0] -notmatch '^\s*%%\{init:') {
    $first = if ($lines) { $lines[0] } else { '<empty>' }
    $errors.Add("Line 1 must start with '%%{init:' (got: '$first')")
}

# ---- 2. Required init background -------------------------------------------
if ($content -notmatch "'background'\s*:\s*'#ffffff'") {
    $errors.Add("Init block must contain `"'background': '#ffffff'`"")
}

# ---- 3. Diagram direction --------------------------------------------------
if ($content -match '(?m)^\s*flowchart\s+TB\b') {
    $errors.Add("Diagram uses 'flowchart TB' — must be 'flowchart LR'")
}
if ($content -notmatch '(?m)^\s*flowchart\s+LR\b') {
    $errors.Add("Diagram is missing the 'flowchart LR' declaration")
}

# ---- 4. Required classDef lines --------------------------------------------
foreach ($cd in @('process', 'external', 'datastore')) {
    if ($content -notmatch "(?m)^\s*classDef\s+$cd\b") {
        $errors.Add("Missing 'classDef $cd' line")
    }
}

# ---- 5. Per-node shape conformance -----------------------------------------
# Match the shape expression (or bare id) immediately preceding ':::<class>'.
# Order matters: cylinder + parallelogram are matched BEFORE rectangle so the
# alternation does not mis-classify them.
$pattern = '(?<shape>\(\([^()]+\)\)|\[\([^()]+\)\]|\[\/[^\]]+[\\\/]\]|\[[^\[\]]+\]|\([^()]+\)|\{\{[^}]+\}\}|\{[^}]+\}|[A-Za-z_][\w]*)\s*:::(?<class>process|external|datastore|newComponent|removedComponent)\b'
$matches = [regex]::Matches($content, $pattern)

foreach ($m in $matches) {
    $shape = $m.Groups['shape'].Value
    $class = $m.Groups['class'].Value

    # Classify the actual rendered shape.
    $kind =
        if     ($shape -match '^\(\(.+\)\)$')         { 'circle' }
        elseif ($shape -match '^\[\(.+\)\]$')         { 'cylinder' }
        elseif ($shape -match '^\[\/.+[\\\/]\]$')     { 'parallelogram' }
        elseif ($shape -match '^\[[^\(].*\]$')        { 'rectangle' }
        elseif ($shape -match '^\(.+\)$')             { 'round-rect' }
        elseif ($shape -match '^\{\{.+\}\}$')         { 'hexagon' }
        elseif ($shape -match '^\{.+\}$')             { 'rhombus' }
        else                                          { 'rectangle' }   # bare id renders as rectangle

    $expected = switch ($class) {
        'process'          { 'circle' }
        'external'         { 'rectangle' }
        'datastore'        { 'cylinder' }
        'newComponent'     { 'circle' }
        'removedComponent' { 'circle' }
    }

    if ($kind -ne $expected) {
        $errors.Add(
            "Wrong shape for :::$class -- got '$kind' from '$shape', expected '$expected'. " +
            'Use: process => ((Name)) (circle), external => [Name] (rectangle), datastore => [(Name)] (cylinder).'
        )
    }
}

# ---- 6. Disallowed palette colors ------------------------------------------
$badColors = @(
    '#4299E1', '#48BB78', '#E53E3E', '#2B6CB0',
    '#2D3748', '#2F855A', '#C53030'
)
foreach ($c in $badColors) {
    if ($content -match [regex]::Escape($c)) {
        $errors.Add(
            "Disallowed color '$c' present. Allowed fills: " +
            "#6baed6 #fdae61 #74c476 #ffffff #000000. Allowed strokes: " +
            "#2171b5 #d94701 #238b45 #e31a1c #666666."
        )
    }
}

# ---- 7. Forbidden themeVariables keys --------------------------------------
if ($content -match 'secondaryColor|tertiaryColor') {
    $errors.Add("themeVariables contains forbidden 'secondaryColor' or 'tertiaryColor'")
}

# ---- Result ----------------------------------------------------------------
if ($errors.Count -gt 0) {
    $body = ($errors | ForEach-Object { "  - $_" }) -join "`n"
    Write-Error "validate-dfd FAILED for $Path`n$body"
    exit 1
}

Write-Host "validate-dfd OK: $Path"
exit 0
