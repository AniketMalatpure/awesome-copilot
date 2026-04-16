<#
.SYNOPSIS
    Daily pattern library update script for the threat-model-analyst skill.
    Runs compile-patterns.py to ingest new/modified meeting transcripts and
    regenerate both public archetypes and internal knowledge files.

.DESCRIPTION
    - Scans MeetingSecurityInfo/ for new or modified transcripts
    - Runs the compilation pipeline in incremental mode
    - Updates internal-knowledge/ (always)
    - Flags archetype changes for human review (does not auto-publish)
    - Validates manifest health after run

.PARAMETER MeetingSource
    Path to the MeetingSecurityInfo directory. Defaults to the standard location.

.PARAMETER SkillRoot
    Path to the threat-model-analyst skill directory. Defaults to script location.

.PARAMETER Force
    Force full recompilation even if no new files detected.

.PARAMETER DryRun
    Show what would be processed without making changes.

.EXAMPLE
    .\update-patterns.ps1
    .\update-patterns.ps1 -Force
    .\update-patterns.ps1 -DryRun
#>

param(
    [string]$MeetingSource = "C:\Users\aniketm\Repo\ThreatModelAgent\MeetingSecurityInfo",
    [string]$SkillRoot = $PSScriptRoot,
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# Paths
$PipelineScript = Join-Path $SkillRoot "compile-patterns.py"
$InternalManifest = Join-Path $SkillRoot "internal-knowledge\internal-manifest.json"
$PatternsManifest = Join-Path $SkillRoot "references\security-patterns\patterns-manifest.json"
$LogDir = Join-Path $SkillRoot ".pattern-logs"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogFile = Join-Path $LogDir "update-$Timestamp.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "[$Timestamp] [$Level] $Message"
    Write-Host $entry
    if (-not $DryRun) {
        $entry | Out-File -Append -FilePath $LogFile -Encoding UTF8
    }
}

# Ensure log directory exists
if (-not $DryRun -and -not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Write-Log "=== Pattern Library Update Started ==="
Write-Log "Meeting source: $MeetingSource"
Write-Log "Skill root: $SkillRoot"

# Validate prerequisites
if (-not (Test-Path $PipelineScript)) {
    Write-Log "compile-patterns.py not found at $PipelineScript" "ERROR"
    exit 1
}

if (-not (Test-Path $MeetingSource)) {
    Write-Log "MeetingSecurityInfo directory not found at $MeetingSource" "ERROR"
    exit 1
}

# Count current source files
$sourceFiles = Get-ChildItem -Path $MeetingSource -Filter "*.md" -File
$sourceCount = $sourceFiles.Count
Write-Log "Source files found: $sourceCount"

# Check for new/modified files since last run
$newFileCount = 0
if (Test-Path $InternalManifest) {
    $manifest = Get-Content $InternalManifest -Raw | ConvertFrom-Json
    $lastRun = [DateTime]::Parse($manifest.generated_at)
    $newFiles = $sourceFiles | Where-Object { $_.LastWriteTime -gt $lastRun }
    $newFileCount = $newFiles.Count
    Write-Log "Files modified since last run ($($lastRun.ToString('yyyy-MM-dd HH:mm'))): $newFileCount"

    if ($newFileCount -eq 0 -and -not $Force) {
        Write-Log "No new files detected. Use -Force to recompile anyway."
        Write-Log "=== Update Complete (no changes) ==="
        exit 0
    }
} else {
    Write-Log "No existing manifest — running full compilation"
    $newFileCount = $sourceCount
}

if ($DryRun) {
    Write-Log "DRY RUN — would process $newFileCount new/modified files out of $sourceCount total" "INFO"
    Write-Log "=== Dry Run Complete ==="
    exit 0
}

# Snapshot pre-run archetype state for diff detection
$preRunArchetypes = @{}
$archetypesDir = Join-Path $SkillRoot "references\security-patterns\archetypes"
if (Test-Path $archetypesDir) {
    Get-ChildItem -Path $archetypesDir -Filter "*.md" | ForEach-Object {
        $preRunArchetypes[$_.Name] = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    }
}

# Run compilation pipeline
Write-Log "Running compile-patterns.py..."
$pythonCmd = "python `"$PipelineScript`""
try {
    $output = & python $PipelineScript 2>&1
    $exitCode = $LASTEXITCODE
    $output | Out-File -Append -FilePath $LogFile -Encoding UTF8
    if ($exitCode -ne 0) {
        Write-Log "Pipeline failed with exit code $exitCode" "ERROR"
        Write-Log ($output -join "`n") "ERROR"
        exit 1
    }
    Write-Log "Pipeline completed successfully"
} catch {
    Write-Log "Pipeline execution error: $_" "ERROR"
    exit 1
}

# Validate post-run health
Write-Log "Validating manifest health..."

if (-not (Test-Path $InternalManifest)) {
    Write-Log "Internal manifest not generated!" "ERROR"
    exit 1
}

$manifest = Get-Content $InternalManifest -Raw | ConvertFrom-Json
$checks = @()

# Check schema version
if ($manifest.schema_version -ne "1.0") {
    $checks += "Schema version mismatch: $($manifest.schema_version)"
}

# Check status
if ($manifest.status -ne "complete") {
    $checks += "Status is not complete: $($manifest.status)"
}

# Check source count
$actualCount = (Get-ChildItem -Path (Join-Path $SkillRoot "internal-knowledge\systems") -Filter "*.json" -File).Count
if ($manifest.source_count -ne $actualCount) {
    $checks += "Source count mismatch: manifest=$($manifest.source_count), actual=$actualCount"
}

# Check freshness (should be within last 5 minutes)
$genTime = [DateTime]::Parse($manifest.generated_at)
$age = (Get-Date) - $genTime
if ($age.TotalMinutes -gt 5) {
    $checks += "Manifest timestamp too old: $($manifest.generated_at)"
}

if ($checks.Count -gt 0) {
    Write-Log "Health check warnings:" "WARN"
    $checks | ForEach-Object { Write-Log "  - $_" "WARN" }
} else {
    Write-Log "All health checks passed"
}

# Detect archetype changes for review
$archetypeChanges = @()
if (Test-Path $archetypesDir) {
    Get-ChildItem -Path $archetypesDir -Filter "*.md" | ForEach-Object {
        $newHash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        if ($preRunArchetypes.ContainsKey($_.Name)) {
            if ($preRunArchetypes[$_.Name] -ne $newHash) {
                $archetypeChanges += "MODIFIED: $($_.Name)"
            }
        } else {
            $archetypeChanges += "NEW: $($_.Name)"
        }
    }
}

if ($archetypeChanges.Count -gt 0) {
    Write-Log "⚠️  Archetype changes detected (requires human review before publishing):" "WARN"
    $archetypeChanges | ForEach-Object { Write-Log "  $_" "WARN" }
    Write-Log "Review changes in $archetypesDir and commit when approved."
} else {
    Write-Log "No archetype changes detected"
}

# Summary
Write-Log "=== Update Summary ==="
Write-Log "  Source files: $sourceCount"
Write-Log "  New/modified: $newFileCount"
Write-Log "  Internal systems generated: $actualCount"
Write-Log "  Archetype changes: $($archetypeChanges.Count)"
Write-Log "  Health issues: $($checks.Count)"
Write-Log "  Log: $LogFile"
Write-Log "=== Pattern Library Update Complete ==="
