<#
.SYNOPSIS
    Parses a Microsoft Threat Modeling Tool .tm7 file, evaluates STRIDE threat generation
    rules from its embedded KnowledgeBase, and produces an HTML threat report.

.DESCRIPTION
    Implements all 8 phases from tm7-threat-generation.md:
      Phase 1 - Parse TM7 XML (elements, flows, boundaries)
      Phase 2 - Build Type Hierarchy from KnowledgeBase
      Phase 3 - Build Element Registry
      Phase 4 - Build Boundary Containment Map
      Phase 5 - Enumerate Interaction Triples
      Phase 6 - Extract & Parse Threat Generation Rules
      Phase 7 - Generate Threats (evaluate Include/Exclude filters)
      Phase 8 - Gap Analysis (compare with existing ThreatInstances)

    XML Namespace Mapping (WCF DataContract serialization):
      abs: = http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts
             Used for element identity/geometry: Guid, TypeId, GenericTypeId, Properties,
             Left, Top, Width, Height, SourceGuid, TargetGuid, SourceX/Y, TargetX/Y
      kb:  = http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase
             Used for KB types (ElementType, ThreatType, ThreatCategory fields: Id, Name,
             ParentId, Category, ShortTitle, Description, GenerationFilters, Include, Exclude)
             AND property children (Name, DisplayName, Value, SelectedIndex)
             AND ThreatInstance value children (FlowGuid, InteractionKey, State, Priority, Id)
      arr: = http://schemas.microsoft.com/2003/10/Serialization/Arrays
             Used for containers: KeyValueOfguidanyType, KeyValueOfstringstring, string arrays
      m:   = http://schemas.datacontract.org/2004/07/ThreatModeling.Model
             Used for top-level structure: ThreatModel, DrawingSurfaceList, ThreatInstances, KnowledgeBase

.PARAMETER TM7Path
    Path to the .tm7 file to analyze.

.PARAMETER TB7Path
    Optional path to an external .tb7 template file.

.PARAMETER OutputDir
    Directory where the HTML report and JSON data will be written.

.EXAMPLE
    .\Invoke-TM7ThreatAnalysis.ps1 -TM7Path "Simple Threat Model_https.tm7" -OutputDir ".\report"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$TM7Path,

    [Parameter()]
    [string]$TB7Path,

    [Parameter(Mandatory)]
    [string]$OutputDir,

    [Parameter()]
    [string]$SurfaceFilter
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Namespace Manager ───────────────────────────────────────────────────────
function New-NsMgr {
    param([xml]$Doc)
    $nsMgr = New-Object System.Xml.XmlNamespaceManager($Doc.NameTable)
    $nsMgr.AddNamespace('m',   'http://schemas.datacontract.org/2004/07/ThreatModeling.Model')
    $nsMgr.AddNamespace('abs', 'http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts')
    $nsMgr.AddNamespace('kb',  'http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase')
    $nsMgr.AddNamespace('arr', 'http://schemas.microsoft.com/2003/10/Serialization/Arrays')
    $nsMgr.AddNamespace('i',   'http://www.w3.org/2001/XMLSchema-instance')
    # Comma prevents PowerShell from enumerating XmlNamespaceManager (IEnumerable)
    return ,$nsMgr
}

# ─── Helper: safe XPath node text ────────────────────────────────────────────
function Get-NodeText {
    param([System.Xml.XmlElement]$Parent, [string]$XPath, [System.Xml.XmlNamespaceManager]$NsMgr)
    $node = $Parent.SelectSingleNode($XPath, $NsMgr)
    if ($node) { return $node.InnerText }
    return $null
}

# ─── Phase 2: Type Hierarchy ─────────────────────────────────────────────────
function Build-TypeHierarchy {
    param([System.Xml.XmlElement]$KBNode, [System.Xml.XmlNamespaceManager]$NsMgr)

    $hierarchy = @{}
    $hierarchy['ROOT'] = @{ Id = 'ROOT'; Name = 'ROOT'; ParentId = $null; Children = [System.Collections.ArrayList]::new() }

    $elements = $KBNode.SelectNodes('.//kb:ElementType', $NsMgr)
    foreach ($el in $elements) {
        $id       = Get-NodeText $el 'kb:Id' $NsMgr
        $name     = Get-NodeText $el 'kb:Name' $NsMgr
        $parentId = Get-NodeText $el 'kb:ParentId' $NsMgr
        if (-not $id) { continue }
        $hierarchy[$id] = @{
            Id       = $id
            Name     = $name
            ParentId = if ($parentId) { $parentId } else { 'ROOT' }
            Children = [System.Collections.ArrayList]::new()
        }
    }

    # Wire parent -> children
    foreach ($kv in @($hierarchy.GetEnumerator())) {
        $node = $kv.Value
        $pId2 = $node.ParentId
        if ($pId2 -and $pId2 -ne $node.Id -and $hierarchy.ContainsKey($pId2)) {
            [void]$hierarchy[$pId2].Children.Add($node.Id)
        }
    }

    return $hierarchy
}

function Test-TypeMatch {
    param(
        [string]$ElementTypeId,
        [string]$FilterTypeId,
        [hashtable]$Hierarchy
    )
    if ($FilterTypeId -eq 'ROOT') { return $true }
    if ($ElementTypeId -eq $FilterTypeId) { return $true }

    $current = $ElementTypeId
    $visited = @{}
    while ($current -and $Hierarchy.ContainsKey($current) -and -not $visited.ContainsKey($current)) {
        $visited[$current] = $true
        $parent = $Hierarchy[$current].ParentId
        if ($parent -eq $FilterTypeId) { return $true }
        $current = $parent
    }
    return $false
}

# ─── Phase 1 & 3: Parse Elements, Flows, Boundaries ─────────────────────────
function Read-Properties {
    <#
    .SYNOPSIS  Read element/flow properties into a hashtable.
    Property children (Name, DisplayName, Value, SelectedIndex) are in kb: namespace.
    List value strings are in arr: namespace.
    #>
    param([System.Xml.XmlElement]$PropsNode, [System.Xml.XmlNamespaceManager]$NsMgr)

    $props = @{}
    if (-not $PropsNode) { return $props }

    foreach ($child in $PropsNode.ChildNodes) {
        $itype = $child.GetAttribute('type', 'http://www.w3.org/2001/XMLSchema-instance')
        $propName = Get-NodeText $child 'kb:Name' $NsMgr
        $dispName = Get-NodeText $child 'kb:DisplayName' $NsMgr

        $value = $null
        if ($itype -match 'ListDisplayAttribute') {
            $selIdx = Get-NodeText $child 'kb:SelectedIndex' $NsMgr
            $valNode = $child.SelectSingleNode('kb:Value', $NsMgr)
            $strings = @()
            if ($valNode) {
                $strings = @($valNode.SelectNodes('arr:string', $NsMgr) | ForEach-Object { $_.InnerText })
            }
            if ($null -ne $selIdx -and $strings.Count -gt 0) {
                $idx = [int]$selIdx
                if ($idx -ge 0 -and $idx -lt $strings.Count) {
                    $value = $strings[$idx]
                }
            }
        }
        elseif ($itype -match 'StringDisplayAttribute') {
            $value = Get-NodeText $child 'kb:Value' $NsMgr
        }
        elseif ($itype -match 'BooleanDisplayAttribute') {
            $value = Get-NodeText $child 'kb:Value' $NsMgr
        }
        elseif ($itype -match 'HeaderDisplayAttribute') {
            continue  # Section header only, no value
        }

        if ($propName -and $null -ne $value) {
            $props[$propName] = $value
        }
        if ($dispName -and $null -ne $value) {
            $props[$dispName] = $value
        }
    }
    return $props
}

function Get-ElementName {
    <# Extract element name from its Properties.
       Priority: 1) StringDisplayAttribute where DisplayName="Name" (actual element name)
                 2) HeaderDisplayAttribute DisplayName (KB type label - last resort) #>
    param([System.Xml.XmlElement]$PropsNode, [System.Xml.XmlNamespaceManager]$NsMgr)

    if (-not $PropsNode) { return $null }

    # Primary: StringDisplayAttribute where DisplayName = "Name" — this is the actual element name
    foreach ($p in $PropsNode.ChildNodes) {
        $pit = $p.GetAttribute('type', 'http://www.w3.org/2001/XMLSchema-instance')
        if ($pit -match 'StringDisplayAttribute') {
            $dn = Get-NodeText $p 'kb:DisplayName' $NsMgr
            if ($dn -eq 'Name') {
                $val = Get-NodeText $p 'kb:Value' $NsMgr
                if ($val) { return $val }
            }
        }
    }
    # Fallback: first HeaderDisplayAttribute DisplayName (KB type display name)
    foreach ($p in $PropsNode.ChildNodes) {
        $pit = $p.GetAttribute('type', 'http://www.w3.org/2001/XMLSchema-instance')
        if ($pit -match 'HeaderDisplayAttribute') {
            $dn = Get-NodeText $p 'kb:DisplayName' $NsMgr
            if ($dn) { return $dn }
        }
    }
    return $null
}

function Parse-TM7 {
    param([xml]$Doc, [System.Xml.XmlNamespaceManager]$NsMgr, [string]$SurfaceFilter)

    $elements       = @{}
    $flows          = @{}
    $lineBounds     = @{}
    $borderBounds   = @{}
    $annotations    = @{}  # GE.A free text annotations
    $danglingFlows  = [System.Collections.ArrayList]::new()  # Flows with unconnected ends
    $existingThreats = @{}
    $guidRemap      = @{}  # Maps duplicate element GUIDs to their canonical GUID

    # ── Iterate drawing surfaces ────────────────────────────────────────────
    $surfaces = $Doc.SelectNodes('//m:DrawingSurfaceModel', $NsMgr)
    $matchedSurfaceGuids = @()
    foreach ($surface in $surfaces) {
        $surfaceHeader = Get-NodeText $surface 'm:Header' $NsMgr
        $surfaceGuid   = Get-NodeText $surface 'm:Guid' $NsMgr
        if (-not $surfaceGuid) { $surfaceGuid = $surfaceHeader ?? 'unknown' }

        # Surface filter: skip surfaces that don't match the filter (wildcard match)
        if ($SurfaceFilter -and $surfaceHeader -notlike "*$SurfaceFilter*") {
            Write-Host "  Skipping surface: $surfaceHeader (filter: $SurfaceFilter)" -ForegroundColor DarkGray
            continue
        }
        $matchedSurfaceGuids += $surfaceGuid

        # ── Borders (elements + border boundaries) ──────────────────────────
        $borderItems = $surface.SelectNodes('.//m:Borders/arr:KeyValueOfguidanyType', $NsMgr)
        foreach ($item in $borderItems) {
            $key   = Get-NodeText $item 'arr:Key' $NsMgr
            $val   = $item.SelectSingleNode('arr:Value', $NsMgr)
            if (-not $key -or -not $val) { continue }

            $itype      = $val.GetAttribute('type', 'http://www.w3.org/2001/XMLSchema-instance')
            $guid       = Get-NodeText $val 'abs:Guid' $NsMgr
            $genTypeId  = Get-NodeText $val 'abs:GenericTypeId' $NsMgr
            $typeId     = Get-NodeText $val 'abs:TypeId' $NsMgr
            $left       = [double]((Get-NodeText $val 'abs:Left' $NsMgr) ?? '0')
            $top        = [double]((Get-NodeText $val 'abs:Top' $NsMgr) ?? '0')
            $width      = [double]((Get-NodeText $val 'abs:Width' $NsMgr) ?? '0')
            $height     = [double]((Get-NodeText $val 'abs:Height' $NsMgr) ?? '0')

            $propsNode = $val.SelectSingleNode('abs:Properties', $NsMgr)
            $props     = Read-Properties -PropsNode $propsNode -NsMgr $NsMgr
            $nameVal   = Get-ElementName -PropsNode $propsNode -NsMgr $NsMgr

            if ($itype -match 'BorderBoundary') {
                $borderBounds[$guid] = @{
                    Guid          = $guid
                    GenericTypeId = $genTypeId
                    TypeId        = $typeId
                    Name          = $nameVal ?? "Boundary-$guid"
                    Left          = $left
                    Top           = $top
                    Width         = $width
                    Height        = $height
                    Properties    = $props
                    Surface       = $surfaceGuid
                }
            }
            elseif ($genTypeId -eq 'GE.A') {
                # Collect annotations (GE.A) — they're not threat-modeled but useful context
                $annotations[$guid] = @{
                    Guid     = $guid
                    Name     = $nameVal ?? "Annotation-$guid"
                    Surface  = $surfaceGuid
                    Position = @{ Left = $left; Top = $top; Width = $width; Height = $height }
                }
            }
            else {
                # Regular element (Process, Data Store, External Interactor)
                $oos = $false
                if ($props.ContainsKey('Out Of Scope')) { $oos = $props['Out Of Scope'] -eq 'true' }
                if ($props.ContainsKey('71f3d9aa-7ec2-4eeb-a0e3-a85f3aa3aaae')) {
                    $oos = $props['71f3d9aa-7ec2-4eeb-a0e3-a85f3aa3aaae'] -eq 'true'
                }

                # Dedup across surfaces by TypeId+Name
                $dedup = "$($typeId)::$($nameVal)"
                $existing = $elements.Values | Where-Object {
                    "$($_.TypeId)::$($_.Name)" -eq $dedup
                } | Select-Object -First 1

                if ($existing) {
                    if (-not $existing.Surfaces) { $existing.Surfaces = @($existing.Surface) }
                    $existing.Surfaces += $surfaceGuid
                    # Map duplicate GUID to canonical GUID for flow lookups
                    $guidRemap[$guid] = $existing.Guid
                }
                else {
                    $elements[$guid] = @{
                        Guid          = $guid
                        GenericTypeId = $genTypeId
                        TypeId        = $typeId
                        Name          = $nameVal ?? "Element-$guid"
                        Properties    = $props
                        Position      = @{ Left = $left; Top = $top; Width = $width; Height = $height }
                        OutOfScope    = $oos
                        Surface       = $surfaceGuid
                        Surfaces      = @($surfaceGuid)
                    }
                }
            }
        }

        # ── Lines (flows + line boundaries) ─────────────────────────────────
        $lineItems = $surface.SelectNodes('.//m:Lines/arr:KeyValueOfguidanyType', $NsMgr)
        foreach ($item in $lineItems) {
            $key  = Get-NodeText $item 'arr:Key' $NsMgr
            $val  = $item.SelectSingleNode('arr:Value', $NsMgr)
            if (-not $key -or -not $val) { continue }

            $itype     = $val.GetAttribute('type', 'http://www.w3.org/2001/XMLSchema-instance')
            $guid      = Get-NodeText $val 'abs:Guid' $NsMgr
            $genTypeId = Get-NodeText $val 'abs:GenericTypeId' $NsMgr
            $typeId    = Get-NodeText $val 'abs:TypeId' $NsMgr
            $srcGuid   = Get-NodeText $val 'abs:SourceGuid' $NsMgr
            $tgtGuid   = Get-NodeText $val 'abs:TargetGuid' $NsMgr
            $srcX      = [double]((Get-NodeText $val 'abs:SourceX' $NsMgr) ?? '0')
            $srcY      = [double]((Get-NodeText $val 'abs:SourceY' $NsMgr) ?? '0')
            $tgtX      = [double]((Get-NodeText $val 'abs:TargetX' $NsMgr) ?? '0')
            $tgtY      = [double]((Get-NodeText $val 'abs:TargetY' $NsMgr) ?? '0')
            $handleX   = [double]((Get-NodeText $val 'abs:HandleX' $NsMgr) ?? '0')
            $handleY   = [double]((Get-NodeText $val 'abs:HandleY' $NsMgr) ?? '0')

            $propsNode = $val.SelectSingleNode('abs:Properties', $NsMgr)
            $props     = Read-Properties -PropsNode $propsNode -NsMgr $NsMgr
            $nameVal   = Get-ElementName -PropsNode $propsNode -NsMgr $NsMgr

            $zeroGuid = '00000000-0000-0000-0000-000000000000'

            if ($itype -match 'LineBoundary' -or $genTypeId -eq 'GE.TB.L' -or ($typeId -and $typeId.StartsWith('SE.TB.L'))) {
                $lineBounds[$guid] = @{
                    Guid          = $guid
                    GenericTypeId = $genTypeId
                    TypeId        = $typeId
                    Name          = $nameVal ?? "LineBoundary-$guid"
                    SourceX       = $srcX
                    SourceY       = $srcY
                    TargetX       = $tgtX
                    TargetY       = $tgtY
                    Properties    = $props
                    Surface       = $surfaceGuid
                }
            }
            elseif ($srcGuid -ne $zeroGuid -and $tgtGuid -ne $zeroGuid -and $genTypeId -eq 'GE.DF') {
                # Remap source/target GUIDs to canonical element GUIDs
                $canonSrc = if ($guidRemap.ContainsKey($srcGuid)) { $guidRemap[$srcGuid] } else { $srcGuid }
                $canonTgt = if ($guidRemap.ContainsKey($tgtGuid)) { $guidRemap[$tgtGuid] } else { $tgtGuid }
                $flows[$guid] = @{
                    Guid               = $guid
                    GenericTypeId      = $genTypeId
                    TypeId             = $typeId
                    Name               = $nameVal ?? "Flow-$guid"
                    SourceGuid         = $canonSrc
                    TargetGuid         = $canonTgt
                    OriginalSourceGuid = $srcGuid   # Pre-remap GUID (for matchKey)
                    OriginalTargetGuid = $tgtGuid   # Pre-remap GUID (for matchKey)
                    SourceX            = $srcX
                    SourceY            = $srcY
                    TargetX            = $tgtX
                    TargetY            = $tgtY
                    Properties         = $props
                    Surface            = $surfaceGuid
                }
            }
            elseif ($genTypeId -eq 'GE.DF' -and ($srcGuid -eq $zeroGuid -or $tgtGuid -eq $zeroGuid)) {
                # Dangling flow — one or both ends not connected to an element
                $srcName = '(not connected)'
                $tgtName = '(not connected)'
                if ($srcGuid -ne $zeroGuid) {
                    $srcEl = $elements[$srcGuid]
                    if (-not $srcEl -and $guidRemap.ContainsKey($srcGuid)) { $srcEl = $elements[$guidRemap[$srcGuid]] }
                    if (-not $srcEl) { $srcEl = $annotations[$srcGuid] }
                    if ($srcEl) { $srcName = $srcEl.Name }
                }
                if ($tgtGuid -ne $zeroGuid) {
                    $tgtEl = $elements[$tgtGuid]
                    if (-not $tgtEl -and $guidRemap.ContainsKey($tgtGuid)) { $tgtEl = $elements[$guidRemap[$tgtGuid]] }
                    if (-not $tgtEl) { $tgtEl = $annotations[$tgtGuid] }
                    if ($tgtEl) { $tgtName = $tgtEl.Name }
                }
                [void]$danglingFlows.Add(@{
                    Name       = $nameVal ?? "Flow-$guid"
                    TypeId     = $typeId
                    SourceName = $srcName
                    TargetName = $tgtName
                    SourceDangling = ($srcGuid -eq $zeroGuid)
                    TargetDangling = ($tgtGuid -eq $zeroGuid)
                    Surface    = $surfaceGuid
                })
            }
        }
    }

    # ── Existing Threats ────────────────────────────────────────────────────
    $threatNodes = $Doc.SelectNodes('//m:ThreatInstances/arr:KeyValueOfstringThreatpc_P0_PhOB', $NsMgr)
    foreach ($tn in $threatNodes) {
        $tKey   = Get-NodeText $tn 'arr:Key' $NsMgr
        $tVal   = $tn.SelectSingleNode('arr:Value', $NsMgr)
        if (-not $tKey -or -not $tVal) { continue }

        # ThreatInstance value children are in kb: namespace
        $flowGuid = Get-NodeText $tVal 'kb:FlowGuid' $NsMgr
        $intKey   = Get-NodeText $tVal 'kb:InteractionKey' $NsMgr
        $state    = Get-NodeText $tVal 'kb:State' $NsMgr
        $priority = Get-NodeText $tVal 'kb:Priority' $NsMgr
        $tid      = Get-NodeText $tVal 'kb:Id' $NsMgr
        $title    = Get-NodeText $tVal 'kb:Title' $NsMgr

        # Extract threat properties (arr:KeyValueOfstringstring with arr:Key / arr:Value)
        $tProps = @{}
        $tPropsNode = $tVal.SelectSingleNode('kb:Properties', $NsMgr)
        if ($tPropsNode) {
            foreach ($kv in $tPropsNode.SelectNodes('arr:KeyValueOfstringstring', $NsMgr)) {
                $pk = Get-NodeText $kv 'arr:Key' $NsMgr
                $pv = Get-NodeText $kv 'arr:Value' $NsMgr
                if ($pk) { $tProps[$pk] = $pv }
            }
        }

        # Title from properties if not directly available
        $threatTitle = $tProps['Title'] ?? $title ?? ''

        $existingThreats[$tKey] = @{
            Key             = $tKey
            FlowGuid        = $flowGuid
            InteractionKey  = $intKey
            State           = $state
            Priority        = $priority
            Id              = $tid
            Title           = $threatTitle
            Category        = $tProps['UserThreatCategory'] ?? ''
            Description     = $tProps['UserThreatDescription'] ?? ''
            Properties      = $tProps
        }
    }

    # If surface filter is active, keep only existing threats whose FlowGuid is in parsed flows
    if ($SurfaceFilter -and $flows.Count -gt 0) {
        $flowGuids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($fk in $flows.Keys) { [void]$flowGuids.Add($fk) }
        $filteredThreats = @{}
        foreach ($tk in $existingThreats.Keys) {
            $et = $existingThreats[$tk]
            if ($et.FlowGuid -and $flowGuids.Contains($et.FlowGuid)) {
                $filteredThreats[$tk] = $et
            }
        }
        $existingThreats = $filteredThreats
        Write-Host "  Existing threats filtered to surface: $($existingThreats.Count)" -ForegroundColor Green
    }

    # ── Notes ───────────────────────────────────────────────────────────────
    $notes = [System.Collections.ArrayList]::new()
    $noteNodes = $Doc.SelectNodes('//m:Note', $NsMgr)
    foreach ($nn in $noteNodes) {
        $noteId   = Get-NodeText $nn 'm:Id' $NsMgr
        $noteMsg  = Get-NodeText $nn 'm:Message' $NsMgr
        $noteBy   = Get-NodeText $nn 'm:AddedBy' $NsMgr
        if ($noteMsg) {
            [void]$notes.Add(@{ Id = $noteId; Message = $noteMsg; AddedBy = $noteBy })
        }
    }

    # ── Detect annotations with flows (misrepresented components) ──
    $annotationsWithFlows = @{}
    foreach ($ak in $annotations.Keys) {
        $ann = $annotations[$ak]
        $connectedFlows = @()
        foreach ($fl in $flows.Values) {
            if ($fl.SourceGuid -eq $ak -or $fl.TargetGuid -eq $ak) {
                $dir = if ($fl.SourceGuid -eq $ak) { 'from' } else { 'to' }
                $connectedFlows += @{ FlowName = $fl.Name; Direction = $dir; FlowGuid = $fl.Guid }
            }
        }
        if ($connectedFlows.Count -gt 0) {
            $annotationsWithFlows[$ak] = @{
                Name  = $ann.Name
                Flows = $connectedFlows
            }
        }
    }

    return @{
        Elements        = $elements
        Flows           = $flows
        LineBoundaries  = $lineBounds
        BorderBounds    = $borderBounds
        Annotations     = $annotations
        AnnotationsWithFlows = $annotationsWithFlows
        DanglingFlows   = $danglingFlows.ToArray()
        ExistingThreats = $existingThreats
        MatchedSurfaces = $matchedSurfaceGuids
        Notes           = $notes.ToArray()
    }
}

# ─── Phase 4: Boundary Containment / Crossing Map ────────────────────────────
function Build-BoundaryCrossingMap {
    param(
        [hashtable]$Elements,
        [hashtable]$Flows,
        [hashtable]$LineBounds,
        [hashtable]$BorderBounds,
        [hashtable]$Hierarchy
    )

    $crossingMap = @{}

    foreach ($flow in $Flows.Values) {
        $crossings = [System.Collections.ArrayList]::new()
        $srcEl = $Elements[$flow.SourceGuid]
        $tgtEl = $Elements[$flow.TargetGuid]
        if (-not $srcEl -or -not $tgtEl) {
            $crossingMap[$flow.Guid] = @()
            continue
        }

        # Use flow endpoint coordinates (surface-local) instead of canonical element
        # centers, because canonical elements may have positions from a different surface.
        $srcCX = $flow.SourceX
        $srcCY = $flow.SourceY
        $tgtCX = $flow.TargetX
        $tgtCY = $flow.TargetY

        # ── Border boundaries (same surface only) ───────────────────────────
        foreach ($bound in $BorderBounds.Values) {
            if ($bound.Surface -ne $flow.Surface) { continue }
            $rectL = $bound['Left']; $rectT = $bound['Top']
            $rectR = $bound['Left'] + $bound['Width']; $rectBot = $bound['Top'] + $bound['Height']

            $srcInside = ($srcCX -ge $rectL -and $srcCX -le $rectR -and $srcCY -ge $rectT -and $srcCY -le $rectBot)
            $tgtInside = ($tgtCX -ge $rectL -and $tgtCX -le $rectR -and $tgtCY -ge $rectT -and $tgtCY -le $rectBot)

            if ($srcInside -xor $tgtInside) {
                [void]$crossings.Add(@{
                    BoundaryGuid          = $bound['Guid']
                    BoundaryTypeId        = $bound['TypeId']
                    BoundaryGenericTypeId = $bound['GenericTypeId']
                    BoundaryName          = $bound['Name']
                })
            }
        }

        # ── Line boundaries (segment intersection) ──────────────────────────
        foreach ($lb in $LineBounds.Values) {
            if ($lb.Surface -ne $flow.Surface) { continue }

            if (Test-SegmentsIntersect `
                    -Ax1 $srcCX -Ay1 $srcCY -Ax2 $tgtCX -Ay2 $tgtCY `
                    -Bx1 $lb.SourceX -By1 $lb.SourceY -Bx2 $lb.TargetX -By2 $lb.TargetY) {
                [void]$crossings.Add(@{
                    BoundaryGuid          = $lb.Guid
                    BoundaryTypeId        = $lb.TypeId
                    BoundaryGenericTypeId = $lb.GenericTypeId
                    BoundaryName          = $lb.Name
                })
            }
        }

        $crossingMap[$flow.Guid] = $crossings.ToArray()
    }

    return $crossingMap
}

function Test-SegmentsIntersect {
    param(
        [double]$Ax1, [double]$Ay1, [double]$Ax2, [double]$Ay2,
        [double]$Bx1, [double]$By1, [double]$Bx2, [double]$By2
    )
    $d1x = $Ax2 - $Ax1; $d1y = $Ay2 - $Ay1
    $d2x = $Bx2 - $Bx1; $d2y = $By2 - $By1

    $cross = $d1x * $d2y - $d1y * $d2x
    if ([Math]::Abs($cross) -lt 1e-10) { return $false }

    $dx = $Bx1 - $Ax1; $dy = $By1 - $Ay1
    $t = ($dx * $d2y - $dy * $d2x) / $cross
    $u = ($dx * $d1y - $dy * $d1x) / $cross

    return ($t -ge 0 -and $t -le 1 -and $u -ge 0 -and $u -le 1)
}

# ─── Phase 5: Interaction Triples ────────────────────────────────────────────
function Build-InteractionTriples {
    param(
        [hashtable]$Elements,
        [hashtable]$Flows,
        [hashtable]$CrossingMap
    )

    $interactions = [System.Collections.ArrayList]::new()
    $seen = @{}

    foreach ($flow in $Flows.Values) {
        $src = $Elements[$flow.SourceGuid]
        $tgt = $Elements[$flow.TargetGuid]
        if (-not $src -or -not $tgt) { continue }
        # NOTE: Do NOT skip OutOfScope elements here. TMT generates threats for
        # OOS interactions (state=AutoGenerated) — OOS is a reporting flag only.

        # TMT evaluates rules per-flow, not per-unique-pair. Each flow is a
        # separate interaction even if source/target are the same element pair.
        # Dedup only by flow GUID to match TMT behavior.
        $dedupKey = $flow.Guid
        if ($seen.ContainsKey($dedupKey)) { continue }
        $seen[$dedupKey] = $true

        $crossings = $CrossingMap[$flow.Guid] ?? @()

        [void]$interactions.Add(@{
            Source    = $src
            Flow      = $flow
            Target    = $tgt
            Crossings = $crossings
        })
    }

    return $interactions.ToArray()
}

# ─── Phase 6: Filter Expression DSL Parser & Evaluator ──────────────────────
class TokenStream {
    [string[]]$Tokens
    [int]$Pos = 0

    TokenStream([string[]]$tokens) { $this.Tokens = $tokens }

    [string] Peek() {
        if ($this.Pos -ge $this.Tokens.Count) { return $null }
        return $this.Tokens[$this.Pos]
    }

    [string] Consume() {
        $tok = $this.Peek()
        $this.Pos++
        return $tok
    }

    [bool] Match([string]$expected) {
        if ($this.Peek() -eq $expected) { $this.Pos++; return $true }
        return $false
    }
}

function Tokenize-Filter {
    param([string]$Expr)
    if (-not $Expr -or $Expr.Trim() -eq '') { return @() }

    $tokens = [System.Collections.ArrayList]::new()
    $i = 0
    $s = $Expr.Trim()

    while ($i -lt $s.Length) {
        if ($s[$i] -match '\s') { $i++; continue }
        if ($s[$i] -eq '(') { [void]$tokens.Add('('); $i++; continue }
        if ($s[$i] -eq ')') { [void]$tokens.Add(')'); $i++; continue }
        if ($s[$i] -eq "'") {
            $j = $s.IndexOf("'", $i + 1)
            if ($j -lt 0) { $j = $s.Length }
            [void]$tokens.Add($s.Substring($i + 1, $j - $i - 1))
            $i = $j + 1
            continue
        }
        $m = [regex]::Match($s.Substring($i), '^[a-zA-Z0-9_.\-]+')
        if ($m.Success) {
            [void]$tokens.Add($m.Value)
            $i += $m.Length
            continue
        }
        $i++
    }

    return $tokens.ToArray()
}

function Parse-Expression {
    param([TokenStream]$Stream)
    return Parse-OrExpr -Stream $Stream
}

function Parse-OrExpr {
    param([TokenStream]$Stream)
    $left = Parse-AndExpr -Stream $Stream
    while ($Stream.Peek() -eq 'or') {
        [void]$Stream.Consume()
        $right = Parse-AndExpr -Stream $Stream
        $left = @{ Op = 'or'; Left = $left; Right = $right }
    }
    return $left
}

function Parse-AndExpr {
    param([TokenStream]$Stream)
    $left = Parse-NotExpr -Stream $Stream
    while ($Stream.Peek() -eq 'and') {
        [void]$Stream.Consume()
        $right = Parse-NotExpr -Stream $Stream
        $left = @{ Op = 'and'; Left = $left; Right = $right }
    }
    return $left
}

function Parse-NotExpr {
    param([TokenStream]$Stream)
    if ($Stream.Peek() -eq 'not') {
        [void]$Stream.Consume()
        $inner = Parse-Atom -Stream $Stream
        return @{ Op = 'not'; Inner = $inner }
    }
    return Parse-Atom -Stream $Stream
}

function Parse-Atom {
    param([TokenStream]$Stream)
    if ($Stream.Peek() -eq '(') {
        [void]$Stream.Consume()
        $inner = Parse-Expression -Stream $Stream
        if ($Stream.Peek() -eq ')') { [void]$Stream.Consume() }
        return $inner
    }
    return Parse-Predicate -Stream $Stream
}

function Parse-Predicate {
    param([TokenStream]$Stream)

    $subject = $Stream.Consume()  # source / target / flow
    $next    = $Stream.Peek()

    if ($next -eq 'crosses') {
        [void]$Stream.Consume()
        $boundaryTypeId = $Stream.Consume()
        return @{ Op = 'crosses'; BoundaryTypeId = $boundaryTypeId }
    }
    elseif ($subject -and $subject.Contains('.') -and $next -eq 'is') {
        # source.attr is 'Value' — attribute check (must be before plain type check)
        $dotIdx     = $subject.IndexOf('.')
        $realSubj   = $subject.Substring(0, $dotIdx)
        $attrName   = $subject.Substring($dotIdx + 1)
        [void]$Stream.Consume()  # consume 'is'
        $val = $Stream.Consume()
        return @{ Op = 'attrCheck'; Subject = $realSubj; Attribute = $attrName; Value = $val }
    }
    elseif ($next -eq 'is') {
        [void]$Stream.Consume()
        $typeId = $Stream.Consume()
        return @{ Op = 'typeCheck'; Subject = $subject; TypeId = $typeId }
    }
    else {
        return @{ Op = 'literal'; Value = $true }
    }
}

function Evaluate-AST {
    param(
        [hashtable]$Node,
        [hashtable]$Interaction,
        [hashtable]$Hierarchy
    )

    switch ($Node.Op) {
        'and' {
            $l = Evaluate-AST -Node $Node.Left -Interaction $Interaction -Hierarchy $Hierarchy
            if (-not $l) { return $false }
            return (Evaluate-AST -Node $Node.Right -Interaction $Interaction -Hierarchy $Hierarchy)
        }
        'or' {
            $l = Evaluate-AST -Node $Node.Left -Interaction $Interaction -Hierarchy $Hierarchy
            if ($l) { return $true }
            return (Evaluate-AST -Node $Node.Right -Interaction $Interaction -Hierarchy $Hierarchy)
        }
        'not' {
            return -not (Evaluate-AST -Node $Node.Inner -Interaction $Interaction -Hierarchy $Hierarchy)
        }
        'typeCheck' {
            $el = switch ($Node.Subject) {
                'source' { $Interaction.Source }
                'target' { $Interaction.Target }
                'flow'   { $Interaction.Flow }
            }
            if (-not $el) { return $false }
            $matchType = Test-TypeMatch -ElementTypeId $el.TypeId -FilterTypeId $Node.TypeId -Hierarchy $Hierarchy
            if ($matchType) { return $true }
            if ($el.GenericTypeId) {
                return (Test-TypeMatch -ElementTypeId $el.GenericTypeId -FilterTypeId $Node.TypeId -Hierarchy $Hierarchy)
            }
            return $false
        }
        'attrCheck' {
            $el = switch ($Node.Subject) {
                'source' { $Interaction.Source }
                'target' { $Interaction.Target }
                'flow'   { $Interaction.Flow }
            }
            if (-not $el -or -not $el.Properties) { return $false }
            $val = $el.Properties[$Node.Attribute]
            if ($null -eq $val) { return $false }
            return ($val -ieq $Node.Value)
        }
        'crosses' {
            $crossings = $Interaction.Crossings
            if (-not $crossings) { return $false }
            foreach ($c in $crossings) {
                if (Test-TypeMatch -ElementTypeId $c.BoundaryTypeId -FilterTypeId $Node.BoundaryTypeId -Hierarchy $Hierarchy) {
                    return $true
                }
                if ($c.BoundaryGenericTypeId -and
                    (Test-TypeMatch -ElementTypeId $c.BoundaryGenericTypeId -FilterTypeId $Node.BoundaryTypeId -Hierarchy $Hierarchy)) {
                    return $true
                }
            }
            return $false
        }
        'literal' {
            return [bool]$Node.Value
        }
        default { return $false }
    }
}

function Evaluate-Filter {
    param(
        [string]$Expression,
        [hashtable]$Interaction,
        [hashtable]$Hierarchy
    )

    if (-not $Expression -or $Expression.Trim() -eq '') { return $false }

    $tokens = Tokenize-Filter -Expr $Expression
    if ($tokens.Count -eq 0) { return $false }

    $stream = [TokenStream]::new($tokens)
    $ast    = Parse-Expression -Stream $stream

    return (Evaluate-AST -Node $ast -Interaction $Interaction -Hierarchy $Hierarchy)
}

# ─── STRIDE Category Normalizer ───────────────────────────────────────────────
function Normalize-StrideCategoryName {
    <# Maps KB category names (which vary across templates) to canonical STRIDE names.
       Handles case differences ("Of" vs "of"), pluralization ("Privileges" vs "Privilege"),
       and abbreviations. Returns the raw name unchanged if no STRIDE match. #>
    param([string]$RawName)
    if (-not $RawName) { return $RawName }
    $lower = $RawName.ToLower().Trim()
    switch -Wildcard ($lower) {
        '*spoof*'             { return 'Spoofing' }
        '*tamper*'            { return 'Tampering' }
        '*repud*'             { return 'Repudiation' }
        '*information*'       { return 'Information Disclosure' }
        '*denial*'            { return 'Denial of Service' }
        '*elevation*'         { return 'Elevation of Privilege' }
        '*compliance*'        { return 'Compliance' }
        default               { return $RawName }
    }
}

# ─── Phase 6: Extract Threat Rules from KnowledgeBase ────────────────────────
function Extract-ThreatRules {
    param([System.Xml.XmlElement]$KBNode, [System.Xml.XmlNamespaceManager]$NsMgr)

    $rules = [System.Collections.ArrayList]::new()
    $categories = @{}

    # ── Threat Categories ───────────────────────────────────────────────────
    $catNodes = $KBNode.SelectNodes('.//kb:ThreatCategory', $NsMgr)
    foreach ($cat in $catNodes) {
        $cid   = Get-NodeText $cat 'kb:Id' $NsMgr
        $cname = Get-NodeText $cat 'kb:Name' $NsMgr
        if ($cid) { $categories[$cid] = $cname }
    }

    # ── Threat Types (rules) ───────────────────────────────────────────────
    $typeNodes = $KBNode.SelectNodes('.//kb:ThreatType', $NsMgr)
    foreach ($tt in $typeNodes) {
        $id       = Get-NodeText $tt 'kb:Id' $NsMgr
        $catId    = Get-NodeText $tt 'kb:Category' $NsMgr
        $title    = Get-NodeText $tt 'kb:ShortTitle' $NsMgr
        $desc     = Get-NodeText $tt 'kb:Description' $NsMgr

        $gfNode   = $tt.SelectSingleNode('kb:GenerationFilters', $NsMgr)
        $include  = if ($gfNode) { Get-NodeText $gfNode 'kb:Include' $NsMgr } else { $null }
        $exclude  = if ($gfNode) { Get-NodeText $gfNode 'kb:Exclude' $NsMgr } else { $null }

        if (-not $id) { continue }

        # Skip umbrella rules
        if ($include -and $include.Trim() -eq "source is 'ROOT'") { continue }

        [void]$rules.Add(@{
            Id           = $id
            Category     = $catId
            CategoryName = Normalize-StrideCategoryName ($categories[$catId] ?? $catId)
            ShortTitle   = $title
            Description  = $desc
            Include      = $include
            Exclude      = $exclude
        })
    }

    return @{
        Rules      = $rules.ToArray()
        Categories = $categories
    }
}

# ─── Phase 7 & 8: Generate Threats + Gap Analysis ────────────────────────────
function Invoke-ThreatGeneration {
    param(
        [array]$Interactions,
        [array]$Rules,
        [hashtable]$Hierarchy,
        [hashtable]$ExistingThreats
    )

    $generated = [System.Collections.ArrayList]::new()
    $threatNum = 0

    foreach ($interaction in $Interactions) {
        foreach ($rule in $Rules) {
            $includeResult = Evaluate-Filter -Expression $rule.Include -Interaction $interaction -Hierarchy $Hierarchy
            if (-not $includeResult) { continue }

            $excludeResult = $false
            if ($rule.Exclude -and $rule.Exclude.Trim() -ne '') {
                $excludeResult = Evaluate-Filter -Expression $rule.Exclude -Interaction $interaction -Hierarchy $Hierarchy
            }
            if ($excludeResult) { continue }

            $threatNum++
            $srcName  = $interaction.Source.Name
            $tgtName  = $interaction.Target.Name
            $flowName = $interaction.Flow.Name

            $title = ($rule.ShortTitle ?? '') -replace '\{source\.Name\}', $srcName `
                -replace '\{target\.Name\}', $tgtName `
                -replace '\{flow\.Name\}', $flowName
            $desc = ($rule.Description ?? '') -replace '\{source\.Name\}', $srcName `
                -replace '\{target\.Name\}', $tgtName `
                -replace '\{flow\.Name\}', $flowName

            # TMT stores threat keys with original (surface-specific) element GUIDs, not canonical.
            # Use flow's OriginalSourceGuid/OriginalTargetGuid which preserve the pre-remap values.
            $origSrc = $interaction.Flow.OriginalSourceGuid ?? $interaction.Source.Guid
            $origTgt = $interaction.Flow.OriginalTargetGuid ?? $interaction.Target.Guid
            $matchKey = "$($rule.Id)$($origSrc)$($interaction.Flow.Guid)$($origTgt)"

            $crossingNames = ($interaction.Crossings | ForEach-Object { $_.BoundaryName }) -join ', '
            if (-not $crossingNames) { $crossingNames = '(none)' }

            $existingMatch = $null
            if ($ExistingThreats.ContainsKey($matchKey)) {
                $existingMatch = $ExistingThreats[$matchKey]
            }

            [void]$generated.Add(@{
                Number          = $threatNum
                RuleId          = $rule.Id
                Category        = $rule.Category
                CategoryName    = $rule.CategoryName
                Title           = $title
                Description     = $desc
                SourceName      = $srcName
                TargetName      = $tgtName
                FlowName        = $flowName
                SourceTypeId    = $interaction.Source.TypeId
                TargetTypeId    = $interaction.Target.TypeId
                FlowTypeId      = $interaction.Flow.TypeId
                Crossings       = $crossingNames
                IncludeFilter   = $rule.Include
                ExcludeFilter   = $rule.Exclude
                MatchKey        = $matchKey
                ExistingMatch   = $existingMatch
                Interaction     = "$srcName -> [$flowName] -> $tgtName"
            })
        }
    }

    $matchedKeys = $generated | ForEach-Object { $_.MatchKey } | Sort-Object -Unique
    $extras = [System.Collections.ArrayList]::new()
    foreach ($et in $ExistingThreats.Values) {
        if ($et.Key -notin $matchedKeys) {
            [void]$extras.Add($et)
        }
    }

    return @{
        Generated  = $generated.ToArray()
        Extras     = $extras.ToArray()
        Matched    = @($generated | Where-Object { $null -ne $_.ExistingMatch }).Count
        Missing    = @($generated | Where-Object { $null -eq $_.ExistingMatch }).Count
        ExtraCount = $extras.Count
    }
}

# ─── Mermaid Diagram Builder ──────────────────────────────────────────────────
function Build-MermaidDiagram {
    param(
        [hashtable]$Elements,
        [hashtable]$Flows,
        [hashtable]$BorderBounds,
        [hashtable]$LineBounds,
        [hashtable]$CrossingMap
    )

    # Helper: sanitize ID for Mermaid (alphanumeric + underscore only)
    function MermaidId([string]$guid) {
        return 'n_' + ($guid -replace '[^a-zA-Z0-9]', '')
    }
    # Helper: escape label text for Mermaid (quotes, brackets, pipes, newlines, parens)
    function MermaidLabel([string]$text) {
        if (-not $text) { return '?' }
        $t = $text -replace '"', '#quot;' -replace '<', '#lt;' -replace '>', '#gt;' -replace '\|', '/'
        # Strip carriage returns and replace newlines with spaces
        $t = $t -replace '\r', '' -replace '\n', ' '
        # Escape square brackets which conflict with Mermaid node syntax
        $t = $t -replace '\[', '#lbrack;' -replace '\]', '#rbrack;'
        # Escape parentheses which conflict with Mermaid shape syntax
        $t = $t -replace '\(', '#lpar;' -replace '\)', '#rpar;'
        # Collapse multiple spaces
        $t = $t -replace '\s{2,}', ' '
        $t = $t.Trim()
        if ($t.Length -gt 60) { $t = $t.Substring(0, 57) + '...' }
        return $t
    }
    # Helper: shape syntax by DFD generic type
    function MermaidShape([string]$genType, [string]$label) {
        switch ($genType) {
            'GE.EI'  { return "([$label])" }     # stadium shape for External Interactor
            'GE.DS'  { return "[($label)]" }     # cylindrical for Data Store
            'GE.P'   { return "[$label]" }       # rectangle for Process
            default   { return "[$label]" }
        }
    }

    # ── 1. Determine which elements sit inside which border boundaries ───────
    $elInBoundary = @{}   # elementGuid => [boundaryGuid, ...]
    $boundaryContains = @{}  # boundaryGuid => [elementGuid, ...]

    foreach ($bound in $BorderBounds.Values) {
        $boundaryContains[$bound.Guid] = [System.Collections.ArrayList]::new()
        $bL = $bound['Left']; $bT = $bound['Top']
        $bR = $bL + $bound['Width']; $bBot = $bT + $bound['Height']

        foreach ($el in $Elements.Values) {
            $sameSurface = ($el.Surface -eq $bound.Surface) -or
                           ($el.Surfaces -and $el.Surfaces -contains $bound.Surface)
            if (-not $sameSurface) { continue }

            $pos = $el.Position
            $cx = $pos.Left + $pos.Width / 2
            $cy = $pos.Top + $pos.Height / 2

            if ($cx -ge $bL -and $cx -le $bR -and $cy -ge $bT -and $cy -le $bBot) {
                if (-not $elInBoundary.ContainsKey($el.Guid)) {
                    $elInBoundary[$el.Guid] = [System.Collections.ArrayList]::new()
                }
                [void]$elInBoundary[$el.Guid].Add($bound.Guid)
                [void]$boundaryContains[$bound.Guid].Add($el.Guid)
            }
        }
    }

    # ── 2. Merge boundaries with same name — keep only those that contain elements ─
    # When same-name boundaries appear on different surfaces, merge their element sets
    $mergedBounds = [ordered]@{}  # boundaryName => { Guid, Name, ElementGuids, Area }
    $sortedBounds = @($BorderBounds.Values | Sort-Object { -($_.Width * $_.Height) })
    foreach ($bound in $sortedBounds) {
        $bName = $bound.Name
        # Find which elements are in their INNERMOST boundary = this one
        $innerEls = [System.Collections.ArrayList]::new()
        foreach ($elGuid in $boundaryContains[$bound.Guid]) {
            $allBoundsForEl = $elInBoundary[$elGuid]
            $innermostGuid = $null
            $innermostArea = [double]::MaxValue
            foreach ($bguid in $allBoundsForEl) {
                $b2 = $BorderBounds[$bguid]
                $area = $b2.Width * $b2.Height
                if ($area -lt $innermostArea) { $innermostArea = $area; $innermostGuid = $bguid }
            }
            if ($innermostGuid -eq $bound.Guid) {
                [void]$innerEls.Add($elGuid)
            }
        }

        if ($mergedBounds.Contains($bName)) {
            # Merge elements into existing boundary with same name
            foreach ($eg in $innerEls) {
                if ($mergedBounds[$bName].ElementGuids -notcontains $eg) {
                    [void]$mergedBounds[$bName].ElementGuids.Add($eg)
                }
            }
        }
        else {
            $mergedBounds[$bName] = @{
                Guid         = $bound.Guid
                Name         = $bName
                ElementGuids = $innerEls
            }
        }
    }

    # ── 3. Identify elements NOT inside any boundary ─────────────────────────
    $insideBoundaryGuids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($mb in $mergedBounds.Values) {
        foreach ($eg in $mb.ElementGuids) { [void]$insideBoundaryGuids.Add($eg) }
    }
    $outsideElements = @($Elements.Values | Where-Object { -not $insideBoundaryGuids.Contains($_.Guid) })

    # ── 4. Pre-compute line boundary subgraphs ─────────────────────────────
    # For line boundaries, determine which elements are "inside" by checking flow crossings.
    $seenLBNames = @{}
    $lineBoundSubgraphs = [ordered]@{}  # boundaryName => { Guid, Elements }
    foreach ($lb in ($LineBounds.Values | Sort-Object { $_.Name })) {
        if ($seenLBNames.ContainsKey($lb.Name)) { continue }
        $seenLBNames[$lb.Name] = $true

        $insideEls = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $outsideEls = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($fl in $Flows.Values) {
            $crossings = $CrossingMap[$fl.Guid]
            if (-not $crossings) { continue }
            $crossesThisLB = $false
            foreach ($cr in @($crossings)) {
                if ($cr.BoundaryName -eq $lb.Name) { $crossesThisLB = $true; break }
            }
            if (-not $crossesThisLB) { continue }

            $srcEl = $Elements[$fl.SourceGuid]
            $tgtEl = $Elements[$fl.TargetGuid]
            if (-not $srcEl -or -not $tgtEl) { continue }

            # Heuristic: External Interactors are outside, Processes/DataStores are inside
            if ($srcEl.GenericTypeId -eq 'GE.EI') { [void]$outsideEls.Add($srcEl.Guid); [void]$insideEls.Add($tgtEl.Guid) }
            elseif ($tgtEl.GenericTypeId -eq 'GE.EI') { [void]$outsideEls.Add($tgtEl.Guid); [void]$insideEls.Add($srcEl.Guid) }
            else { [void]$insideEls.Add($srcEl.Guid); [void]$insideEls.Add($tgtEl.Guid) }
        }

        # Remove elements already in border boundary subgraphs
        $finalInside = [System.Collections.ArrayList]::new()
        foreach ($eg in $insideEls) {
            if (-not $insideBoundaryGuids.Contains($eg) -and -not $outsideEls.Contains($eg)) {
                [void]$finalInside.Add($eg)
            }
        }

        # Expand: elements connected to "inside" elements via non-crossing flows are also inside
        $expanded = $true
        while ($expanded) {
            $expanded = $false
            foreach ($fl in $Flows.Values) {
                $crossings = $CrossingMap[$fl.Guid]
                $crossesThisLB2 = $false
                if ($crossings) { foreach ($cr in @($crossings)) { if ($cr.BoundaryName -eq $lb.Name) { $crossesThisLB2 = $true; break } } }
                if ($crossesThisLB2) { continue }  # Skip flows that cross this boundary

                $srcEl = $Elements[$fl.SourceGuid]
                $tgtEl = $Elements[$fl.TargetGuid]
                if (-not $srcEl -or -not $tgtEl) { continue }

                $srcIn = $finalInside -contains $fl.SourceGuid
                $tgtIn = $finalInside -contains $fl.TargetGuid
                if ($srcIn -and -not $tgtIn -and -not $outsideEls.Contains($fl.TargetGuid) -and -not $insideBoundaryGuids.Contains($fl.TargetGuid)) {
                    [void]$finalInside.Add($fl.TargetGuid); $expanded = $true
                }
                if ($tgtIn -and -not $srcIn -and -not $outsideEls.Contains($fl.SourceGuid) -and -not $insideBoundaryGuids.Contains($fl.SourceGuid)) {
                    [void]$finalInside.Add($fl.SourceGuid); $expanded = $true
                }
            }
        }

        if ($finalInside.Count -gt 0) {
            $lineBoundSubgraphs[$lb.Name] = @{ Guid = $lb.Guid; Elements = $finalInside }
        }
    }

    # Track elements in line boundary subgraphs
    $inLineBoundGuids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($lbs in $lineBoundSubgraphs.Values) {
        foreach ($eg in $lbs.Elements) { [void]$inLineBoundGuids.Add($eg) }
    }

    # ── 5. Build Mermaid lines ───────────────────────────────────────────────
    $lines = [System.Collections.ArrayList]::new()
    [void]$lines.Add("%%{init: {'theme': 'base', 'themeVariables': { 'background': '#ffffff', 'primaryColor': '#ffffff', 'lineColor': '#666666' }}}%%")
    [void]$lines.Add('graph LR')

    # -- Elements NOT in any boundary (border or line)
    foreach ($el in ($outsideElements | Sort-Object { $_.Name })) {
        if ($inLineBoundGuids.Contains($el.Guid)) { continue }
        $nid = MermaidId $el.Guid
        $label = MermaidLabel $el.Name
        $shape = MermaidShape $el.GenericTypeId $label
        [void]$lines.Add("    $nid$shape")
    }

    # -- Subgraphs for merged boundaries
    foreach ($mb in $mergedBounds.Values) {
        $bid = MermaidId $mb.Guid
        $bLabel = MermaidLabel $mb.Name
        [void]$lines.Add("    subgraph $bid [""$bLabel""]")
        if ($mb.ElementGuids.Count -eq 0) {
            # Empty boundary — add invisible placeholder so Mermaid renders the subgraph
            [void]$lines.Add("        ${bid}_empty[ ]")
            [void]$lines.Add("        style ${bid}_empty fill:none,stroke:none,color:transparent")
        }
        foreach ($elGuid in $mb.ElementGuids) {
            $el = $Elements[$elGuid]
            if (-not $el) { continue }
            $nid = MermaidId $el.Guid
            $label = MermaidLabel $el.Name
            $shape = MermaidShape $el.GenericTypeId $label
            [void]$lines.Add("        $nid$shape")
        }
        [void]$lines.Add('    end')
    }

    # -- Line boundary subgraphs (rendered as dashed boxes like border boundaries)
    foreach ($lbName in $lineBoundSubgraphs.Keys) {
        $lbs = $lineBoundSubgraphs[$lbName]
        $lbid = MermaidId $lbs.Guid
        $lbLabel = MermaidLabel $lbName
        [void]$lines.Add("    subgraph $lbid [""$lbLabel""]")
        foreach ($elGuid in $lbs.Elements) {
            $el = $Elements[$elGuid]
            if (-not $el) { continue }
            $nid = MermaidId $el.Guid
            $label = MermaidLabel $el.Name
            $shape = MermaidShape $el.GenericTypeId $label
            [void]$lines.Add("        $nid$shape")
        }
        [void]$lines.Add('    end')
    }

    # -- Flow edges (deduplicate: group by src+tgt, aggregate names & crossings)
    $edgeMap = [ordered]@{}
    foreach ($fl in $Flows.Values) {
        $srcEl = $Elements[$fl.SourceGuid]
        $tgtEl = $Elements[$fl.TargetGuid]
        if (-not $srcEl -or -not $tgtEl) { continue }
        # Skip self-referencing flows (same canonical element)
        if ($fl.SourceGuid -eq $fl.TargetGuid) { continue }

        $edgeKey = "$($fl.SourceGuid)::$($fl.TargetGuid)"
        if (-not $edgeMap.Contains($edgeKey)) {
            $edgeMap[$edgeKey] = @{
                SourceGuid = $fl.SourceGuid
                TargetGuid = $fl.TargetGuid
                Names      = [System.Collections.ArrayList]::new()
                Crosses    = [System.Collections.ArrayList]::new()
            }
        }
        $fname = if ($fl.Name -and $fl.Name -ne "Flow-$($fl.Guid)") { $fl.Name } else { $fl.TypeId }
        if ($edgeMap[$edgeKey].Names -notcontains $fname) {
            [void]$edgeMap[$edgeKey].Names.Add($fname)
        }
        $crossNames = @($CrossingMap[$fl.Guid] | ForEach-Object { $_.BoundaryName })
        foreach ($cn in $crossNames) {
            if ($edgeMap[$edgeKey].Crosses -notcontains $cn) {
                [void]$edgeMap[$edgeKey].Crosses.Add($cn)
            }
        }
    }

    foreach ($edge in $edgeMap.Values) {
        $srcId = MermaidId $edge.SourceGuid
        $tgtId = MermaidId $edge.TargetGuid
        $allNames = ($edge.Names | Select-Object -Unique) -join ', '
        $label = MermaidLabel $allNames
        if (@($edge.Crosses).Count -gt 0) {
            $crossLabel = ($edge.Crosses | Select-Object -Unique) -join ', '
            $label = "$label<br/>Crosses: $crossLabel"
        }
        [void]$lines.Add("    $srcId -->|""$label""| $tgtId")
    }

    # -- Style classes for DFD element shapes
    [void]$lines.Add('')
    [void]$lines.Add('    classDef extInteractor fill:#dae8fc,stroke:#6c8ebf,stroke-width:2px,color:#1a1a2e')
    [void]$lines.Add('    classDef process fill:#d5e8d4,stroke:#82b366,stroke-width:2px,color:#1a1a2e')
    [void]$lines.Add('    classDef dataStore fill:#fff2cc,stroke:#d6b656,stroke-width:2px,color:#1a1a2e')
    [void]$lines.Add('    classDef lineBound fill:#fff0f0,stroke:#e74c3c,stroke-width:1px,stroke-dasharray:5 5,color:#c0392b,font-style:italic')
    [void]$lines.Add('    linkStyle default stroke:#666666,stroke-width:2px')

    # Apply element classes
    foreach ($el in $Elements.Values) {
        $nid = MermaidId $el.Guid
        $cls = switch ($el.GenericTypeId) {
            'GE.EI'  { 'extInteractor' }
            'GE.DS'  { 'dataStore' }
            'GE.P'   { 'process' }
            default   { 'process' }
        }
        [void]$lines.Add("    class $nid $cls")
    }

    # Apply line boundary class (only for line bounds NOT converted to subgraphs)
    $seenLBNames2 = @{}
    foreach ($lb in $LineBounds.Values) {
        if ($seenLBNames2.ContainsKey($lb.Name)) { continue }
        $seenLBNames2[$lb.Name] = $true
        # Skip if this line boundary is now a subgraph
        if ($lineBoundSubgraphs.Contains($lb.Name)) { continue }
        [void]$lines.Add("    class $(MermaidId $lb.Guid) lineBound")
    }

    # Style subgraph boundaries (red dashed) — both border and line boundaries
    foreach ($mb in $mergedBounds.Values) {
        $bid = MermaidId $mb.Guid
        [void]$lines.Add("    style $bid fill:#fff5f5,stroke:#e74c3c,stroke-width:2px,stroke-dasharray:5 5,color:#c0392b")
    }
    foreach ($lbName in $lineBoundSubgraphs.Keys) {
        $lbs = $lineBoundSubgraphs[$lbName]
        $lbid = MermaidId $lbs.Guid
        [void]$lines.Add("    style $lbid fill:#fff5f5,stroke:#e74c3c,stroke-width:2px,stroke-dasharray:5 5,color:#c0392b")
    }

    return ($lines -join "`n")
}

# ─── HTML Report Generator ───────────────────────────────────────────────────
function Get-CategoryBadgeClass {
    param([string]$CategoryName)
    switch -Wildcard ($CategoryName) {
        '*Spoofing*'     { return 'badge-spoofing' }
        '*Tampering*'    { return 'badge-tampering' }
        '*Repudiation*'  { return 'badge-repudiation' }
        '*Information*'  { return 'badge-info' }
        '*Denial*'       { return 'badge-dos' }
        '*Elevation*'    { return 'badge-elevation' }
        '*Compliance*'   { return 'badge-compliance' }
        default          { return 'badge-custom' }
    }
}

function HtmlEnc {
    param([string]$Text)
    if (-not $Text) { return '' }
    return [System.Web.HttpUtility]::HtmlEncode($Text)
}

function Export-HTMLReport {
    param(
        [hashtable]$ParseResult,
        [hashtable]$ThreatResult,
        [hashtable]$RuleData,
        [hashtable]$Hierarchy,
        [hashtable]$CrossingMap,
        [string]$TM7FileName,
        [string]$OutputPath,
        [string]$MermaidDiagram
    )

    $elements       = $ParseResult.Elements
    $flows          = $ParseResult.Flows
    $lineBounds     = $ParseResult.LineBoundaries
    $borderBounds   = $ParseResult.BorderBounds
    $generated      = $ThreatResult.Generated
    $extras         = $ThreatResult.Extras
    $totalGenerated = $generated.Count
    $matched        = $ThreatResult.Matched
    $missing        = $ThreatResult.Missing
    $extraCount     = $ThreatResult.ExtraCount
    $existingTotal  = $ParseResult.ExistingThreats.Count

    # Category distribution — always include all 6 STRIDE categories (even 0 count)
    $strideNames = @('Spoofing','Tampering','Repudiation','Information Disclosure','Denial of Service','Elevation of Privilege')
    $catDist = [ordered]@{}
    foreach ($sn in $strideNames) { $catDist[$sn] = 0 }
    foreach ($g in $generated) {
        $cn = $g.CategoryName
        if (-not $catDist.Contains($cn)) { $catDist[$cn] = 0 }
        $catDist[$cn]++
    }

    # Group threats by interaction
    $byInteraction = [ordered]@{}
    foreach ($g in $generated) {
        $key = $g.Interaction
        if (-not $byInteraction.Contains($key)) { $byInteraction[$key] = [System.Collections.ArrayList]::new() }
        [void]$byInteraction[$key].Add($g)
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TM7 Threat Analysis - $(HtmlEnc $TM7FileName)</title>
<style>
:root {
    --primary: #2171b5; --primary-light: #6baed6; --accent: #d94701;
    --green: #238b45; --green-light: #74c476; --red: #e31a1c;
    --bg: #ffffff; --text: #1a1a2e; --border: #dee2e6;
    --gray: #666666; --light-bg: #f8f9fa;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
       color: var(--text); background: var(--bg); line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
h1 { color: var(--primary); border-bottom: 3px solid var(--primary); padding-bottom: 10px; margin-bottom: 20px; }
h2 { color: var(--primary); margin: 30px 0 15px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
h3 { color: var(--accent); margin: 20px 0 10px; }
table { width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 0.9em; }
th, td { border: 1px solid var(--border); padding: 8px 12px; text-align: left; }
th { background: var(--primary); color: white; font-weight: 600; }
tr:nth-child(even) { background: var(--light-bg); }
.badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.8em; font-weight: 600; }
.badge-spoofing { background: #fde2e2; color: #c0392b; }
.badge-tampering { background: #fef3cd; color: #856404; }
.badge-repudiation { background: #e8daef; color: #6c3483; }
.badge-info { background: #d4efdf; color: #1e8449; }
.badge-dos { background: #d6eaf8; color: #2471a3; }
.badge-elevation { background: #fadbd8; color: #922b21; }
.badge-compliance { background: #fdebd0; color: #a04000; }
.badge-custom { background: #e8e8e8; color: #555; }
.badge-matched { background: #d4edda; color: #155724; }
.badge-missing { background: #fff3cd; color: #856404; }
.badge-extra { background: #cce5ff; color: #004085; }
.metrics-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }
.metrics-grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }
.metric-card { background: var(--light-bg); border: 1px solid var(--border); border-radius: 8px; padding: 15px; text-align: center; }
.metric-card .value { font-size: 2em; font-weight: 700; color: var(--primary); }
.metric-card .label { font-size: 0.85em; color: var(--gray); }
.detail-card { border: 1px solid var(--border); border-radius: 8px; margin: 15px 0; padding: 15px; background: var(--light-bg); }
.detail-card h4 { color: var(--primary); margin-bottom: 10px; }
.filter-code { background: #f0f0f0; padding: 4px 8px; border-radius: 4px; font-family: 'Cascadia Code', monospace; font-size: 0.85em; word-break: break-all; }
@media print {
    .container { max-width: 100%; }
    table { font-size: 0.8em; }
    .detail-card { break-inside: avoid; }
}
.mermaid-wrapper { margin: 20px 0; padding: 20px; background: #fafbfc; border: 1px solid var(--border); border-radius: 8px; overflow-x: auto; }
.mermaid-wrapper .mermaid { text-align: center; }
.mermaid-legend { display: flex; gap: 20px; flex-wrap: wrap; margin: 10px 0; font-size: 0.85em; }
.mermaid-legend span { display: inline-flex; align-items: center; gap: 5px; }
.legend-swatch { width: 16px; height: 16px; border-radius: 3px; display: inline-block; }
</style>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>mermaid.initialize({startOnLoad:true, theme:'base', themeVariables:{primaryColor:'#d5e8d4',primaryBorderColor:'#82b366',lineColor:'#666',textColor:'#1a1a2e',fontSize:'14px'}, flowchart:{useMaxWidth:true,htmlLabels:true,curve:'basis'}, securityLevel:'loose'});</script>
</head>
<body>
<div class="container">
<h1>TM7 Threat Analysis Report</h1>
<p><strong>File:</strong> $(HtmlEnc $TM7FileName) &nbsp;|&nbsp; <strong>Generated:</strong> $timestamp</p>
"@)

    # Section 1: Data Flow Diagram (Mermaid)
    if ($MermaidDiagram) {
        [void]$sb.AppendLine('<h2>1. Data Flow Diagram</h2>')
        [void]$sb.AppendLine('<div class="mermaid-legend">')
        [void]$sb.AppendLine('  <span><span class="legend-swatch" style="background:#dae8fc;border:2px solid #6c8ebf"></span> External Interactor</span>')
        [void]$sb.AppendLine('  <span><span class="legend-swatch" style="background:#d5e8d4;border:2px solid #82b366"></span> Process</span>')
        [void]$sb.AppendLine('  <span><span class="legend-swatch" style="background:#fff2cc;border:2px solid #d6b656"></span> Data Store</span>')
        [void]$sb.AppendLine('  <span><span class="legend-swatch" style="background:#fff5f5;border:2px dashed #e74c3c"></span> Trust Boundary</span>')
        [void]$sb.AppendLine('</div>')
        [void]$sb.AppendLine('<div class="mermaid-wrapper">')
        [void]$sb.AppendLine('<pre class="mermaid">')
        [void]$sb.AppendLine($MermaidDiagram)
        [void]$sb.AppendLine('</pre>')
        [void]$sb.AppendLine('</div>')
    }

    # Section 2: Components
    [void]$sb.AppendLine('<h2>2. Components</h2>')
    [void]$sb.AppendLine('<table><tr><th>#</th><th>Element</th><th>Type</th><th>Generic</th><th>Key Attributes</th></tr>')
    $i = 0
    foreach ($el in ($elements.Values | Sort-Object { $_.Name })) {
        $i++
        $guidPat = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        $attrs = ($el.Properties.GetEnumerator() |
            Where-Object { $_.Value -and $_.Value -ne '' -and $_.Key -notmatch $guidPat } |
            Select-Object -First 5 |
            ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
        $genLabel = switch ($el.GenericTypeId) {
            'GE.P'    { 'Process' }
            'GE.EI'   { 'External Interactor' }
            'GE.DS'   { 'Data Store' }
            default   { $el.GenericTypeId }
        }
        $scope = if ($el.OutOfScope) { ' <em>(Out of Scope)</em>' } else { '' }
        [void]$sb.AppendLine("<tr><td>$i</td><td>$(HtmlEnc $el.Name)$scope</td><td><code>$(HtmlEnc $el.TypeId)</code></td><td>$genLabel</td><td>$(HtmlEnc $attrs)</td></tr>")
    }
    [void]$sb.AppendLine('</table>')

    # Section 3: Data Flow Inventory — assign DF labels
    [void]$sb.AppendLine('<h2>3. Data Flow Inventory</h2>')
    [void]$sb.AppendLine('<table><tr><th>DF#</th><th>Flow</th><th>Type</th><th>Source &rarr; Target</th><th>Crosses Boundaries</th></tr>')
    $dfNum = 0
    $flowDFLabels = @{}  # Maps flow GUID to DF label
    foreach ($fl in ($flows.Values | Sort-Object { $_.Name })) {
        $dfNum++
        $dfLabel = "DF$('{0:D2}' -f $dfNum)"
        $flowDFLabels[$fl.Guid] = $dfLabel
        $srcEl = $elements[$fl.SourceGuid]
        $tgtEl = $elements[$fl.TargetGuid]
        $srcN  = if ($srcEl) { $srcEl.Name } else { $fl.SourceGuid }
        $tgtN  = if ($tgtEl) { $tgtEl.Name } else { $fl.TargetGuid }
        $cross = ($CrossingMap[$fl.Guid] | ForEach-Object { $_.BoundaryName }) -join ', '
        if (-not $cross) { $cross = '(none)' }
        [void]$sb.AppendLine("<tr><td><strong>$dfLabel</strong></td><td>$(HtmlEnc $fl.Name)</td><td><code>$(HtmlEnc $fl.TypeId)</code></td><td>$(HtmlEnc $srcN) &rarr; $(HtmlEnc $tgtN)</td><td>$(HtmlEnc $cross)</td></tr>")
    }
    [void]$sb.AppendLine('</table>')

    # Build interaction-to-DF label map for Section 6 headings
    $interactionDFMap = @{}
    foreach ($fl in $flows.Values) {
        $srcEl = $elements[$fl.SourceGuid]; $tgtEl = $elements[$fl.TargetGuid]
        if ($srcEl -and $tgtEl) {
            $intKey = "$($srcEl.Name) -> [$($fl.Name)] -> $($tgtEl.Name)"
            if ($flowDFLabels.ContainsKey($fl.Guid)) { $interactionDFMap[$intKey] = $flowDFLabels[$fl.Guid] }
        }
    }

    # Section 4: Trust Boundary Map
    [void]$sb.AppendLine('<h2>4. Trust Boundary Map</h2>')
    [void]$sb.AppendLine('<table><tr><th>#</th><th>Boundary</th><th>Type</th><th>Kind</th></tr>')
    $i = 0
    $allBounds = [System.Collections.ArrayList]::new()
    foreach ($lb in $lineBounds.Values)  { [void]$allBounds.Add(@{ Name = $lb.Name; TypeId = $lb.TypeId; Kind = 'Line' }) }
    foreach ($bb in $borderBounds.Values) { [void]$allBounds.Add(@{ Name = $bb.Name; TypeId = $bb.TypeId; Kind = 'Border' }) }
    foreach ($b in ($allBounds | Sort-Object { $_.Name })) {
        $i++
        [void]$sb.AppendLine("<tr><td>$i</td><td>$(HtmlEnc $b.Name)</td><td><code>$(HtmlEnc $b.TypeId)</code></td><td>$($b.Kind)</td></tr>")
    }
    [void]$sb.AppendLine('</table>')

    # Section 5: Summary Metrics — 2 rows of 3
    [void]$sb.AppendLine('<h2>5. Threat Generation Summary</h2>')
    # Row 1: Architecture
    [void]$sb.AppendLine('<div class="metrics-grid">')
    [void]$sb.AppendLine("<div class='metric-card'><div class='value'>$($elements.Count)</div><div class='label'>Elements</div></div>")
    [void]$sb.AppendLine("<div class='metric-card'><div class='value'>$($flows.Count)</div><div class='label'>Data Flows</div></div>")
    [void]$sb.AppendLine("<div class='metric-card'><div class='value'>$($allBounds.Count)</div><div class='label'>Trust Boundaries</div></div>")
    [void]$sb.AppendLine('</div>')
    # Row 2: Threats (4 cards) — Total first, then TM7, LLM New, LLM Extends
    # LLM cards show ‘–’ (pending) until Phase 9 updates them with actual counts
    [void]$sb.AppendLine('<div class="metrics-grid-4">')
    [void]$sb.AppendLine("<div class='metric-card' style='border-left: 4px solid #27ae60;'><div class='value' id='total-threats-count'>$totalGenerated</div><div class='label'>Total Threats</div></div>")
    [void]$sb.AppendLine("<div class='metric-card'><div class='value'>$totalGenerated</div><div class='label'>TM7 Threats</div></div>")
    [void]$sb.AppendLine("<div class='metric-card' style='border-left: 4px solid #e67e22;'><div class='value' id='llm-new-count'>&ndash;</div><div class='label'>LLM New</div></div>")
    [void]$sb.AppendLine("<div class='metric-card' style='border-left: 4px solid #3498db;'><div class='value' id='llm-extends-count'>&ndash;</div><div class='label'>LLM Extends</div></div>")
    [void]$sb.AppendLine('<!-- PHASE9_STATUS=PENDING -->')
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<h3>STRIDE Category Distribution</h3>')
    [void]$sb.AppendLine('<table><tr><th>Category</th><th>Count</th></tr>')
    foreach ($cd in $catDist.GetEnumerator()) {
        [void]$sb.AppendLine("<tr><td>$(HtmlEnc $cd.Key)</td><td>$($cd.Value)</td></tr>")
    }
    [void]$sb.AppendLine('</table>')

    # Section 6: STRIDE Threat Matrix
    [void]$sb.AppendLine('<h2>6. STRIDE Threat Matrix</h2>')
    # Sort interaction groups by DF label (DF01, DF02, ...) so Section 6 follows the Data Flow Inventory order
    $sortedIntKeys = $byInteraction.Keys | Sort-Object {
        if ($interactionDFMap.ContainsKey($_)) {
            $interactionDFMap[$_]  # Sort by DF01, DF02, etc.
        } else {
            'ZZ99'  # Unmapped interactions go last
        }
    }
    foreach ($intKey in $sortedIntKeys) {
        $threats = $byInteraction[$intKey]
        $dfLabel = if ($interactionDFMap.ContainsKey($intKey)) { "$($interactionDFMap[$intKey]): " } else { '' }
        [void]$sb.AppendLine("<h3>${dfLabel}Interaction: $(HtmlEnc $intKey)</h3>")
        [void]$sb.AppendLine('<table><tr><th>#</th><th>Rule</th><th>Category</th><th>Threat</th><th>Status</th></tr>')
        foreach ($t in $threats) {
            $catBadge = Get-CategoryBadgeClass -CategoryName $t.CategoryName
            $statusBadge = if ($t.ExistingMatch) {
                "<span class='badge badge-matched'>TM7</span>"
            } else {
                "<span class='badge badge-missing'>Missing</span>"
            }
            [void]$sb.AppendLine("<tr><td>$($t.Number)</td><td><code>$(HtmlEnc $t.RuleId)</code></td><td><span class='badge $catBadge'>$(HtmlEnc $t.CategoryName)</span></td><td>$(HtmlEnc $t.Title)</td><td>$statusBadge</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    }

    # Add HTML markers for Phase 9 LLM insertions
    [void]$sb.AppendLine("<!-- LAST_KB_THREAT_NUMBER=$totalGenerated -->")
    [void]$sb.AppendLine('<!-- LLM_THREATS_SECTION_END -->')

    # (Gap Analysis moved to Section 9 TM7 Quality Review)

    # Section 7: Threat Detail Cards
    [void]$sb.AppendLine('<h2>7. Threat Detail Cards</h2>')
    foreach ($t in $generated) {
        $catBadge = Get-CategoryBadgeClass -CategoryName $t.CategoryName
        $existStatus = if ($t.ExistingMatch) {
            "Yes - State: $($t.ExistingMatch.State), Priority: $($t.ExistingMatch.Priority)"
        } else { 'No - coverage gap' }

        [void]$sb.AppendLine(@"
<div class="detail-card">
<h4>THREAT-$($t.Number.ToString('D3')): $(HtmlEnc $t.Title)</h4>
<table>
<tr><td><strong>Rule ID</strong></td><td><code>$(HtmlEnc $t.RuleId)</code></td></tr>
<tr><td><strong>Category</strong></td><td><span class="badge $catBadge">$(HtmlEnc $t.CategoryName)</span></td></tr>
<tr><td><strong>Interaction</strong></td><td>$(HtmlEnc $t.Interaction)</td></tr>
<tr><td><strong>Source</strong></td><td>$(HtmlEnc $t.SourceName) (<code>$(HtmlEnc $t.SourceTypeId)</code>)</td></tr>
<tr><td><strong>Target</strong></td><td>$(HtmlEnc $t.TargetName) (<code>$(HtmlEnc $t.TargetTypeId)</code>)</td></tr>
<tr><td><strong>Flow</strong></td><td>$(HtmlEnc $t.FlowName) (<code>$(HtmlEnc $t.FlowTypeId)</code>)</td></tr>
<tr><td><strong>Boundaries Crossed</strong></td><td>$(HtmlEnc $t.Crossings)</td></tr>
<tr><td><strong>Include Filter</strong></td><td><span class="filter-code">$(HtmlEnc $t.IncludeFilter)</span></td></tr>
<tr><td><strong>Exclude Filter</strong></td><td><span class="filter-code">$(HtmlEnc $t.ExcludeFilter)</span></td></tr>
<tr><td><strong>Existing in TM7</strong></td><td>$existStatus</td></tr>
</table>
<p><strong>Description:</strong> $(HtmlEnc $t.Description)</p>
</div>
"@)
    }

    # Section 8: LLM-Augmented Threat Analysis
    # LLM threats are added directly into the STRIDE Threat Matrix tables above (Section 6)
    # by the LLM. This section shows a summary.
    [void]$sb.AppendLine(@"
<h2>8. LLM-Augmented Threat Analysis</h2>
<div class="llm-augmented-section" style="border: 2px dashed #e67e22; border-radius: 8px; padding: 20px; margin: 16px 0; background: #fdf6ec;">
<p style="color: #e67e22; font-weight: bold; font-size: 1.1em;">&#x1F9E0; AI-Augmented Analysis</p>
<div id="llm-threats-placeholder">
<p style="color: var(--gray); font-style: italic;">
The AI analyzes the architecture, deployment context, and element properties to identify
threats beyond what the KnowledgeBase template rules detect. These threats are added directly
into the STRIDE Threat Matrix (Section 6) above, tagged with <code style="background:#e67e22;color:white;padding:2px 6px;border-radius:3px">NEW-LLM</code>
or <code style="background:#3498db;color:white;padding:2px 6px;border-radius:3px">EXTENDS</code>.
A summary will appear here after analysis completes.
</p>
</div>
</div>
<!-- LLM_SECTION8_END -->
"@)

    # ── Section 9: TM7 Quality Review ──────────────────────────────────────
    $annWithFlows = $ParseResult.AnnotationsWithFlows
    $danglingFlows = $ParseResult.DanglingFlows
    $allAnnotations = $ParseResult.Annotations

    # Find empty boundaries (borders with no elements)
    $emptyBoundaries = @()
    foreach ($bb in $ParseResult.BorderBounds.Values) {
        $hasElements = $false
        foreach ($el in $ParseResult.Elements.Values) {
            $eLeft = $el.Position.Left; $eTop = $el.Position.Top
            if ($eLeft -ge $bb.Left -and $eLeft -le ($bb.Left + $bb.Width) -and $eTop -ge $bb.Top -and $eTop -le ($bb.Top + $bb.Height)) {
                $hasElements = $true; break
            }
        }
        if (-not $hasElements) { $emptyBoundaries += $bb }
    }

    # Find orphan elements (no flows)
    $flowGuids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($fl in $flows.Values) { [void]$flowGuids.Add($fl.SourceGuid); [void]$flowGuids.Add($fl.TargetGuid) }
    $orphanElements = @($elements.Values | Where-Object { -not $flowGuids.Contains($_.Guid) })

    $hasIssues = ($annWithFlows.Count -gt 0 -or $danglingFlows.Count -gt 0 -or $emptyBoundaries.Count -gt 0 -or $orphanElements.Count -gt 0 -or $allAnnotations.Count -gt 0 -or $missing -gt 0 -or $extraCount -gt 0)

    if ($hasIssues) {
        [void]$sb.AppendLine('<h2>9. TM7 Quality Review</h2>')
        [void]$sb.AppendLine('<div style="border: 2px solid #f39c12; border-radius: 8px; padding: 16px; margin: 16px 0; background: #fffdf5;">')
        [void]$sb.AppendLine('<p style="color: #f39c12; font-weight: bold; font-size: 1.1em;">&#x26A0; Diagram Quality Issues</p>')

        # 9a. Annotations (potential misrepresentation)
        if ($allAnnotations.Count -gt 0) {
            [void]$sb.AppendLine('<h3 style="color:#e67e22;">Annotations (Potential Misrepresentation)</h3>')
            [void]$sb.AppendLine('<p>The following Free Text Annotations were found on the diagram. Annotations are <strong>not threat-modeled</strong> &mdash; no STRIDE threats are generated for them. If any represent actual data stores, configuration files, or components, they should be re-drawn as proper Data Store or Process stencils.</p>')
            [void]$sb.AppendLine('<table><tr><th>#</th><th>Annotation</th><th>Has Connected Flows?</th><th>Assessment</th></tr>')
            $annNum = 0
            foreach ($ak in $allAnnotations.Keys) {
                $ann = $allAnnotations[$ak]
                $annNum++
                $hasFlows = $annWithFlows.ContainsKey($ak)
                $flowInfo = ''
                $severity = 'Info'
                if ($hasFlows) {
                    $fls = $annWithFlows[$ak].Flows
                    $flowNames = ($fls | ForEach-Object { $_.FlowName }) -join ', '
                    $flowInfo = "Yes &mdash; $($fls.Count) flow(s): $flowNames"
                    $severity = 'Warning'
                } else {
                    $flowInfo = 'No'
                }
                $color = if ($severity -eq 'Warning') { '#e74c3c' } else { '#888' }
                $assess = if ($hasFlows) { "<span style='color:#e74c3c;font-weight:bold;'>&#x26A0; Likely misrepresented &mdash; has data flow arrows connected. Should be a Data Store or Process.</span>" } else { "<span style='color:#888;'>Context label only (no flows connected)</span>" }
                [void]$sb.AppendLine("<tr><td>$annNum</td><td>$(HtmlEnc $ann.Name)</td><td>$flowInfo</td><td>$assess</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }

        # 9b. Dangling Connections
        if ($danglingFlows.Count -gt 0) {
            [void]$sb.AppendLine('<h3 style="color:#e74c3c;">Dangling Connections</h3>')
            [void]$sb.AppendLine('<p>The following data flow arrows have one or both ends <strong>not connected</strong> to any element. These flows are excluded from threat analysis. The arrow was drawn close to an element but not snapped to its connector point in TMT.</p>')
            [void]$sb.AppendLine('<table><tr><th>#</th><th>Flow Name</th><th>Source</th><th>Target</th><th>Issue</th></tr>')
            $dfNum = 0
            foreach ($df in $danglingFlows) {
                $dfNum++
                $srcCell = if ($df.SourceDangling) { "<span style='color:#e74c3c;font-weight:bold;'>&#x2717; Not connected</span>" } else { HtmlEnc $df.SourceName }
                $tgtCell = if ($df.TargetDangling) { "<span style='color:#e74c3c;font-weight:bold;'>&#x2717; Not connected</span>" } else { HtmlEnc $df.TargetName }
                $issue = if ($df.SourceDangling -and $df.TargetDangling) { 'Both ends disconnected' } elseif ($df.SourceDangling) { 'Source not connected' } else { 'Target not connected' }
                [void]$sb.AppendLine("<tr><td>$dfNum</td><td>$(HtmlEnc $df.Name)</td><td>$srcCell</td><td>$tgtCell</td><td>$issue</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }

        # 9c. Empty Trust Boundaries
        if ($emptyBoundaries.Count -gt 0) {
            [void]$sb.AppendLine('<h3 style="color:#f39c12;">Empty Trust Boundaries</h3>')
            [void]$sb.AppendLine('<p>The following trust boundaries contain <strong>no elements</strong> on this diagram. They may represent planned components or belong to a different diagram in the same TM7 file.</p>')
            [void]$sb.AppendLine('<table><tr><th>#</th><th>Boundary</th><th>Type</th></tr>')
            $ebNum = 0
            foreach ($eb in $emptyBoundaries) {
                $ebNum++
                [void]$sb.AppendLine("<tr><td>$ebNum</td><td>$(HtmlEnc $eb.Name)</td><td><code>$(HtmlEnc $eb.TypeId)</code></td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }

        # 9d. Orphan Elements (no data flows)
        if ($orphanElements.Count -gt 0) {
            [void]$sb.AppendLine('<h3 style="color:#95a5a6;">Orphan Elements (No Data Flows)</h3>')
            [void]$sb.AppendLine('<p>The following elements have <strong>no data flows</strong> connected. No threats are generated for elements without interaction triples.</p>')
            [void]$sb.AppendLine('<table><tr><th>#</th><th>Element</th><th>Type</th></tr>')
            $oeNum = 0
            foreach ($oe in $orphanElements) {
                $oeNum++
                [void]$sb.AppendLine("<tr><td>$oeNum</td><td>$(HtmlEnc $oe.Name)</td><td><code>$(HtmlEnc $oe.TypeId)</code> ($($oe.GenericTypeId))</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }

        # 8e. Missing Threats (coverage gaps from gap analysis)
        if ($missing -gt 0) {
            $missingThreats = $generated | Where-Object { $null -eq $_.ExistingMatch }
            [void]$sb.AppendLine('<h3 style="color:#e74c3c;">Missing Threats (Not in TM7)</h3>')
            [void]$sb.AppendLine('<p>The following threats were <strong>generated by KB rules</strong> but are NOT present in the TM7 file&apos;s existing threat instances. These represent coverage gaps in the original threat model.</p>')
            [void]$sb.AppendLine('<table><tr><th>#</th><th>Rule</th><th>Category</th><th>Threat</th><th>Interaction</th></tr>')
            $m = 0
            foreach ($t in $missingThreats) {
                $m++
                [void]$sb.AppendLine("<tr><td>$m</td><td><code>$($t.RuleId)</code></td><td>$($t.CategoryName)</td><td>$(HtmlEnc $t.Title)</td><td>$(HtmlEnc $t.Interaction)</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }

        # 8f. Extra Threats (in TM7 but not generated by rules)
        if ($extraCount -gt 0) {
            [void]$sb.AppendLine('<h3 style="color:#3498db;">Extra Threats (Custom/Manual in TM7)</h3>')
            [void]$sb.AppendLine('<p>The following threats exist in the TM7 file but were NOT generated by any KB rule. They may be custom/manually-added threats.</p>')
            [void]$sb.AppendLine('<table><tr><th>#</th><th>Title</th><th>Category</th><th>State</th></tr>')
            $m = 0
            foreach ($t in $extras) {
                $m++
                [void]$sb.AppendLine("<tr><td>$m</td><td>$(HtmlEnc $t.Title)</td><td>$(HtmlEnc $t.Category)</td><td>$($t.State)</td></tr>")
            }
            [void]$sb.AppendLine('</table>')
        }

        [void]$sb.AppendLine('</div>')
    }

    # Footer
    [void]$sb.AppendLine(@"
<hr>
<p style="color: var(--gray); font-size: 0.85em;">
Generated by <strong>Invoke-TM7ThreatAnalysis.ps1</strong> &nbsp;|&nbsp;
File: $(HtmlEnc $TM7FileName) &nbsp;|&nbsp;
Timestamp: $timestamp &nbsp;|&nbsp;
Elements: $($elements.Count), Flows: $($flows.Count), Boundaries: $($allBounds.Count), Threats: $totalGenerated
</p>
</div>
</body>
</html>
"@)

    $sb.ToString() | Set-Content -Path $OutputPath -Encoding UTF8
}

# ─── Phase 9 Context Export ────────────────────────────────────────────────────
function Export-Phase9Context {
    param(
        [hashtable]$ParseResult,
        [hashtable]$ThreatResult,
        [hashtable]$CrossingMap,
        [string]$TM7FileName,
        [string]$OutputPath
    )

    $elements       = $ParseResult.Elements
    $flows          = $ParseResult.Flows
    $lineBounds     = $ParseResult.LineBoundaries
    $borderBounds   = $ParseResult.BorderBounds
    $generated      = $ThreatResult.Generated
    $notes          = $ParseResult.Notes

    # Rebuild flowDFLabels by sorting flows by name (same logic as Export-HTMLReport)
    $flowDFLabels = @{}
    $dfNum = 0
    foreach ($fl in ($flows.Values | Sort-Object { $_.Name })) {
        $dfNum++
        $flowDFLabels[$fl.Guid] = "DF$('{0:D2}' -f $dfNum)"
    }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("=== TM7 THREAT ANALYSIS - PHASE 9 CONTEXT ===")
    [void]$sb.AppendLine("File: $TM7FileName")
    [void]$sb.AppendLine("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine("")

    [void]$sb.AppendLine("=== ARCHITECTURE SUMMARY ===")
    [void]$sb.AppendLine("Elements: $($elements.Count)")
    [void]$sb.AppendLine("Flows: $($flows.Count)")
    $allBoundsCount = $lineBounds.Count + $borderBounds.Count
    [void]$sb.AppendLine("Boundaries: $allBoundsCount")
    [void]$sb.AppendLine("KB Threats Generated: $($generated.Count)")
    [void]$sb.AppendLine("Existing TM7 Threats: $($ParseResult.ExistingThreats.Count)")
    [void]$sb.AppendLine("")

    # Elements
    [void]$sb.AppendLine("=== ELEMENTS ===")
    foreach ($el in ($elements.Values | Sort-Object { $_.Name })) {
        $scope = if ($el.OutOfScope) { 'OOS=true' } else { 'OOS=false' }
        $genLabel = switch ($el.GenericTypeId) {
            'GE.P'    { 'Process' }
            'GE.EI'   { 'External Interactor' }
            'GE.DS'   { 'Data Store' }
            default   { $el.GenericTypeId }
        }
        [void]$sb.AppendLine("$($el.Name) | $genLabel | $($el.TypeId) | $scope")
    }
    [void]$sb.AppendLine("")

    # Flows with DF labels and crossings
    [void]$sb.AppendLine("=== FLOWS (with crossings) ===")
    foreach ($fl in ($flows.Values | Sort-Object { $_.Name })) {
        $dfLabel = $flowDFLabels[$fl.Guid]
        $srcEl = $elements[$fl.SourceGuid]
        $tgtEl = $elements[$fl.TargetGuid]
        $srcName = if ($srcEl) { $srcEl.Name } else { '(unknown)' }
        $tgtName = if ($tgtEl) { $tgtEl.Name } else { '(unknown)' }
        $crosses = if ($CrossingMap -and $CrossingMap[$fl.Guid]) {
            ($CrossingMap[$fl.Guid] | ForEach-Object { $_.BoundaryName } | Sort-Object -Unique) -join ', '
        } else { 'none' }
        [void]$sb.AppendLine("${dfLabel}: $srcName -> [$($fl.Name)] -> $tgtName | Type: $($fl.TypeId) | Crosses: $crosses")
    }
    [void]$sb.AppendLine("")

    # Boundaries
    [void]$sb.AppendLine("=== BOUNDARIES ===")
    foreach ($lb in ($lineBounds.Values | Sort-Object { $_.Name })) {
        [void]$sb.AppendLine("$($lb.Name) | $($lb.TypeId) | Line")
    }
    foreach ($bbVal in ($borderBounds.Values | Sort-Object { $_.Name })) {
        [void]$sb.AppendLine("$($bbVal.Name) | $($bbVal.TypeId) | Border")
    }
    [void]$sb.AppendLine("")

    # Key element properties (non-GUID, non-empty)
    [void]$sb.AppendLine("=== KEY ELEMENT PROPERTIES ===")
    $guidPat = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    foreach ($el in ($elements.Values | Sort-Object { $_.Name })) {
        $hasProps = $false
        foreach ($pk in $el.Properties.Keys) {
            $pv = $el.Properties[$pk]
            if ($pk -notmatch $guidPat -and $pv -and $pv -ne '') {
                if (-not $hasProps) { [void]$sb.AppendLine("$($el.Name):"); $hasProps = $true }
                [void]$sb.AppendLine("  $pk=$pv")
            }
        }
    }
    [void]$sb.AppendLine("")

    # Notes from TM7
    if ($notes -and $notes.Count -gt 0) {
        [void]$sb.AppendLine("=== NOTES (from TM7) ===")
        foreach ($note in $notes) {
            [void]$sb.AppendLine("$($note.Message)")
        }
        [void]$sb.AppendLine("")
    }

    # KB threat titles for dedup
    [void]$sb.AppendLine("=== KB THREAT TITLES (for dedup) ===")
    $tNum = 1
    foreach ($t in $generated) {
        [void]$sb.AppendLine("$tNum. $($t.Title)")
        $tNum++
    }
    [void]$sb.AppendLine("")

    # Interactions with zero KB threats
    [void]$sb.AppendLine("=== INTERACTIONS WITH ZERO KB THREATS ===")
    $coveredInteractions = @($generated | ForEach-Object { $_.Interaction } | Sort-Object -Unique)
    foreach ($fl in $flows.Values) {
        $srcEl = $elements[$fl.SourceGuid]
        $tgtEl = $elements[$fl.TargetGuid]
        if ($srcEl -and $tgtEl) {
            $intKey = "$($srcEl.Name) -> [$($fl.Name)] -> $($tgtEl.Name)"
            if ($intKey -notin $coveredInteractions) {
                [void]$sb.AppendLine($intKey)
            }
        }
    }
    [void]$sb.AppendLine("")

    # Stats
    [void]$sb.AppendLine("=== STATS ===")
    [void]$sb.AppendLine("Elements: $($elements.Count) | Flows: $($flows.Count) | Boundaries: $allBoundsCount | KB Threats: $($generated.Count) | Existing TM7 Threats: $($ParseResult.ExistingThreats.Count)")

    $sb.ToString() | Set-Content -Path $OutputPath -Encoding UTF8
}

# ─── JSON Export ──────────────────────────────────────────────────────────────
function Export-JSONData {
    param(
        [hashtable]$ParseResult,
        [hashtable]$ThreatResult,
        [hashtable]$CrossingMap,
        [string]$OutputPath
    )

    $data = @{
        generated_at = (Get-Date -Format 'o')
        elements     = @($ParseResult.Elements.Values | ForEach-Object {
            $elProps = @{}
            foreach ($pk in $_.Properties.Keys) {
                $pv = $_.Properties[$pk]
                # Skip GUID-pattern property names and empty values
                if ($pk -notmatch '^[0-9a-f]{8}-' -and $pv -and $pv -ne '') {
                    $elProps[$pk] = $pv
                }
            }
            @{ guid = $_.Guid; name = $_.Name; typeId = $_.TypeId; genericTypeId = $_.GenericTypeId; outOfScope = $_.OutOfScope; properties = $elProps }
        })
        flows        = @($ParseResult.Flows.Values | ForEach-Object {
            $flProps = @{}
            foreach ($pk in $_.Properties.Keys) {
                $pv = $_.Properties[$pk]
                if ($pk -notmatch '^[0-9a-f]{8}-' -and $pv -and $pv -ne '') {
                    $flProps[$pk] = $pv
                }
            }
            $srcEl = $ParseResult.Elements[$_.SourceGuid]
            $tgtEl = $ParseResult.Elements[$_.TargetGuid]
            $srcName = if ($srcEl) { $srcEl.Name } else { '(unknown)' }
            $tgtName = if ($tgtEl) { $tgtEl.Name } else { '(unknown)' }
            $flCrossings = @()
            if ($CrossingMap -and $CrossingMap[$_.Guid]) {
                $flCrossings = @($CrossingMap[$_.Guid] | ForEach-Object { $_.BoundaryName } | Sort-Object -Unique)
            }
            @{ guid = $_.Guid; name = $_.Name; typeId = $_.TypeId; source = $_.SourceGuid; target = $_.TargetGuid; source_name = $srcName; target_name = $tgtName; crossings = $flCrossings; properties = $flProps }
        })
        boundaries   = @(
            @($ParseResult.LineBoundaries.Values | ForEach-Object {
                @{ guid = $_.Guid; name = $_.Name; typeId = $_.TypeId; kind = 'Line' }
            }) +
            @($ParseResult.BorderBounds.Values | ForEach-Object {
                @{ guid = $_.Guid; name = $_.Name; typeId = $_.TypeId; kind = 'Border' }
            })
        )
        threats      = @($ThreatResult.Generated | ForEach-Object {
            @{
                number = $_.Number; ruleId = $_.RuleId; category = $_.CategoryName
                title = $_.Title; interaction = $_.Interaction; crossings = $_.Crossings
                matchedExisting = ($null -ne $_.ExistingMatch)
            }
        })
        gap_analysis = @{
            total_generated = $ThreatResult.Generated.Count
            matched         = $ThreatResult.Matched
            missing         = $ThreatResult.Missing
            extra           = $ThreatResult.ExtraCount
        }
        existing_threats = @($ParseResult.ExistingThreats.Values | ForEach-Object {
            @{ key = $_.Key; title = $_.Title; category = $_.Category; state = $_.State; priority = $_.Priority }
        })
        notes = @($ParseResult.Notes | ForEach-Object {
            @{ id = $_.Id; message = $_.Message; addedBy = $_.AddedBy }
        })
        llm_augmentation_context = @{
            instruction = 'Use this context for Phase 9 LLM-Augmented Threat Analysis. Analyze the architecture, flows, boundaries, notes, and element properties to identify threats beyond what the KB rules generated. Focus on deployment-specific, technology-specific, operational, and supply-chain risks. Compare each LLM threat against the kb_threats array and mark as NEW or PARTIAL_OVERLAP.'
            kb_threat_count = $ThreatResult.Generated.Count
            kb_threat_titles = @($ThreatResult.Generated | Select-Object -ExpandProperty Title -Unique)
        }
    }

    $data | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  TM7 Threat Analysis - Invoke-TM7ThreatAnalysis.ps1" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

$tm7FileName = [System.IO.Path]::GetFileName($TM7Path)
Write-Host "[Phase 1] Parsing TM7: $tm7FileName" -ForegroundColor Yellow

Add-Type -AssemblyName System.Web
[xml]$doc = Get-Content -Path $TM7Path -Raw -Encoding UTF8
$nsMgr = New-NsMgr -Doc $doc

# Get KnowledgeBase
$kbNode = $doc.SelectSingleNode('//m:KnowledgeBase', $nsMgr)
if (-not $kbNode -and $TB7Path) {
    Write-Host "  No embedded KnowledgeBase - loading from TB7: $TB7Path" -ForegroundColor Yellow
    [xml]$tb7Doc = Get-Content -Path $TB7Path -Raw -Encoding UTF8
    $tb7NsMgr = New-NsMgr -Doc $tb7Doc
    $kbNode = $tb7Doc.SelectSingleNode('//m:KnowledgeBase', $tb7NsMgr) ??
              $tb7Doc.SelectSingleNode('//kb:KnowledgeBase', $tb7NsMgr) ??
              $tb7Doc.DocumentElement
    # Use TB7 namespace manager for KB queries
    $kbNsMgr = $tb7NsMgr
}
else {
    $kbNsMgr = $nsMgr
}

if (-not $kbNode) {
    Write-Error "No KnowledgeBase found in TM7 or TB7. Cannot generate threats."
    return
}

# Phase 1+3: Parse
$parseResult = Parse-TM7 -Doc $doc -NsMgr $nsMgr -SurfaceFilter $SurfaceFilter
if ($SurfaceFilter) {
    Write-Host "  Surface filter active: '$SurfaceFilter'" -ForegroundColor Magenta
    Write-Host "  Matched surfaces: $($parseResult.MatchedSurfaces.Count)" -ForegroundColor Magenta
}
Write-Host "  Elements: $($parseResult.Elements.Count)" -ForegroundColor Green
Write-Host "  Flows:    $($parseResult.Flows.Count)" -ForegroundColor Green
Write-Host "  Line Boundaries:   $($parseResult.LineBoundaries.Count)" -ForegroundColor Green
Write-Host "  Border Boundaries: $($parseResult.BorderBounds.Count)" -ForegroundColor Green
Write-Host "  Existing Threats:  $($parseResult.ExistingThreats.Count)" -ForegroundColor Green

# Phase 2: Type hierarchy
Write-Host "[Phase 2] Building type hierarchy..." -ForegroundColor Yellow
$hierarchy = Build-TypeHierarchy -KBNode $kbNode -NsMgr $kbNsMgr
Write-Host "  Types in hierarchy: $($hierarchy.Count)" -ForegroundColor Green

# Phase 4: Boundary crossings
Write-Host "[Phase 4] Computing boundary crossings..." -ForegroundColor Yellow
$crossingMap = Build-BoundaryCrossingMap -Elements $parseResult.Elements -Flows $parseResult.Flows `
    -LineBounds $parseResult.LineBoundaries -BorderBounds $parseResult.BorderBounds -Hierarchy $hierarchy
$crossCount = @($crossingMap.Values | Where-Object { @($_).Count -gt 0 }).Count
Write-Host "  Flows crossing boundaries: $crossCount" -ForegroundColor Green

# Phase 5: Interaction triples
Write-Host "[Phase 5] Enumerating interaction triples..." -ForegroundColor Yellow
$interactions = Build-InteractionTriples -Elements $parseResult.Elements -Flows $parseResult.Flows -CrossingMap $crossingMap
Write-Host "  Interaction triples: $($interactions.Count)" -ForegroundColor Green

# Phase 6: Threat rules
Write-Host "[Phase 6] Extracting threat generation rules..." -ForegroundColor Yellow
$ruleData = Extract-ThreatRules -KBNode $kbNode -NsMgr $kbNsMgr
Write-Host "  Threat rules: $($ruleData.Rules.Count) (umbrella rules excluded)" -ForegroundColor Green
Write-Host "  Categories: $($ruleData.Categories.Count)" -ForegroundColor Green

# Phase 7+8: Generate threats
Write-Host "[Phase 7-8] Generating threats and gap analysis..." -ForegroundColor Yellow
$threatResult = Invoke-ThreatGeneration -Interactions $interactions -Rules $ruleData.Rules `
    -Hierarchy $hierarchy -ExistingThreats $parseResult.ExistingThreats
Write-Host "  Generated: $($threatResult.Generated.Count)" -ForegroundColor Green
Write-Host "  Matched:   $($threatResult.Matched)" -ForegroundColor Green
Write-Host "  Missing:   $($threatResult.Missing)" -ForegroundColor $(if ($threatResult.Missing -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  Extra:     $($threatResult.ExtraCount)" -ForegroundColor $(if ($threatResult.ExtraCount -gt 0) { 'Yellow' } else { 'Green' })

# Build Mermaid diagram
Write-Host "[Diagram] Building Mermaid data flow diagram..." -ForegroundColor Yellow
$mermaidDiagram = Build-MermaidDiagram -Elements $parseResult.Elements -Flows $parseResult.Flows `
    -BorderBounds $parseResult.BorderBounds -LineBounds $parseResult.LineBoundaries -CrossingMap $crossingMap
Write-Host "  Mermaid diagram built ($($mermaidDiagram.Split("`n").Count) lines)" -ForegroundColor Green

# Export HTML
$htmlPath = Join-Path $OutputDir 'threat-analysis-report.html'
Write-Host "`n[Output] Writing HTML report: $htmlPath" -ForegroundColor Yellow
Export-HTMLReport -ParseResult $parseResult -ThreatResult $threatResult -RuleData $ruleData `
    -Hierarchy $hierarchy -CrossingMap $crossingMap -TM7FileName $tm7FileName -OutputPath $htmlPath `
    -MermaidDiagram $mermaidDiagram

# Export JSON
$jsonPath = Join-Path $OutputDir 'threat-analysis-data.json'
Write-Host "[Output] Writing JSON data:   $jsonPath" -ForegroundColor Yellow
Export-JSONData -ParseResult $parseResult -ThreatResult $threatResult -CrossingMap $crossingMap -OutputPath $jsonPath

# Export Phase 9 context
$ctxPath = Join-Path $OutputDir 'phase9-context.txt'
Write-Host "[Phase 9 Prep] Writing Phase 9 context: $ctxPath" -ForegroundColor Yellow
Export-Phase9Context -ParseResult $parseResult -ThreatResult $threatResult -CrossingMap $crossingMap `
    -TM7FileName $tm7FileName -OutputPath $ctxPath
Write-Host "  Phase 9 context ready ($([Math]::Round((Get-Item $ctxPath).Length / 1024, 1)) KB)" -ForegroundColor Green

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  DONE - $($threatResult.Generated.Count) threats generated" -ForegroundColor Cyan
Write-Host "  HTML: $htmlPath" -ForegroundColor Cyan
Write-Host "  JSON: $jsonPath" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
