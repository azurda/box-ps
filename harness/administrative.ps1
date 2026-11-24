# using namespaces to find the necessary types of the parameters generated for the overrides
using namespace System.Management.Automation
using namespace System.Management.Automation.Runspaces
using namespace System.IO
using namespace System.Text
using namespace Microsoft.PowerShell.Commands
using namespace System.Diagnostics
using namespace System.Collections
using namespace Microsoft.PowerShell
using namespace NewtonSoft.Json
using namespace System

class BoxPSSecurityIdentifier {
    [string] $Value
    BoxPSSecurityIdentifier([string] $v) { $this.Value = $v }
}

class BoxPSWindowsIdentity {
    [string] $Name
    [object[]] $Groups

    BoxPSWindowsIdentity() {
        $this.Name = "LEGITMACHINE01\LEGITUSER"
        $this.Groups = @([BoxPSSecurityIdentifier]::new("S-1-5-32-544"))
    }

    static [BoxPSWindowsIdentity] GetCurrent() {
        return [BoxPSWindowsIdentity]::new()
    }
}

class BoxPSWindowsPrincipal {
    [object] $Identity
    
    BoxPSWindowsPrincipal([object] $identity) {
        $this.Identity = $identity
    }

    [bool] IsInRole([string] $role) {
        return $true
    }

    [bool] IsInRole([System.Security.Principal.WindowsBuiltInRole] $role) {
        return $true
    }
}

$WORK_DIR = "./working_<PID>"
$global:WORK_DIR = $WORK_DIR
$CODE_DIR = "<CODE_DIR>"
$BOXPS_CONFIG = Microsoft.PowerShell.Management\Get-Content "$CODE_DIR/config.json" | ConvertFrom-Json -AsHashtable

function Get-BoxPSPositiveIntEnv {
    param(
        [string] $Name,
        [long] $Default
    )

    $raw = [Environment]::GetEnvironmentVariable($Name)
    [long] $parsed = 0
    if (-not [string]::IsNullOrWhiteSpace($raw) -and [long]::TryParse($raw, [ref]$parsed) -and $parsed -gt 0) {
        return $parsed
    }
    return $Default
}

$script:BOXPS_MAX_ACTIONS = Get-BoxPSPositiveIntEnv -Name "BOXPS_MAX_ACTIONS" -Default 2000
$script:BOXPS_MAX_ACTIONS_BYTES = Get-BoxPSPositiveIntEnv -Name "BOXPS_MAX_ACTIONS_BYTES" -Default 20971520
$script:BOXPS_MAX_REPEAT_BEHAVIOR = Get-BoxPSPositiveIntEnv -Name "BOXPS_MAX_REPEAT_BEHAVIOR" -Default 10
$script:BOXPS_MAX_ARTIFACT_ACTIONS = Get-BoxPSPositiveIntEnv -Name "BOXPS_MAX_ARTIFACT_ACTIONS" -Default 100
$script:BOXPS_MAX_ARTIFACTS_BYTES = Get-BoxPSPositiveIntEnv "BOXPS_MAX_ARTIFACTS_BYTES" 52428800
$script:BOXPS_MAX_SCRAPED_BYTES = Get-BoxPSPositiveIntEnv "BOXPS_MAX_SCRAPED_BYTES" 5242880
$script:BOXPS_SEEN_NET_IOCS = [System.Collections.Generic.HashSet[string]]::new()
$script:BOXPS_SEEN_FS_IOCS = [System.Collections.Generic.HashSet[string]]::new()
$script:BOXPS_BEHAVIOR_COUNTS = @{}
$script:BOXPS_ACTION_COUNT = 0
$script:BOXPS_ARTIFACT_ACTION_COUNT = 0
$script:BOXPS_TRUNCATED = $false

class Action <# lawsuit... I'll be here all week #> {

    [String[]] $Behaviors
    [String[]] $SubBehaviors
    [String] $Actor
    [String] $Line
    [hashtable] $BehaviorProps
    [hashtable] $Parameters
    [string] $ExtraInfo
    [int] $Id
    [string] $BehaviorId

    Action ([String[]] $Behaviors, [String[]] $SubBehaviors, [String] $Actor, 
        [hashtable] $BehaviorProps, [InvocationInfo] $Invocation, [string] $ExtraInfo) {

        $this.Behaviors = $Behaviors
        $this.SubBehaviors = $SubBehaviors
        $this.Actor = $Actor
        $this.BehaviorProps = $BehaviorProps
        $this.Line = $Invocation.Line.Trim()
        $this.ExtraInfo = $ExtraInfo
        $this.Id = 0
        $this.BehaviorId = $this.GetBehaviorId()


        $paramsSplit = $this.SplitParams($Invocation)
        $this.Parameters = $paramsSplit["bound"]

        if ($paramsSplit["switches"]) {
            $this.Parameters["Switches"] = $paramsSplit["switches"]
        }
    }

    # for class members
    # e.g. System.Net.WebClient.DownloadFile
    #   These are guaranteed not to have switches, and the MyInvocation variable does not
    #   contain boundparameters, so callers need to be able to pass the PSBoundParameters variable
    Action ([String[]] $Behaviors, [String[]] $SubBehaviors, [String] $Actor, 
        [hashtable] $BehaviorProps, [hashtable] $BoundParams, [String] $Line, [String] $ExtraInfo) {

        $this.Behaviors = $Behaviors
        $this.SubBehaviors = $SubBehaviors
        $this.Actor = $Actor
        $this.BehaviorProps = $BehaviorProps
        $this.Parameters = $BoundParams
        if ($null -ne $Line) {
            $this.Line = $Line.Trim()
        } else {
            $this.Line = ""
        }
        $this.ExtraInfo = $ExtraInfo
        $this.Id = 0
        $this.BehaviorId = $this.GetBehaviorId()
    }

    [string] GetBehaviorId() {
        $hasher = [System.Security.Cryptography.IncrementalHash]::CreateHash(
            [System.Security.Cryptography.HashAlgorithmName]::SHA256
        )
        try {
            if (-not [string]::IsNullOrEmpty($this.Actor)) {
                $actorBytes = [System.Text.Encoding]::UTF8.GetBytes($this.Actor)
                $hasher.AppendData($actorBytes)
            }

            if ($null -ne $this.BehaviorProps) {
                $keys = [string[]]@($this.BehaviorProps.Keys)
                [System.Array]::Sort($keys)
                foreach ($behaviorProp in $keys) {
                    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($behaviorProp)
                    $hasher.AppendData($keyBytes)
                    $this.AppendValueToHash($hasher, $this.BehaviorProps[$behaviorProp])
                }
            }

            $hashBytes = $hasher.GetHashAndReset()
            return [System.BitConverter]::ToString($hashBytes).Replace("-", "")
        }
        finally {
            $hasher.Dispose()
        }
    }

    hidden [void] AppendStringToHash([System.Security.Cryptography.IncrementalHash] $Hasher, [string] $Text) {
        if ([string]::IsNullOrEmpty($Text)) {
            return
        }
        # Chunk large strings so multi-megabyte payloads never trigger large temporary allocations.
        $chunkChars = 65536
        if ($Text.Length -le $chunkChars) {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
            $Hasher.AppendData($bytes)
            return
        }
        $offset = 0
        while ($offset -lt $Text.Length) {
            $len = [Math]::Min($chunkChars, $Text.Length - $offset)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text.Substring($offset, $len))
            $Hasher.AppendData($bytes)
            $offset += $len
        }
    }

    hidden [void] AppendValueToHash([System.Security.Cryptography.IncrementalHash] $Hasher, [object] $Val) {
        if ($null -eq $Val) {
            return
        }
        if ($Val -is [byte[]]) {
            if ($Val.Length -gt 0) {
                $Hasher.AppendData($Val)
            }
            return
        }
        if ($Val -is [int[]]) {
            if ($Val.Length -eq 0) {
                return
            }
            $buf = [byte[]]::new(65536)
            [long] $totalBytes = [long]$Val.Length * 4
            [long] $offset = 0
            while ($offset -lt $totalBytes) {
                [int] $chunk = [Math]::Min($buf.Length, $totalBytes - $offset)
                [System.Buffer]::BlockCopy($Val, [int]$offset, $buf, 0, $chunk)
                $Hasher.AppendData($buf, 0, $chunk)
                $offset += $chunk
            }
            return
        }
        if ($Val -is [string]) {
            $this.AppendStringToHash($Hasher, $Val)
            return
        }
        if ($Val -is [System.Array]) {
            $this.AppendStringToHash($Hasher, "[len=$($Val.Length)]")
            $limit = [Math]::Min($Val.Length, 4096)
            for ($i = 0; $i -lt $limit; $i++) {
                $elem = $Val[$i]
                if ($null -ne $elem) {
                    $this.AppendStringToHash($Hasher, [string]$elem)
                }
            }
            return
        }
        $this.AppendStringToHash($Hasher, [string]$Val)
    }

    # linear walk through all parameters rebuilding bound params and switches
    [hashtable] SplitParams([InvocationInfo] $Invocation) {

        $allParams = $Invocation.MyCommand.Parameters

        $bound = @{}
        $localSwitches = @() # not allowed to name this $switches (thanks for the help, pwsh)
        
        foreach ($paramName in $allParams.Keys) {

            if ($allParams[$paramName].SwitchParameter -and $Invocation.BoundParameters.Keys -eq `
                    $paramName) {

                $localSwitches += $paramName
            }
            elseif ($Invocation.BoundParameters.Keys -eq $paramName) {
                $bound[$paramName] = $Invocation.BoundParameters[$paramName]
            }
        }

        return @{
            "bound" = $bound;
            "switches" = $localSwitches
        }
    }

    [string] GetShortActor([string] $FullActor) {

        # commandlet notation
        if ($FullActor.Contains("\")) {
            return $FullActor.Split("\")[-1]
        }
        # static function notation
        elseif ($FullActor.Contains("::")) {
            return $FullActor.Split("::")[-1]
        }
        # class member notation
        else {
            return $FullActor.Split(".")[-1]
        }
    }
}

function Test-IsArtifactAction {
    param(
        [Action] $Action
    )

    if ($null -eq $Action) {
        return $false
    }

    $artifactBehaviors = @("write_to_memory", "file_write", "binary_import")
    foreach ($b in (@($Action.Behaviors) + @($Action.SubBehaviors))) {
        if ($null -ne $b -and $artifactBehaviors -contains $b) {
            return $true
        }
    }
    return $false
}

function Convert-ToRawBytes {
    param(
        [object] $Val
    )

    if ($null -eq $Val) {
        return $null
    }
    if ($Val -is [byte[]]) {
        return ,$Val
    }
    if ($Val -is [int[]]) {
        try {
            return ,([byte[]]$Val)
        }
        catch {
            return $null
        }
    }
    if ($Val -is [object[]]) {
        $len = $Val.Length
        $out = [byte[]]::new($len)
        for ($i = 0; $i -lt $len; $i++) {
            $elem = $Val[$i]
            if ($elem -is [byte] -or $elem -is [sbyte] -or $elem -is [int16] -or $elem -is [uint16] -or
                $elem -is [int32] -or $elem -is [uint32] -or $elem -is [int64] -or $elem -is [uint64] -or
                $elem -is [decimal] -or $elem -is [double] -or $elem -is [single]) {
                [long] $num = [long]$elem
                if ($num -lt 0 -or $num -gt 255) {
                    return $null
                }
                $out[$i] = [byte]$num
            }
            else {
                return $null
            }
        }
        return ,$out
    }
    if ($Val -is [string]) {
        return ,([System.Text.Encoding]::UTF8.GetBytes($Val))
    }
    return $null
}

function Get-ArtifactsDirectoryBytes {
    param(
        [string] $ArtifactsDir
    )

    if (-not [System.IO.Directory]::Exists($ArtifactsDir)) {
        return [long]0
    }
    [long] $total = 0
    foreach ($filePath in [System.IO.Directory]::GetFiles($ArtifactsDir)) {
        $total += ([System.IO.FileInfo]::new($filePath)).Length
    }
    return $total
}

function Compact-ActionPropertyTable {
    param(
        [hashtable] $Table
    )

    if ($null -eq $Table) {
        return
    }

    $maxArrayLen = 4096
    $maxStringLen = 16384

    foreach ($key in @($Table.Keys)) {
        $val = $Table[$key]
        if ($null -eq $val) {
            continue
        }
        if ($val -is [System.Array]) {
            if ($val.Length -gt $maxArrayLen) {
                $Table[$key] = "<truncated: $($val.Length) items>"
                continue
            }
            $hasOversizedElem = $false
            for ($i = 0; $i -lt $val.Length; $i++) {
                if ($val[$i] -is [string] -and $val[$i].Length -gt $maxStringLen) {
                    $hasOversizedElem = $true
                    break
                }
            }
            if ($hasOversizedElem) {
                $cloned = [object[]]::new($val.Length)
                for ($i = 0; $i -lt $val.Length; $i++) {
                    $elem = $val[$i]
                    if ($elem -is [string] -and $elem.Length -gt $maxStringLen) {
                        $cloned[$i] = $elem.Substring(0, $maxStringLen) + "... <truncated: $($elem.Length) chars>"
                    }
                    else {
                        $cloned[$i] = $elem
                    }
                }
                $Table[$key] = $cloned
            }
        }
        elseif ($val -is [string] -and $val.Length -gt $maxStringLen) {
            $Table[$key] = $val.Substring(0, $maxStringLen) + "... <truncated: $($val.Length) chars>"
        }
    }
}

function Harvest-ActionArtifactsAtRecordTime {
    param(
        [Action] $Action,
        [string] $WorkDir
    )

    if ($null -eq $Action) {
        return
    }

    if ($null -ne $Action.BehaviorProps) {
        $Action.BehaviorProps = $Action.BehaviorProps.Clone()
    }
    if ($null -ne $Action.Parameters) {
        $Action.Parameters = $Action.Parameters.Clone()
    }

    $behaviorPropMap = @{
        "write_to_memory" = "bytes"
        "file_write"      = "content"
        "binary_import"   = "bytes"
    }

    $allBehaviors = @()
    if ($null -ne $Action.Behaviors) { $allBehaviors += $Action.Behaviors }
    if ($null -ne $Action.SubBehaviors) { $allBehaviors += $Action.SubBehaviors }

    $processedProps = [System.Collections.Generic.HashSet[string]]::new()
    if ($null -ne $Action.BehaviorProps) {
        foreach ($behavior in $allBehaviors) {
            if ($null -eq $behavior -or -not $behaviorPropMap.ContainsKey($behavior)) {
                continue
            }
            $prop = $behaviorPropMap[$behavior]
            if ($processedProps.Contains($prop) -or -not $Action.BehaviorProps.ContainsKey($prop)) {
                continue
            }

            $rawVal = $Action.BehaviorProps[$prop]
            if ($rawVal -is [System.Array] -and $rawVal.Length -eq 1 -and $rawVal[0] -is [string]) {
                $rawVal = $rawVal[0]
            }
            if ($null -eq $rawVal) {
                continue
            }
            if ($rawVal -is [string] -and ($rawVal.StartsWith("<harvested artifact:") -or $rawVal.StartsWith("<truncated:"))) {
                continue
            }

            $isBinaryArray = ($rawVal -is [System.Array])
            $rawLen = if ($isBinaryArray) { $rawVal.Length } elseif ($rawVal -is [string]) { $rawVal.Length } else { 0 }
            if ($rawLen -le 10) {
                continue
            }

            [byte[]] $rawBytes = Convert-ToRawBytes -Val $rawVal
            if ($null -eq $rawBytes -or $rawBytes.Length -le 10) {
                continue
            }

            $sha = [System.Security.Cryptography.SHA256]::Create()
            $sha256 = ""
            try {
                $hashBytes = $sha.ComputeHash($rawBytes)
                $sha256 = [System.BitConverter]::ToString($hashBytes).Replace("-", "")
            }
            finally {
                $sha.Dispose()
            }

            $artifactsDir = [System.IO.Path]::Combine($WorkDir, "artifacts")
            if (-not [System.IO.Directory]::Exists($artifactsDir)) {
                [void][System.IO.Directory]::CreateDirectory($artifactsDir)
            }
            $artifactPath = [System.IO.Path]::Combine($artifactsDir, $sha256)
            if (-not [System.IO.File]::Exists($artifactPath)) {
                $existingBytes = Get-ArtifactsDirectoryBytes -ArtifactsDir $artifactsDir
                if (($existingBytes + $rawBytes.Length) -le $script:BOXPS_MAX_ARTIFACTS_BYTES) {
                    [System.IO.File]::WriteAllBytes($artifactPath, $rawBytes)
                }
            }

            if ([System.IO.File]::Exists($artifactPath)) {
                $fileType = if ($isBinaryArray -and $rawBytes.Length -ge 2 -and $rawBytes[0] -eq 77 -and $rawBytes[1] -eq 90) {
                    "PE"
                }
                else {
                    "unknown"
                }
                $ndjsonLine = "{`"actionId`":`"$($Action.Id)`",`"sha256`":`"$sha256`",`"fileType`":`"$fileType`"}`n"
                [System.IO.File]::AppendAllText(
                    [System.IO.Path]::Combine($WorkDir, "harvested_artifacts.jsonl"),
                    $ndjsonLine,
                    [System.Text.UTF8Encoding]::new($false)
                )
            }

            [void]$processedProps.Add($prop)

            if (($isBinaryArray -and $rawBytes.Length -gt 4096) -or ($rawVal -is [string] -and $rawVal.Length -gt 16384)) {
                $placeholder = "<harvested artifact: sha256=$sha256, bytes=$($rawBytes.Length)>"
                $Action.BehaviorProps[$prop] = $placeholder
                if ($null -ne $Action.Parameters) {
                    foreach ($paramKey in @($Action.Parameters.Keys)) {
                        $paramVal = $Action.Parameters[$paramKey]
                        if ($paramVal -is [System.Array] -and $paramVal.Length -gt 4096) {
                            if ($paramVal.Length -eq $rawBytes.Length) {
                                $Action.Parameters[$paramKey] = $placeholder
                            }
                            else {
                                $Action.Parameters[$paramKey] = "<truncated: $($paramVal.Length) items>"
                            }
                        }
                        elseif ($paramVal -is [string] -and $paramVal.Length -gt 16384) {
                            if ($rawVal -is [string] -and $paramVal.Length -eq $rawVal.Length) {
                                $Action.Parameters[$paramKey] = $placeholder
                            }
                            else {
                                $Action.Parameters[$paramKey] = $paramVal.Substring(0, 16384) + "... <truncated: $($paramVal.Length) chars>"
                            }
                        }
                    }
                }
            }
        }
    }

    Compact-ActionPropertyTable -Table $Action.BehaviorProps
    Compact-ActionPropertyTable -Table $Action.Parameters
}

function Append-BoundedIocLine {
    param(
        [string] $FilePath,
        [string] $Value,
        [long] $MaxBytes
    )

    if ([string]::IsNullOrEmpty($Value)) {
        return
    }
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $lineText = $Value + "`n"
    $lineBytes = $utf8NoBom.GetBytes($lineText)
    [long] $currentLen = 0
    if ([System.IO.File]::Exists($FilePath)) {
        $currentLen = ([System.IO.FileInfo]::new($FilePath)).Length
    }
    if (($currentLen + $lineBytes.Length) -gt $MaxBytes) {
        return
    }
    [System.IO.File]::AppendAllText($FilePath, $lineText, $utf8NoBom)
}

function Save-DroppedActionIOCs {
    param(
        [Action] $Action,
        [string] $WorkDir
    )

    if ($null -eq $Action -or [string]::IsNullOrEmpty($WorkDir)) {
        return
    }

    if ($null -ne $Action.Behaviors -and $Action.Behaviors -contains "network" -and $null -ne $Action.BehaviorProps -and $Action.BehaviorProps.ContainsKey("uri")) {
        foreach ($rawUri in @($Action.BehaviorProps["uri"])) {
            if ($null -eq $rawUri) {
                continue
            }
            $u = [string]$rawUri
            if (-not [string]::IsNullOrEmpty($u) -and $script:BOXPS_SEEN_NET_IOCS.Add($u)) {
                $netPath = [System.IO.Path]::Combine($WorkDir, "scraped_network.txt")
                Append-BoundedIocLine -FilePath $netPath -Value $u -MaxBytes $script:BOXPS_MAX_SCRAPED_BYTES
            }
        }
    }

    if ($null -ne $Action.Behaviors -and $Action.Behaviors -contains "file_system" -and $null -ne $Action.BehaviorProps -and $Action.BehaviorProps.ContainsKey("paths")) {
        foreach ($rawPath in @($Action.BehaviorProps["paths"])) {
            if ($null -eq $rawPath) {
                continue
            }
            $p = [string]$rawPath
            if (-not [string]::IsNullOrEmpty($p) -and $script:BOXPS_SEEN_FS_IOCS.Add($p)) {
                $fsPath = [System.IO.Path]::Combine($WorkDir, "scraped_paths.txt")
                Append-BoundedIocLine -FilePath $fsPath -Value $p -MaxBytes $script:BOXPS_MAX_SCRAPED_BYTES
            }
        }
    }
}

function RecordAction {

    param(
        [Action] $Action
    )

    $wd = $WORK_DIR
    if ($null -eq $wd -or $wd -eq "") { $wd = $global:WORK_DIR }
    if ($null -eq $wd -or $wd -eq "") { $wd = "." }

    $resolvedWd = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($wd)
    $actionsPath = [System.IO.Path]::Combine($resolvedWd, "actions.json")

    $bid = if ($null -ne $Action.BehaviorId) { $Action.BehaviorId } else { "" }
    $prevCount = 0
    if ($script:BOXPS_BEHAVIOR_COUNTS.ContainsKey($bid)) {
        $prevCount = [int]$script:BOXPS_BEHAVIOR_COUNTS[$bid]
    }
    if ($prevCount -ge $script:BOXPS_MAX_REPEAT_BEHAVIOR) {
        Save-DroppedActionIOCs $Action $resolvedWd
        return
    }

    [long] $actionsSize = 0
    if ([System.IO.File]::Exists($actionsPath)) {
        $actionsSize = ([System.IO.FileInfo]::new($actionsPath)).Length
    }
    $byteLimitReached = ($actionsSize -ge $script:BOXPS_MAX_ACTIONS_BYTES)
    if ($script:BOXPS_TRUNCATED -or $script:BOXPS_ACTION_COUNT -ge $script:BOXPS_MAX_ACTIONS -or $byteLimitReached) {
        $canExemptArtifact = (Test-IsArtifactAction -Action $Action) -and `
            ($script:BOXPS_ARTIFACT_ACTION_COUNT -lt $script:BOXPS_MAX_ARTIFACT_ACTIONS) -and `
            ($actionsSize -lt ($script:BOXPS_MAX_ACTIONS_BYTES * 2))
        if ($canExemptArtifact) {
            $script:BOXPS_ARTIFACT_ACTION_COUNT++
        }
        else {
            if (-not $script:BOXPS_TRUNCATED) {
                $script:BOXPS_TRUNCATED = $true
                [Console]::Error.WriteLine("[!] box-ps action trace cap reached; truncating further action entries.")
                [System.IO.File]::WriteAllText(
                    [System.IO.Path]::Combine($resolvedWd, "actions_truncated.txt"),
                    "truncated",
                    [System.Text.UTF8Encoding]::new($false)
                )
            }
            Save-DroppedActionIOCs $Action $resolvedWd
            return
        }
    }

    $script:BOXPS_BEHAVIOR_COUNTS[$bid] = $prevCount + 1
    $script:BOXPS_ACTION_COUNT++

    # read and update the running action id on disk
    $Action.Id = [int](Microsoft.PowerShell.Management\Get-Content -Raw "$wd/action_id.txt")
    ($Action.Id + 1) | Out-File "$wd/action_id.txt"

    Harvest-ActionArtifactsAtRecordTime -Action $Action -WorkDir $resolvedWd

    $json = $Action | ConvertTo-Json -Depth 5 -Compress
    # manual_cmdlets.ps1's ConvertTo-Json startInfo branch omits -Compress; normalize to single-line NDJSON
    if ($null -ne $json -and ($json.IndexOf("`n") -ge 0 -or $json.IndexOf("`r") -ge 0)) {
        $json = ($json | Microsoft.PowerShell.Utility\ConvertFrom-Json | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 5 -Compress)
    }
    [System.IO.File]::AppendAllText($actionsPath, $json + "`n", [System.Text.UTF8Encoding]::new($false))
}

function RedirectObjectCreation {

    param(
        [string] $TypeName,
        [object[]] $ArgumentList
    )

    return Microsoft.PowerShell.Utility\New-Object -TypeName "BoxPS$($TypeName.Split(".")[-1])" -ArgumentList $ArgumentList
}

function GetOverridedClasses {
    return $BOXPS_CONFIG["Classes"].Keys | ForEach-Object { $_.ToLower() -replace "^system." }
}

<# 
process objects make the output huge and it's not that useful
just keep the string representation
#> 
function FlattenProcessObjects {

    param(
        [System.Diagnostics.Process[]] $ProcessList
    )

    $strings = @()

    $count = 0;
    while ($count -lt $ProcessList.Count) {
        $strings += $ProcessList[$count].ProcessName
        $count++
    }

    return $strings
}

Microsoft.PowerShell.Core\Import-Module -Name $CODE_DIR/ScriptInspector.psm1
Microsoft.PowerShell.Core\Import-Module -Name $CODE_DIR/HarnessBuilder.psm1