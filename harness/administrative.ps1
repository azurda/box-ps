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

        $hashed = $this.Actor
        foreach ($behaviorProp in $this.BehaviorProps.Keys) {
            $hashed += $this.BehaviorProps[$behaviorProp] | Out-String
        }

        $stringStream = [System.IO.MemoryStream]::new()
        $streamWriter = [System.IO.StreamWriter]::new($stringStream)
        $streamWriter.write($hashed)
        $streamWriter.Flush()
        $stringStream.Position = 0

        return (Get-FileHash -InputStream $stringStream -Algorithm SHA256).Hash
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

function RecordAction {

    param(
        [Action] $Action
    )

    $bid = if ($null -ne $Action.BehaviorId) { $Action.BehaviorId } else { "" }
    $prevCount = 0
    if ($script:BOXPS_BEHAVIOR_COUNTS.ContainsKey($bid)) {
        $prevCount = [int]$script:BOXPS_BEHAVIOR_COUNTS[$bid]
    }
    if ($prevCount -ge $script:BOXPS_MAX_REPEAT_BEHAVIOR) {
        return
    }

    $wd = $WORK_DIR
    if ($null -eq $wd -or $wd -eq "") { $wd = $global:WORK_DIR }
    if ($null -eq $wd -or $wd -eq "") { $wd = "." }

    $resolvedWd = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($wd)
    $actionsPath = [System.IO.Path]::Combine($resolvedWd, "actions.json")

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
            return
        }
    }

    $script:BOXPS_BEHAVIOR_COUNTS[$bid] = $prevCount + 1
    $script:BOXPS_ACTION_COUNT++

    # read and update the running action id on disk
    $Action.Id = [int](Microsoft.PowerShell.Management\Get-Content -Raw "$wd/action_id.txt")
    ($Action.Id + 1) | Out-File "$wd/action_id.txt"

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