<# known issues
    Overrides do not support wildcard arguments, so if the malicious powershell uses wildcards and the
    override goes ahead and executes the function because it's safe, it may error out (which is fine)
#>

[CmdletBinding(DefaultParameterSetName='IncludeArtifacts')]
param (
    [switch] $Docker,
    [parameter(ParameterSetName="ReportOnly", Mandatory=$true)]
    [switch] $ReportOnly,
    [parameter(Position=0)]
    [String] $InFile,
    [parameter(ValueFromPipeline=$true)]
    [String] $ScriptContent,
    [String] $EnvVar,
    [String] $EnvFile,
    [parameter(ParameterSetName="ReportOnly", Mandatory=$true)]
    [parameter(ParameterSetName="IncludeArtifacts")]
    [parameter(Position=1)]
    [String] $OutFile,
    [parameter(ParameterSetName="IncludeArtifacts")]
    [string] $OutDir,
    [switch] $NoCleanUp,
    [string] $Timeout
)

# can't give both InFile and script content
if ($ScriptContent -and $InFile) {
    [Console]::Error.WriteLine("[-] can't give both an input file and script contents")
    exit 1
}

# must give either script content or InFile
if (!$ScriptContent -and !$InFile) {
    [Console]::Error.WriteLine("[-] must give either script contents or input file")
    exit 1
}

# input file must exist if given
if ($InFile -and !(Test-Path $InFile)) {
    [Console]::Error.WriteLine("[-] input file does not exist")
    exit 3
}

# input file must be a file
if ($InFile -and (Get-Item $InFile) -is [System.IO.DirectoryInfo]) {
    [Console]::Error.WriteLine("[-] input file cannot be a directory")
    exit 3
}

# can't give both options
if ($EnvVar -and $EnvFile) {
    [Console]::Error.WriteLine("[-] can't give both a string and a file for environment variable input")
    exit 1
}

# give OutDir a default value if the user hasn't specified they don't want artifacts 
if (!$ReportOnly -and !$OutDir) {

    if ($ScriptContent) {
        $OutDir = "./script.boxed"
    }
    else {
        # by default named <script>.boxed in the current working directory
        $OutDir = "./$($InFile.Substring($InFile.LastIndexOf("/") + 1)).boxed"
    }
}

$utils = Import-Module -Name $PSScriptRoot/Utils.psm1 -AsCustomObject -Scope Local

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

function ReadBoundedText {
    param(
        [string] $Path,
        [int] $MaxChars = 262144
    )

    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if (-not [System.IO.File]::Exists($resolvedPath)) {
        return ""
    }

    $reader = [System.IO.StreamReader]::new($resolvedPath, [System.Text.Encoding]::UTF8)
    try {
        $buffer = [char[]]::new($MaxChars)
        $totalRead = 0
        while ($totalRead -lt $MaxChars) {
            $readCount = $reader.Read($buffer, $totalRead, $MaxChars - $totalRead)
            if ($readCount -le 0) {
                break
            }
            $totalRead += $readCount
        }
        return [string]::new($buffer, 0, $totalRead)
    }
    finally {
        $reader.Dispose()
    }
}

function Add-BoundedLinesToCollection {
    param(
        [string] $Path,
        [object] $Target,
        [long] $MaxBytes = 5242880
    )

    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if (-not [System.IO.File]::Exists($resolvedPath)) {
        return
    }

    $reader = [System.IO.StreamReader]::new($resolvedPath, [System.Text.Encoding]::UTF8)
    try {
        [long] $bytesRead = 0
        while ($null -ne ($line = $reader.ReadLine())) {
            $bytesRead += [System.Text.Encoding]::UTF8.GetByteCount($line) + 1
            if ($line.Length -gt 0) {
                [void]$Target.Add($line)
            }
            if ($bytesRead -ge $MaxBytes) {
                break
            }
        }
    }
    finally {
        $reader.Dispose()
    }
}

function Add-EnvProbeListItem {
    param(
        [hashtable] $Table,
        [string] $Key1,
        [string] $Key2,
        [object] $Obj
    )

    if (-not $Table.ContainsKey($Key1)) {
        $Table[$Key1] = @{}
    }
    if (-not $Table[$Key1].ContainsKey($Key2)) {
        $Table[$Key1][$Key2] = @()
    }
    $Table[$Key1][$Key2] += $Obj
}

# Isolates the script being executed in a powershell invocation. It may be written to be interpreted 
# with a cmd.exe shell and therefore does not play well with our PowerShell-interpreted 
# powershell.exe override (unquoted for the -Command flag or even cmd.exe obfuscation). Records the 
# initial action as a script execution of the code we come up with here (decoded if it was b64 
# encoded).
function HandleCmdInvocation {

    param(
        [string] $OrigScript
    )

    $OrigScript = $OrigScript.Trim()

    # matches if the powershell.exe call is right up front and it's all on a single line
    $cmdInvokePat = "^\s*[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll](\.exe)?\s+.+$"
    if (!($OrigScript | Select-String -Pattern $cmdInvokePat)) {
        return $OrigScript
    }

    $invokedScript = $null

    # if the invocation uses an encoded command, we need to decode
    # that is encoded if there's an "-e" or "-en" and there's a base64
    # string in the invocation, but not one of the other flags that
    # also start with EN.  Note that we are only interested in
    # -enc... showing up at the beginning of the pwsh, not as part of
    # a pwsh invocation run by the code to analyze later.
    $i = 100
    if ($i -gt $OrigScript.length) {
        $i = $OrigScript.length
    }
    $StartScript = $OrigScript.substring(0, $i)
    if ($StartScript -match ".*\-[Ee][NnCc][^qQnXxPp].*") {

        $match = [Regex]::Match($OrigScript, ".*?([A-Za-z0-9+/=]{40,}).*").captures
        if ($match -ne $null) {
            $invokedScript = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($match.groups[1]))
        }
    }
    else {

        # see if the script was given with the -Command option explicitely. (Must be the last argument)
        $match = ($OrigScript | Select-String -Pattern "^\s*[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll](?:\.exe)?\s+.*?-[Cc][Oo]?[Mm]?[Mm]?[Aa]?[Nn]?[Dd]?\s+(.+)$")
        if ($match) {
            $invokedScript = $match.Matches[0].Groups[1].Value
        }
        # the command used the -Command option implicitely. Scrub anything that looks like an argument 
        # flag to leave only the command
        else {

            # Delete pwsh arguments that take no parameters, they
            # confuse things.
            $OrigScript = ($OrigScript -ireplace " \-nopr?o?f?i?l?e?", "")

            # Scrub pwsh flags with arguments.
            $invokedScript = $OrigScript -replace "^\s*[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll](\.exe)?\s+((-[\w``]+\s+([\w\d``]+ )?)?)*"
        }

        # trim whitespace and unwrap any quotes around the command
        $invokedScript = $invokedScript.Trim()
        if (($invokedScript.StartsWith("`"") -and $invokedScript.EndsWith("`"")) -or 
            ($invokedScript.StartsWith("'") -and $invokedScript.EndsWith("'"))) {
            $invokedScript = $invokedScript.SubString(1,$invokedScript.Length-2)
        }

        # remove wrapping curly braces just in case this script was meant to be executed under 
        # PowerShell and is interpreting a scriptblock
        if ($invokedScript.StartsWith("{") -and $invokedScript.EndsWith("}")) {
            $invokedScript = $invokedScript.SubString(1,$invokedScript.Length-2)
        }
    }

    # TODO import administrative or something so we don't have duplicate code here it bites me every time
    # TODO parse out flags used to put them in arguments
    [hashtable] $action = @{
        "Behaviors" = @("script_exec")
        "SubBehaviors" = @("start_process")
        "Actor" = "powershell.exe"
        "Line" = ""
        "ExtraInfo" = ""
        "BehaviorProps" = @{
            "script" = $invokedScript
        }
        "Parameters" = @{}
        "Id" = 0
    }

    $hashed = "powershell.exe$invokedScript"

    $stringStream = [System.IO.MemoryStream]::new()
    $streamWriter = [System.IO.StreamWriter]::new($stringStream)
    $streamWriter.write($hashed)
    $streamWriter.Flush()
    $stringStream.Position = 0

    $action["BehaviorId"] = (Get-FileHash -InputStream $stringStream -Algorithm SHA256).Hash

    $json = $action | ConvertTo-Json -Depth 10 -Compress
    $resolvedActionsPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath("$WORK_DIR/actions.json")
    [System.IO.File]::AppendAllText($resolvedActionsPath, $json + "`n", [System.Text.UTF8Encoding]::new($false))

    return $invokedScript
}

# For some reason, some piece of the powershell codebase behind the scenes is calling my Test-Path
# override and that invocation is showing up in the actions. Haven't been able to track it down.
function Test-IsBugAction {
    param(
        [object] $Action
    )

    if ($Action.Actor -ne "Microsoft.PowerShell.Management\Test-Path") {
        return $false
    }
    if ($null -eq $Action.BehaviorProps -or $null -eq $Action.BehaviorProps.paths) {
        return $false
    }
    $paths = @($Action.BehaviorProps.paths)
    return ($paths.Count -eq 1 -and $paths[0] -eq "env:__SuppressAnsiEscapeSequences")
}

function HandleDirectlyWrittenFiles {

    # Find directly written files heuristically by looking for files
    # in the current directory whose name starts with 'C:' (not
    # expected for Linux files).
    $outDir = $WORK_DIR + "/untracked_artifacts/"
    foreach ($payloadFile in (Get-ChildItem -path "." -name "C:*")) {

        # Does this look like a bogus "C:\foo\bar\baz" file we can
        # move as an artifact?
        $fileObj= ([type]"IO.File")
        if ($payloadFile.contains("\")){

            # Make the directory for saving the file writes that are
            # not tracked in the regular analysis.
            if (-not (Test-Path -Path $outDir)) {
                New-Item -Path $outDir -ItemType "directory" > /dev/null 2>&1
            }
            
            # Get the name (no path) of the file.
            $fname = $payloadFile.SubString($payloadFile.lastIndexOf("\") + 1)

            # Move the file to the artifact directory.
            $fileObj::Move($payloadFile, ($outDir + $fname), $true)
        }

        # Not an obvious bogus C: file. Just delete it.
        else {
            Remove-Item $payloadFile
        }
    }
}

# extracts artifacts from a single action, writes them to disk, and updates $ArtifactMap
function HarvestSingleActionArtifacts {
    param(
        [object] $Action,
        [string] $ArtifactsDir,
        [hashtable] $ArtifactMap
    )

    $behaviorMap = @{
        "write_to_memory" = "bytes";
        "file_write" = "content";
        "binary_import" = "bytes";
    }

    $actionBehaviors = @()
    if ($null -ne $Action.Behaviors) { $actionBehaviors += $Action.Behaviors }
    if ($null -ne $Action.SubBehaviors) { $actionBehaviors += $Action.SubBehaviors }

    if ($null -eq $Action.BehaviorProps) {
        return
    }

    foreach ($behavior in $behaviorMap.Keys) {
        if ($actionBehaviors -notcontains $behavior) {
            continue
        }

        $artifactProperty = $behaviorMap[$behavior]
        $artifactContent = $Action.BehaviorProps."$artifactProperty"
        if ($null -eq $artifactContent) {
            continue
        }

        # Could have a single element list where the content is
        # actually the string in the list. Check for that.
        $artifactIsArray = $artifactContent.GetType().BaseType.Name -eq "Array"
        if ($artifactIsArray -and ($artifactContent.Length -eq 1) -and ($null -ne $artifactContent[0]) -and ($artifactContent[0].GetType().Name -eq "String")) {
            $artifactIsArray = $false
            $artifactContent = $artifactContent[0]
        }

        if ($artifactContent.Length -le 10) {
            continue
        }

        $actionId = ($Action.Id | Out-String).Trim()
        $fileType = "unknown"
        $outPath = [System.IO.Path]::Combine($ArtifactsDir, "tmp.bin")

        try {
            # array content means bytes, assuming we'll never have an array of chars
            if ($artifactIsArray) {
                [System.IO.File]::WriteAllBytes($outPath, $artifactContent)
            }
            # content is just text
            else {
                $artifactContent | Out-File $outPath
            }
        }
        catch {
            [Console]::Error.WriteLine("[-] error writing artifact to disk from action ID $actionId : $($_.Exception)")
            continue
        }

        $sha256 = (Get-FileHash -Path $outPath -Algorithm SHA256).Hash
        Move-Item -Path $outPath -Destination ([System.IO.Path]::Combine($ArtifactsDir, $sha256)) -Force

        # check if the bytes indicate a PE file
        if ($artifactIsArray -and $artifactContent[0] -eq 77 -and $artifactContent[1] -eq 90) {
            $fileType = "PE"
        }

        if (-not $ArtifactMap.Contains($actionId)) {
            $ArtifactMap[$actionId] = @()
        }

        $ArtifactMap[$actionId] += @{
            "sha256" = $sha256;
            "fileType" = $fileType
        }
    }
}

function Update-ActionIndicatorsAndProbes {
    param(
        [object] $Action,
        [System.Collections.Generic.HashSet[string]] $PathsSet,
        [System.Collections.Generic.HashSet[string]] $NetworkSet,
        [hashtable] $EnvReport
    )

    $behaviors = @()
    if ($null -ne $Action.Behaviors) { $behaviors = @($Action.Behaviors) }
    $subBehaviors = @()
    if ($null -ne $Action.SubBehaviors) { $subBehaviors = @($Action.SubBehaviors) }

    if ($behaviors -contains "file_system" -and $null -ne $Action.BehaviorProps -and $null -ne $Action.BehaviorProps.paths) {
        foreach ($p in @($Action.BehaviorProps.paths)) {
            if ($null -ne $p) {
                [void]$PathsSet.Add([string]$p)
            }
        }
    }

    if ($behaviors -contains "network" -and $null -ne $Action.BehaviorProps -and $null -ne $Action.BehaviorProps.uri) {
        foreach ($u in @($Action.BehaviorProps.uri)) {
            if ($null -ne $u) {
                [void]$NetworkSet.Add([string]$u)
            }
        }
    }

    if ($behaviors -contains "environment_probe") {
        if ($subBehaviors -contains "probe_language") {
            Add-EnvProbeListItem -Table $EnvReport -Key1 "Language" -Key2 "Actors" -Obj $Action.Actor
        }
        elseif ($subBehaviors -contains "probe_host") {
            Add-EnvProbeListItem -Table $EnvReport -Key1 "Host" -Key2 "Actors" -Obj $Action.Actor
        }
        elseif ($subBehaviors -contains "probe_date") {
            Add-EnvProbeListItem -Table $EnvReport -Key1 "Date" -Key2 "Actors" -Obj $Action.Actor
        }
    }
}

function Test-IsArtifactActionObj {
    param(
        [object] $Action
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

function Get-CompactedActionJson {
    param(
        [object] $Action,
        [string] $RawJsonLine
    )

    if ($RawJsonLine.Length -le 65536) {
        return $RawJsonLine
    }

    $compacted = $false
    $maxStringChars = 16384

    if ($null -ne $Action.BehaviorProps) {
        foreach ($propName in @("bytes", "content")) {
            $prop = $Action.BehaviorProps.PSObject.Properties[$propName]
            if ($null -eq $prop -or $null -eq $prop.Value) {
                continue
            }
            $val = $prop.Value
            if ($val -is [System.Array] -and $val.Length -gt 8192) {
                $prop.Value = "<truncated: $($val.Length) bytes; harvested as artifact>"
                $compacted = $true
            }
            elseif ($val -is [string] -and $val.Length -gt 8192) {
                $prop.Value = "<truncated: $($val.Length) bytes; harvested as artifact>"
                $compacted = $true
            }
        }

        foreach ($prop in $Action.BehaviorProps.PSObject.Properties) {
            $val = $prop.Value
            if ($val -is [string] -and $val.Length -gt $maxStringChars) {
                $prop.Value = $val.Substring(0, $maxStringChars) + "... <truncated: $($val.Length) chars>"
                $compacted = $true
            }
        }
    }

    if ($null -ne $Action.Parameters) {
        foreach ($paramProp in $Action.Parameters.PSObject.Properties) {
            $val = $paramProp.Value
            if ($null -eq $val) {
                continue
            }
            if ($val -is [System.Array] -and $val.Length -gt 8192) {
                $paramProp.Value = "<truncated: $($val.Length) bytes; harvested as artifact>"
                $compacted = $true
            }
            elseif ($val -is [string] -and $val.Length -gt 8192 -and $paramProp.Name -in @("bytes", "content", "contents", "Value")) {
                $paramProp.Value = "<truncated: $($val.Length) bytes; harvested as artifact>"
                $compacted = $true
            }
            elseif ($val -is [string] -and $val.Length -gt $maxStringChars) {
                $paramProp.Value = $val.Substring(0, $maxStringChars) + "... <truncated: $($val.Length) chars>"
                $compacted = $true
            }
            elseif ($val -is [System.Array]) {
                for ($i = 0; $i -lt $val.Length; $i++) {
                    if ($val[$i] -is [string] -and $val[$i].Length -gt $maxStringChars) {
                        $val[$i] = $val[$i].Substring(0, $maxStringChars) + "... <truncated: $($val[$i].Length) chars>"
                        $compacted = $true
                    }
                }
            }
        }
    }

    if ($compacted) {
        $depth = if ($Action.Actor -eq "powershell.exe") { 10 } else { 5 }
        return ($Action | ConvertTo-Json -Depth $depth -Compress)
    }

    return $RawJsonLine
}

function Write-StreamingReport {
    param(
        [string] $WorkDir,
        [string] $ActionsPath,
        [string] $ReportOutPath,
        [long] $MaxReportActions
    )

    $artifactsDir = "$WorkDir/artifacts"
    New-Item -Path $artifactsDir -ItemType "directory" > $null 2>&1
    $resolvedArtifactsDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($artifactsDir)

    # Hacky handling for files directly written via obfuscated .NET
    # object calls (box-ps can't override these methods so they actually run).
    HandleDirectlyWrittenFiles

    $artifactMap = @{}
    $pathsSet = [System.Collections.Generic.HashSet[string]]::new()
    $networkSet = [System.Collections.Generic.HashSet[string]]::new()
    $envReport = @{}

    $resolvedActionsPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ActionsPath)
    $resolvedReportPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReportOutPath)
    $maxArtifactActions = Get-BoxPSPositiveIntEnv -Name "BOXPS_MAX_ARTIFACT_ACTIONS" -Default 100

    $writer = [System.IO.StreamWriter]::new($resolvedReportPath, $false, [System.Text.UTF8Encoding]::new($false))
    try {
        $writer.Write('{"Actions":[')
        $firstAction = $true
        [long] $writtenActions = 0
        [long] $writtenArtifactActions = 0

        if ([System.IO.File]::Exists($resolvedActionsPath)) {
            $reader = [System.IO.StreamReader]::new($resolvedActionsPath, [System.Text.Encoding]::UTF8)
            try {
                while ($null -ne ($rawLine = $reader.ReadLine())) {
                    $trimmed = $rawLine.Trim()
                    if ($trimmed.EndsWith(",")) {
                        $trimmed = $trimmed.Substring(0, $trimmed.Length - 1).TrimEnd()
                    }
                    if ([string]::IsNullOrEmpty($trimmed)) {
                        continue
                    }

                    $action = $null
                    try {
                        $action = $trimmed | ConvertFrom-Json
                    }
                    catch {
                        [Console]::Error.WriteLine("[!] box-ps skipping malformed action entry: $($_.Exception.Message)")
                        continue
                    }
                    if ($null -eq $action) {
                        continue
                    }

                    if (Test-IsBugAction -Action $action) {
                        continue
                    }

                    # Harvest artifacts before compacting oversized properties in memory
                    HarvestSingleActionArtifacts -Action $action -ArtifactsDir $resolvedArtifactsDir -ArtifactMap $artifactMap
                    Update-ActionIndicatorsAndProbes -Action $action -PathsSet $pathsSet -NetworkSet $networkSet -EnvReport $envReport

                    $emitAction = $false
                    if ($writtenActions -lt $MaxReportActions) {
                        $emitAction = $true
                        $writtenActions++
                    }
                    elseif ((Test-IsArtifactActionObj -Action $action) -and $writtenArtifactActions -lt $maxArtifactActions) {
                        $emitAction = $true
                        $writtenArtifactActions++
                    }

                    if ($emitAction) {
                        $lineToWrite = Get-CompactedActionJson -Action $action -RawJsonLine $trimmed
                        if (-not $firstAction) {
                            $writer.Write(",")
                        }
                        $writer.Write($lineToWrite)
                        $firstAction = $false
                    }
                }
            }
            finally {
                $reader.Dispose()
            }
        }

        $writer.Write("]")

        $maxScrapedBytes = Get-BoxPSPositiveIntEnv -Name "BOXPS_MAX_SCRAPED_BYTES" -Default 5242880
        Add-BoundedLinesToCollection -Path "$WorkDir/scraped_network.txt" -Target $networkSet -MaxBytes $maxScrapedBytes
        Add-BoundedLinesToCollection -Path "$WorkDir/scraped_paths.txt" -Target $pathsSet -MaxBytes $maxScrapedBytes

        $probesSet = [System.Collections.Generic.HashSet[string]]::new()
        Add-BoundedLinesToCollection -Path "$WorkDir/scraped_probes.txt" -Target $probesSet -MaxBytes $maxScrapedBytes

        $operatorMap = @{
            "NULL" = "unknown";
            "eq" = "equals";
            "ne" = "not equals"
        }
        foreach ($probeStr in $probesSet) {
            $split = $probeStr.Split(",")
            if ($split.Length -ge 3) {
                $probe = @{
                    "Value" = $split[1];
                    "Operator" = $operatorMap[$split[2]]
                }
                if ($split[0] -eq "language") {
                    Add-EnvProbeListItem -Table $envReport -Key1 "Language" -Key2 "Checks" -Obj $probe
                }
                elseif ($split[0] -eq "host") {
                    Add-EnvProbeListItem -Table $envReport -Key1 "Host" -Key2 "Checks" -Obj $probe
                }
                elseif ($split[0] -eq "date") {
                    Add-EnvProbeListItem -Table $envReport -Key1 "Date" -Key2 "Checks" -Obj $probe
                }
            }
        }

        $potentialArtifactsList = [System.Collections.Generic.List[string]]::new()
        Add-BoundedLinesToCollection -Path "$WorkDir/in_mem_pes.txt" -Target $potentialArtifactsList -MaxBytes $maxScrapedBytes

        $networkJson = ConvertTo-Json -InputObject ([string[]]$networkSet) -Depth 2 -Compress
        $pathsJson = ConvertTo-Json -InputObject ([string[]]$pathsSet) -Depth 2 -Compress
        $envReportJson = ConvertTo-Json -InputObject $envReport -Depth 5 -Compress
        $artifactsJson = ConvertTo-Json -InputObject $artifactMap -Depth 5 -Compress
        $potentialArtifactsJson = ConvertTo-Json -InputObject ([string[]]$potentialArtifactsList) -Depth 2 -Compress
        $workingDirJson = ConvertTo-Json -InputObject $WorkDir -Compress

        $writer.Write(",`"PotentialIndicators`":{`"network`":$networkJson,`"file_system`":$pathsJson}")
        $writer.Write(",`"EnvironmentProbes`":$envReportJson")
        $writer.Write(",`"Artifacts`":$artifactsJson")
        $writer.Write(",`"PotentialArtifacts`":$potentialArtifactsJson")
        $writer.Write(",`"WorkingDir`":$workingDirJson")
        $writer.Write("}")
        $writer.Flush()
    }
    finally {
        $writer.Dispose()
    }
}

# clean up working directory if desired, remove imported modules, and exit with a code
function CleanExit {
    
    param(
        [bool] $NoCleanUp,
        [int] $ExitCode,
        [string] $WorkDir
    )

    if (!$NoCleanUp) {
        Remove-Item -Recurse $WorkDir -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "[+] Keeping working dir $WorkDir ..."
    }

    Remove-Module HarnessBuilder -ErrorAction SilentlyContinue
    Remove-Module ScriptInspector -ErrorAction SilentlyContinue
    Remove-Module Utils -ErrorAction SilentlyContinue

    exit $ExitCode
}

# Use the current PID to give each box-ps run a unique working directory.
# This allows multiple box-ps instances to analyze samples in the same directory.
$WORK_DIR = "./working_" + $PID

# pull down the box-ps docker container and run it in there
if ($Docker) {

    # test to see if docker is installed. EXIT IF NOT
    try {
        $output = docker ps 2>&1
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        [Console]::Error.WriteLine("[-] docker is not installed. install it and add your user to the docker group")
        exit 2
    }

    # some other error with docker. EXIT
    if ($output -and $output.GetType().Name -eq "ErrorRecord") {
        $msg = $output.Exception.Message
        if ($msg.Contains("Got permission denied")) {
            [Console]::Error.WriteLine("[-] permissions incorrect. add your user to the docker group")
        }
        [Console]::Error.WriteLine("[-] there's a problem with your docker environment...")
        [Console]::Error.WriteLine($msg)
        exit 2
    }

    # validate that the input environment variable file exists if given
    if ($EnvFile -and !(Test-Path $EnvFile)) {
        [Console]::Error.WriteLine("[-] input environment variable file doesn't exist. exiting.")
        exit 3
    }

    Write-Host "[+] pulling latest docker image"
    docker pull connorshride/box-ps:latest > $null
    #docker pull connorshride/box-ps:develop > $null 
    Write-Host "[+] starting docker container"
    docker run -td --network none connorshride/box-ps:latest > $null
    #docker run -td --network none connorshride/box-ps:develop > $null

    # get the ID of the container we just started
    $psOutput = docker ps -f status=running -f ancestor=connorshride/box-ps -l
    #$psOutput=$(docker ps -f status=running -f ancestor=connorshride/box-ps:develop -l)

    $idMatch = $psOutput | Select-String -Pattern "[\w]+_[\w]+"
    $containerId = $idMatch.Matches.Value

    # modify args to those that the container should receive

    $PSBoundParameters.Remove("Docker") > $null

    # copy the input file into the container
    $PSBoundParameters["InFile"] = "./infile.ps1"
    if ($InFile) {
        docker cp $InFile "$containerId`:/opt/box-ps/infile.ps1"
    }
    # given script contents instead
    else {
        
        # pipe the script contents into a file in the container
        $ScriptContent | docker exec -i $containerId /bin/bash -c "cat - > /opt/box-ps/infile.ps1"
        $PSBoundParameters.Remove("ScriptContent") > $null
    }

    # TODO same error handling as below so we pass through return codes

    # just keep all the input/output files in the box-ps dir in the container
    if ($OutFile) {
        $PSBoundParameters["OutFile"] = "./out.json"
    }

    if ($OutDir) {
        $PSBoundParameters["OutDir"] = "./outdir"
    }

    if ($EnvFile) {
        $PSBoundParameters["EnvFile"] = "./input_env.json"
        docker cp $EnvFile "$containerId`:/opt/box-ps/input_env.json"
    }

    Write-Host "[+] running box-ps in container"
    docker exec $containerId pwsh /opt/box-ps/box-ps.ps1 @PSBoundParameters

    if ($OutFile) {
        docker cp "$containerId`:/opt/box-ps/out.json" $OutFile
    }

    if ($OutDir) {

        if (Test-Path $OutDir) {
            Remove-Item -Recurse $OutDir
        }

        # attempt to copy the output dir in the container back out to the host
        $output = docker cp "$containerId`:/opt/box-ps/outdir" $OutDir 2>&1
        $output = $output | Out-String
        if ($output.Contains("Error") -and $output.Contains("No such container:path")) {
            [Console]::Error.WriteLine("[-] no output directory produced in container")
        }
    }

    # clean up
    docker kill $containerId > $null
}
# do sandboxing
else {

    $stderrPath = "$WORK_DIR/stderr.txt"
    $stdoutPath = "$WORK_DIR/stdout.txt"
    $actionsPath = "$WORK_DIR/actions.json"
    $harnessedScriptPath = "$WORK_DIR/harnessed_script.ps1"

    # create working directory to store
    if (Test-Path $WORK_DIR) {
        Remove-Item -Force $WORK_DIR/*
    }
    else {
        New-Item $WORK_DIR -ItemType Directory > $null
    }

    # init working directory files
    "1" | Out-File $WORK_DIR/action_id.txt
    New-Item $WORK_DIR/actions.json > $null

    Import-Module -Name $PSScriptRoot/HarnessBuilder.psm1
    Import-Module -Name $PSScriptRoot/ScriptInspector.psm1

    # read script content from the input file
    if ($InFile) {
        Write-Host -NoNewLine "[+] reading script..."
        $ScriptContent = (Get-Content $InFile -ErrorAction Stop | Out-String)
        $ScriptContent = HandleCmdInvocation $ScriptContent
        Write-Host " done"
    }

    # write out string environment variable to JSON for harness builder
    if ($EnvVar) {

        # validate that it's in the right form <var_name>=<var_value>
        if (!$EnvVar.Contains("=")) {
            [Console]::Error.WriteLine("[-] no equals sign in environment variable string")
            [Console]::Error.WriteLine("[-] USAGE <var_name>=<value>")
            CleanExit -NoCleanUp $NoCleanUp -WorkDir $WORK_DIR -ExitCode 1
        }

        $name = $EnvVar[0..($EnvVar.IndexOf("="))] -join ''
        $value = $EnvVar[($EnvVar.IndexOf("=")+1)..($EnvVar.Length-1)] -join ''
        $varObj = @{
            $name = $value
        }
        $varObj | ConvertTo-Json | Out-File $WORK_DIR/input_env.json
    }

    # copy the given json file where the harness builder expects it
    elseif ($EnvFile) {

        # validate the file exists
        if (!(Test-Path $EnvFile)) {
            [Console]::Error.WriteLine("[-] input environment variable file doesn't exist. exiting.")
            CleanExit -NoCleanUp $NoCleanUp -WorkDir $WORK_DIR -ExitCode 3
        }
        else {

            # validate it's in valid JSON
            $envFileContent = Get-Content $EnvFile -Raw
            try {
                $envFileContent | ConvertFrom-Json -AsHashTable | Out-Null
            }
            catch {
                [Console]::Error.WriteLine("[-] input environment variable file $EnvFile is not formatted in valid JSON. exiting")
                CleanExit -NoCleanUp $NoCleanUp -WorkDir $WORK_DIR -ExitCode 1
            }

            $envFileContent | Out-File $WORK_DIR/input_env.json
        }
    }

    Write-Host -NoNewLine "[+] building script harness..."

    # build harness and integrate script with it
    $harness = (BuildHarness).Replace("<CODE_DIR>", $PSScriptRoot).Replace("<PID>", $PID)
    $ScriptContent = PreProcessScript $ScriptContent $PID

    # attach the harness to the script
    $harnessedScript = $harness + "`r`n`r`n" + $ScriptContent
    $harnessedScript | Out-File -FilePath $harnessedScriptPath

    Write-Host " done"
    Write-Host -NoNewLine "[+] sandboxing harnessed script..."

    # Run sandboxed script via ProcessStartInfo.ArgumentList (avoids Start-Process space-splitting bugs
    # and drains stdout/stderr streams asynchronously so pipes never deadlock).
    $resolvedStdoutPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($stdoutPath)
    $resolvedStderrPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($stderrPath)
    $resolvedHarnessedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($harnessedScriptPath)

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $ExecutionContext.SessionState.Path.CurrentFileSystemLocation.ProviderPath

    if ($Timeout) {
        $psi.FileName = "timeout"
        [void]$psi.ArgumentList.Add("--foreground")
        [void]$psi.ArgumentList.Add($Timeout)
        [void]$psi.ArgumentList.Add("pwsh")
        [void]$psi.ArgumentList.Add("-noni")
        [void]$psi.ArgumentList.Add($resolvedHarnessedPath)
    }
    else {
        $psi.FileName = "pwsh"
        [void]$psi.ArgumentList.Add("-noni")
        [void]$psi.ArgumentList.Add($resolvedHarnessedPath)
    }

    $proc = $null
    $stdoutFs = $null
    $stderrFs = $null
    $innerExitCode = -1
    $startError = $null
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
        if ($null -eq $proc) {
            throw "Process.Start returned null for $($psi.FileName)"
        }
        $stdoutFs = [System.IO.FileStream]::new($resolvedStdoutPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        $stderrFs = [System.IO.FileStream]::new($resolvedStderrPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)

        $stdoutTask = $proc.StandardOutput.BaseStream.CopyToAsync($stdoutFs)
        $stderrTask = $proc.StandardError.BaseStream.CopyToAsync($stderrFs)

        $proc.WaitForExit()
        [void]$stdoutTask.GetAwaiter().GetResult()
        [void]$stderrTask.GetAwaiter().GetResult()
        $innerExitCode = $proc.ExitCode
    }
    catch {
        $startError = $_.Exception.Message
    }
    finally {
        if ($null -ne $stdoutFs) { $stdoutFs.Dispose() }
        if ($null -ne $stderrFs) { $stderrFs.Dispose() }
        if ($null -ne $proc) { $proc.Dispose() }
    }

    if ($null -ne $startError) {
        [Console]::Error.WriteLine("[-] sandboxing failed: unable to execute sandboxed process: $startError")
        CleanExit -NoCleanUp $NoCleanUp -WorkDir $WORK_DIR -ExitCode 4
    }

    Write-Host " done"

    # check for some indicators of sandboxing failure
    $stderr = ReadBoundedText -Path $stderrPath -MaxChars 262144
    $fail = $false
    $errorReason = ""
    $errorCode = 4

    # detect some critical errors from the exit code and stderr of the sandbox process
    if ($innerExitCode -eq 124) {
        $fail = $true
        $errorReason = "sandboxing timed out"
        $errorCode = 124
    }
    elseif ($innerExitCode -in @(125, 126, 127)) {
        $fail = $true
        $errorReason = "sandbox timeout wrapper failed (exit code $innerExitCode)"
        $errorCode = $innerExitCode
    }
    elseif ($null -ne $stderr -and $stderr.Contains("OutOfMemoryException")) {
        $fail = $true
        $errorReason = "sandboxed process ran out of memory"
        $errorCode = 137
    }
    elseif ($innerExitCode -gt 128) {
        $fail = $true
        $errorReason = "sandboxed process terminated by signal (exit code $innerExitCode)"
        $errorCode = $innerExitCode
    }
    elseif ($null -ne $stderr -and $stderr.Contains("ParserError: ")) {
        [Console]::Error.WriteLine("[!] parser error encountered in sample; proceeding with extracted layers and indicators")
    }

    # print error and exit
    if ($fail) {
        [Console]::Error.WriteLine("[-] sandboxing failed: $errorReason...")
        [Console]::Error.WriteLine($stderr)
        CleanExit -NoCleanUp $NoCleanUp -WorkDir $WORK_DIR -ExitCode $errorCode
    }

    Write-Host -NoNewLine "[+] post-processing results..."

    $maxReportActions = Get-BoxPSPositiveIntEnv -Name "BOXPS_MAX_ACTIONS" -Default 2000
    $reportTmpPath = "$WORK_DIR/report.json"
    Write-StreamingReport -WorkDir $WORK_DIR -ActionsPath $actionsPath -ReportOutPath $reportTmpPath -MaxReportActions $maxReportActions

    Write-Host " done"

    # user wants more detailed artifacts as well as the report
    if ($OutDir) {

        # overwrite output dir if it already exists
        if (Test-Path $OutDir) {
            Remove-Item -Recurse $OutDir/*
        }
        else {
            New-Item $OutDir -ItemType Directory > $null
        }

        # move some stuff from working directory here
        Move-Item $WORK_DIR/stdout.txt $OutDir/
        Move-Item $WORK_DIR/stderr.txt $OutDir/
        Move-Item $WORK_DIR/layers.ps1 $OutDir/

        if ($(Test-Path $WORK_DIR/artifacts) -and $(Get-ChildItem $WORK_DIR/artifacts).Length -gt 0) {
            Move-Item $WORK_DIR/artifacts $OutDir
        }
        if ($(Test-Path $WORK_DIR/untracked_artifacts) -and $(Get-ChildItem $WORK_DIR/untracked_artifacts).Length -gt 0) {
            Move-Item $WORK_DIR/untracked_artifacts $OutDir
        }

        $outReportPath = Join-Path $OutDir "report.json"
        Move-Item -Path $reportTmpPath -Destination $outReportPath -Force

        if ($OutFile) {
            $resolvedOutFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
            $resolvedOutReport = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($outReportPath)
            if ($resolvedOutFile -ne $resolvedOutReport) {
                Copy-Item -Path $outReportPath -Destination $OutFile -Force
            }
        }
    }
    elseif ($OutFile) {
        Copy-Item -Path $reportTmpPath -Destination $OutFile -Force
    }

    CleanExit -NoCleanUp $NoCleanUp -WorkDir $WORK_DIR -ExitCode 0
}
