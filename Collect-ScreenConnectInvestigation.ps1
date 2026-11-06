#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Collects local Windows evidence for a suspected unauthorized ScreenConnect instance.
.DESCRIPTION
Exports retained Windows event logs and snapshots services, processes, and TCP
connections. ScreenConnect/ConnectWise matches are also saved separately.
The script runs locally, makes no network requests, copies no executable samples,
and does not stop services, remove software, scan for malware, or change auditing.
It creates evidence files only. It does not determine whether a machine is clean.
Evidence can contain sensitive account information and command lines. Protect the
output folder and move a verified copy to your approved evidence storage.
.PARAMETER OutputRoot
Existing or new local drive directory under which a unique case folder is created.
Defaults to ProgramData. UNC paths, mapped network drives, and existing reparse
point ancestors are rejected. The new case folder permits SYSTEM and local
Administrators only; collection stops if its ACL cannot be applied. Use a local
filesystem that supports Windows ACLs. Allow space for complete EVTX logs.
.EXAMPLE
.\Collect-ScreenConnectInvestigation.ps1
.EXAMPLE
.\Collect-ScreenConnectInvestigation.ps1 -OutputRoot 'D:\IncidentEvidence'
.NOTES
Requires an elevated Windows PowerShell 5.1 or later session on Windows.
Collect through approved incident response procedures. Running this script changes
local activity and creates files; it is not a forensic disk or memory acquisition.
Offline collection cannot retrieve historical EDR, firewall, DNS, or cloud records.
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$OutputRoot = $env:ProgramData
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$scriptVersion = '1.0.0'
$startedUtc = [DateTime]::UtcNow
$statusRows = New-Object 'System.Collections.Generic.List[object]'

function Add-CollectionStatus {
    param(
        [string]$Item, [bool]$Required, [string]$Status,
        [string]$File = '', [object]$Count = $null, [string]$Details = ''
    )
    $statusRows.Add([pscustomobject][ordered]@{
        TimeUtc = [DateTime]::UtcNow.ToString('o')
        Item = $Item; Required = $Required; Status = $Status
        File = $File; Count = $Count; Details = $Details
    })
}

function Save-CsvSnapshot {
    param([object[]]$Rows, [string[]]$Columns, [string]$FilePath)
    if ($null -ne $Rows -and $Rows.Count -gt 0) {
        $Rows | Select-Object -Property $Columns |
            Export-Csv -LiteralPath $FilePath -NoTypeInformation -Encoding UTF8
    }
    else {
        # Export-Csv alone cannot retain column headers for an empty result.
        $emptyRow = [ordered]@{}
        foreach ($column in $Columns) { $emptyRow[$column] = $null }
        $header = ([pscustomobject]$emptyRow | ConvertTo-Csv -NoTypeInformation)[0]
        Set-Content -LiteralPath $FilePath -Value $header -Encoding UTF8
    }
}

# Accept only an absolute drive path. Refuse ambiguous/network-backed destinations.
if ($env:OS -ne 'Windows_NT') { throw 'This collector requires Windows.' }
if ($OutputRoot -notmatch '^[A-Za-z]:[\\/]') {
    throw 'OutputRoot must be a fully qualified local drive path, such as D:\IncidentEvidence.'
}
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$driveId = $OutputRoot.Substring(0, 2)
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$driveId'"
if ($null -eq $disk -or $disk.DriveType -notin @(2, 3, 6)) {
    throw 'OutputRoot must be on a local fixed, removable, or RAM drive; network/unknown drives are rejected.'
}
$ancestor = $OutputRoot
while ($ancestor) {
    if (Test-Path -LiteralPath $ancestor) {
        $entry = Get-Item -LiteralPath $ancestor -Force
        if (-not $entry.PSIsContainer) { throw "Not a directory: $ancestor" }
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Reparse point destinations are rejected: $ancestor"
        }
    }
    $ancestor = [IO.Path]::GetDirectoryName($ancestor.TrimEnd('\', '/'))
}
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
$caseName = 'IR-{0}-{1}-{2}' -f $env:COMPUTERNAME,
    (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
$caseDir = Join-Path $OutputRoot $caseName
New-Item -ItemType Directory -Path $caseDir | Out-Null
# Restrict only this new evidence folder before collecting potentially sensitive data.
$caseAcl = [Security.AccessControl.DirectorySecurity]::new()
$caseAcl.SetAccessRuleProtection($true, $false)
foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544')) {
    $sid = [Security.Principal.SecurityIdentifier]::new($sidValue)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $sid, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow)
    $caseAcl.AddAccessRule($rule)
}
$caseAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
Set-Acl -LiteralPath $caseDir -AclObject $caseAcl
Write-Host "Collecting local evidence into: $caseDir"

$metadata = [ordered]@{
    ScriptVersion = $scriptVersion
    ScriptPath = $PSCommandPath
    CollectorProcessId = $PID
    ComputerName = $env:COMPUTERNAME
    UserName = "$env:USERDOMAIN\$env:USERNAME"
    UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    CollectionStartUtc = $startedUtc.ToString('o')
    CollectionEndUtc = $null
    TimeZoneId = [TimeZoneInfo]::Local.Id
    UtcOffsetAtStart = [TimeZoneInfo]::Local.GetUtcOffset([DateTime]::Now).ToString()
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    OutputDirectory = $caseDir
    RequiredCollectionComplete = $false
    RequiredFailureCount = $null
    Notes = 'RequiredCollectionComplete covers required inventories and log exports only. Review optional statuses and the hash manifest separately. No matches or missing events do not establish absence of compromise.'
}
$metadataPath = Join-Path $caseDir 'Collection-Metadata.json'
$metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $metadataPath -Encoding UTF8

# Capture volatile/current inventories before the potentially slower log exports.
try {
    $services = @(Get-CimInstance Win32_Service)
    $columns = @('Name', 'DisplayName', 'State', 'StartMode', 'StartName', 'ProcessId', 'PathName')
    Save-CsvSnapshot $services $columns (Join-Path $caseDir 'Services-All.csv')
    Add-CollectionStatus 'Service inventory' $true 'Collected' 'Services-All.csv' $services.Count
    $serviceMatches = @($services | Where-Object {
        $_.Name -match 'ScreenConnect|ConnectWise' -or
        $_.DisplayName -match 'ScreenConnect|ConnectWise' -or
        $_.PathName -match 'ScreenConnect|ConnectWise'
    })
    Save-CsvSnapshot $serviceMatches $columns (Join-Path $caseDir 'Services-ScreenConnectMatches.csv')
    $matchStatus = if ($serviceMatches.Count) { 'MatchesFound' } else { 'NoMatches' }
    Add-CollectionStatus 'Matching services' $true $matchStatus `
        'Services-ScreenConnectMatches.csv' $serviceMatches.Count 'String matches are investigation leads, not an authorization or cleanliness verdict.'
}
catch {
    Add-CollectionStatus 'Service inventory/matches' $true 'Failed' '' $null $_.Exception.Message
}

try {
    $processProperties = @(
        'Name', 'ProcessId', 'ParentProcessId', 'ExecutablePath', 'CommandLine',
        @{Name = 'CreationTimeUtc'; Expression = {
            if ($_.CreationDate) { ([DateTime]$_.CreationDate).ToUniversalTime().ToString('o') }
        }}
    )
    $processes = @(Get-CimInstance Win32_Process | Select-Object -Property $processProperties)
    $columns = @('Name', 'ProcessId', 'ParentProcessId', 'CreationTimeUtc', 'ExecutablePath', 'CommandLine')
    Save-CsvSnapshot $processes $columns (Join-Path $caseDir 'Processes-All.csv')
    Add-CollectionStatus 'Process inventory' $true 'Collected' 'Processes-All.csv' $processes.Count `
        'Some protected processes can have blank path or command-line fields. This is a point-in-time snapshot.'
    $processMatches = @($processes | Where-Object {
        $_.Name -match 'ScreenConnect|ConnectWise' -or
        $_.ExecutablePath -match 'ScreenConnect|ConnectWise' -or
        $_.CommandLine -match 'ScreenConnect|ConnectWise'
    })
    Save-CsvSnapshot $processMatches $columns (Join-Path $caseDir 'Processes-ScreenConnectMatches.csv')
    $matchStatus = if ($processMatches.Count) { 'MatchesFound' } else { 'NoMatches' }
    Add-CollectionStatus 'Matching processes' $true $matchStatus `
        'Processes-ScreenConnectMatches.csv' $processMatches.Count 'The collector may match because its filename contains ScreenConnect; see CollectorProcessId. Renamed files and unrelated child processes can be missed.'
}
catch {
    Add-CollectionStatus 'Process inventory/matches' $true 'Failed' '' $null $_.Exception.Message
}

try {
    $connections = @(Get-NetTCPConnection)
    $columns = @('State', 'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort', 'OwningProcess')
    Save-CsvSnapshot $connections $columns (Join-Path $caseDir 'TCP-Connections.csv')
    Add-CollectionStatus 'TCP connections' $false 'Collected' 'TCP-Connections.csv' $connections.Count `
        'Current TCP state only. Connections may have ended or disappeared after isolation; PIDs can be reused.'
}
catch {
    Add-CollectionStatus 'TCP connections' $false 'Failed' '' $null $_.Exception.Message
}

$channels = @(
    @{ Name = 'System'; File = 'System.evtx'; Required = $true }
    @{ Name = 'Security'; File = 'Security.evtx'; Required = $true }
    @{ Name = 'Application'; File = 'Application.evtx'; Required = $true }
    @{ Name = 'Microsoft-Windows-PowerShell/Operational'; File = 'PowerShell.evtx'; Required = $true }
    @{ Name = 'Windows PowerShell'; File = 'Windows-PowerShell.evtx'; Required = $false }
    @{ Name = 'Microsoft-Windows-Windows Defender/Operational'; File = 'Defender.evtx'; Required = $false }
    @{ Name = 'Microsoft-Windows-TaskScheduler/Operational'; File = 'TaskScheduler.evtx'; Required = $false }
    @{ Name = 'Microsoft-Windows-WMI-Activity/Operational'; File = 'WMI-Activity.evtx'; Required = $false }
    @{ Name = 'Microsoft-Windows-Sysmon/Operational'; File = 'Sysmon.evtx'; Required = $false }
    @{ Name = 'PowerShellCore/Operational'; File = 'PowerShellCore.evtx'; Required = $false }
)
$wevtutilPath = Join-Path $env:SystemRoot 'System32\wevtutil.exe'
foreach ($channel in $channels) {
    $logInfo = $null
    try {
        $logInfo = Get-WinEvent -ListLog $channel.Name
    }
    catch {
        $result = if ($_.FullyQualifiedErrorId -like 'NoMatchingLogsFound*') { 'NotPresent' } else { 'Failed' }
        Add-CollectionStatus $channel.Name $channel.Required $result '' $null $_.Exception.Message
        continue
    }
    try {
        $exportPath = Join-Path $caseDir $channel.File
        # Windows PowerShell can treat redirected native stderr as an ErrorRecord.
        # Capture it without prematurely terminating; inspect the native exit code.
        $savedPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $nativeOutput = & $wevtutilPath epl $channel.Name $exportPath 2>&1
            $nativeExitCode = $LASTEXITCODE
        }
        finally { $ErrorActionPreference = $savedPreference }
        $nativeText = ($nativeOutput | Out-String).Trim()
        if ($nativeExitCode -ne 0) {
            throw "wevtutil returned exit code ${nativeExitCode}: $nativeText"
        }
        if (-not (Test-Path -LiteralPath $exportPath -PathType Leaf)) {
            throw 'wevtutil returned success, but the export file is missing.'
        }
        if ((Get-Item -LiteralPath $exportPath).Length -le 0) {
            throw 'wevtutil returned success, but the export file is empty.'
        }
        $result = if ($logInfo.IsEnabled) { 'Exported' } else { 'DisabledExported' }
        $details = 'Complete retained channel exported without a time or event-ID filter.'
        if (-not $logInfo.IsEnabled) { $details += ' Channel was disabled at inspection; retained data was still exported.' }
        if ($logInfo.RecordCount -eq 0) { $details += ' Channel had zero retained records at inspection.' }
        if ($nativeText) { $details += " wevtutil output: $nativeText" }
        Add-CollectionStatus $channel.Name $channel.Required $result $channel.File $logInfo.RecordCount $details
    }
    catch {
        Add-CollectionStatus $channel.Name $channel.Required 'Failed' $channel.File $null $_.Exception.Message
    }
}

# Finalize metadata/status first, then hash the final versions of all evidence files.
$requiredFailures = @($statusRows | Where-Object {
    $_.Required -and $_.Status -in @('Failed', 'NotPresent')
})
$metadata.CollectionEndUtc = [DateTime]::UtcNow.ToString('o')
$metadata.RequiredFailureCount = $requiredFailures.Count
$metadata.RequiredCollectionComplete = ($requiredFailures.Count -eq 0)
$metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $metadataPath -Encoding UTF8
$statusRows | Export-Csv -LiteralPath (Join-Path $caseDir 'Collection-Status.csv') -NoTypeInformation -Encoding UTF8

$hashRows = New-Object 'System.Collections.Generic.List[object]'
$hashFailures = 0
foreach ($file in Get-ChildItem -LiteralPath $caseDir -File | Sort-Object Name) {
    try {
        $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256
        $hashRows.Add([pscustomobject][ordered]@{
            File = $file.Name; LengthBytes = $file.Length; SHA256 = $hash.Hash
            Status = 'Hashed'; Details = ''
        })
    }
    catch {
        $hashFailures++
        $hashRows.Add([pscustomobject][ordered]@{
            File = $file.Name; LengthBytes = $file.Length; SHA256 = ''
            Status = 'Failed'; Details = $_.Exception.Message
        })
    }
}
$hashRows | Export-Csv -LiteralPath (Join-Path $caseDir 'SHA256-Manifest.csv') -NoTypeInformation -Encoding UTF8

Write-Host "Evidence folder: $caseDir"
Write-Host 'Review Collection-Status.csv and SHA256-Manifest.csv for completeness and failures.'
Write-Host 'The manifest excludes itself. A successful collection is not a clean-machine verdict.'
if ($requiredFailures.Count -gt 0) {
    Write-Warning "$($requiredFailures.Count) required collection item(s) failed or were not present. Review the status report."
}
if ($hashFailures -gt 0) {
    Write-Warning "$hashFailures evidence file(s) could not be hashed. Review the manifest before relying on integrity checks."
}
$optionalIssues = @($statusRows | Where-Object { -not $_.Required -and $_.Status -eq 'Failed' })
$disabledChannels = @($statusRows | Where-Object { $_.Status -eq 'DisabledExported' })
if ($optionalIssues.Count -gt 0 -or $disabledChannels.Count -gt 0) {
    Write-Warning 'Optional collection failures or disabled channels were recorded. Review the status report for evidence gaps.'
}
