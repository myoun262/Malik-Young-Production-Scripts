<#
.SYNOPSIS
    Reads Windows Installer (MSI) package metadata without installing the MSI.

.DESCRIPTION
    Accepts one or more MSI files, or folders containing MSI files, and returns
    packaging-oriented metadata and copies a readable report directly to the
    Windows clipboard. Results can optionally include a SHA-256 hash.

    This script uses the Windows Installer COM API and must run on Windows.

.PARAMETER Path
    An MSI file or a directory containing MSI files. Accepts pipeline input and
    FileInfo objects through the FullName alias.

.PARAMETER Recurse
    Searches subdirectories when Path points to a directory.

.PARAMETER Property
    Additional names from the MSI Property table to include. Each extra column
    is prefixed with "Property_".

.PARAMETER IncludeHash
    Adds the package SHA-256 hash. Hashing large packages can take extra time.

.PARAMETER PassThru
    Also writes the result objects to the PowerShell pipeline. By default, the
    script only copies the formatted report to the clipboard.

.EXAMPLE
    .\Get-MsiInfo.ps1 -Path .\Application.msi

.EXAMPLE
    .\Get-MsiInfo.ps1 -Path C:\Packages -Recurse -IncludeHash

.EXAMPLE
    Get-ChildItem C:\Packages -Filter *.msi | .\Get-MsiInfo.ps1 `
        -Property INSTALLDIR, COMPANYNAME

.EXAMPLE
    .\Get-MsiInfo.ps1 -Path .\Application.msi -PassThru | Format-List
#>

#requires -version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('FullName')]
    [string[]] $Path,

    [switch] $Recurse,

    [string[]] $Property,

    [switch] $IncludeHash,

    [switch] $PassThru
)

begin {
    Set-StrictMode -Version Latest

    $requestedPaths = [System.Collections.Generic.List[string]]::new()

    function Invoke-ComMethod {
        param(
            [Parameter(Mandatory)] [object] $ComObject,
            [Parameter(Mandatory)] [string] $Name,
            [object[]] $Arguments = @()
        )

        $flags = [System.Reflection.BindingFlags]::InvokeMethod
        $ComObject.GetType().InvokeMember($Name, $flags, $null, $ComObject, $Arguments)
    }

    function Get-ComIndexedProperty {
        param(
            [Parameter(Mandatory)] [object] $ComObject,
            [Parameter(Mandatory)] [string] $Name,
            [object[]] $Arguments = @()
        )

        $flags = [System.Reflection.BindingFlags]::GetProperty
        $ComObject.GetType().InvokeMember($Name, $flags, $null, $ComObject, $Arguments)
    }

    function Remove-ComReference {
        param([AllowNull()] [object] $ComObject)

        if ($null -ne $ComObject -and
            [System.Runtime.InteropServices.Marshal]::IsComObject($ComObject)) {
            [void] [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ComObject)
        }
    }

    function Get-SummaryProperty {
        param(
            [Parameter(Mandatory)] [object] $SummaryInformation,
            [Parameter(Mandatory)] [int] $Id
        )

        try {
            Get-ComIndexedProperty -ComObject $SummaryInformation -Name 'Property' -Arguments @($Id)
        }
        catch {
            $null
        }
    }

    function Get-MsiMetadata {
        param(
            [Parameter(Mandatory)] [System.IO.FileInfo] $File,
            [Parameter(Mandatory)] [object] $Installer,
            [string[]] $AdditionalProperty,
            [switch] $WithHash
        )

        $database = $null
        $view = $null
        $record = $null
        $summary = $null

        try {
            # 0 opens the MSI database read-only.
            $database = Invoke-ComMethod -ComObject $Installer -Name 'OpenDatabase' `
                -Arguments @($File.FullName, 0)

            $query = 'SELECT `Property`, `Value` FROM `Property`'
            $view = Invoke-ComMethod -ComObject $database -Name 'OpenView' -Arguments @($query)
            [void] (Invoke-ComMethod -ComObject $view -Name 'Execute')

            $properties = @{}
            while ($true) {
                $record = Invoke-ComMethod -ComObject $view -Name 'Fetch'
                if ($null -eq $record) {
                    break
                }

                try {
                    $propertyName = Get-ComIndexedProperty -ComObject $record -Name 'StringData' `
                        -Arguments @(1)
                    $propertyValue = Get-ComIndexedProperty -ComObject $record -Name 'StringData' `
                        -Arguments @(2)

                    if (-not [string]::IsNullOrWhiteSpace([string] $propertyName)) {
                        $properties[[string] $propertyName] = [string] $propertyValue
                    }
                }
                finally {
                    Remove-ComReference $record
                    $record = $null
                }
            }

            # SummaryInformation IDs are defined by the MSI Summary Information stream.
            $summary = Get-ComIndexedProperty -ComObject $Installer -Name 'SummaryInformation' `
                -Arguments @($File.FullName, 0)
            $summaryTitle = Get-SummaryProperty -SummaryInformation $summary -Id 2
            $summarySubject = Get-SummaryProperty -SummaryInformation $summary -Id 3
            $summaryAuthor = Get-SummaryProperty -SummaryInformation $summary -Id 4
            $summaryComments = Get-SummaryProperty -SummaryInformation $summary -Id 6
            $template = [string] (Get-SummaryProperty -SummaryInformation $summary -Id 7)
            $packageCode = [string] (Get-SummaryProperty -SummaryInformation $summary -Id 9)
            $created = Get-SummaryProperty -SummaryInformation $summary -Id 12
            $lastSaved = Get-SummaryProperty -SummaryInformation $summary -Id 13
            $installerVersionCode = Get-SummaryProperty -SummaryInformation $summary -Id 14
            $wordCount = Get-SummaryProperty -SummaryInformation $summary -Id 15

            $rawPlatform = if ($template) { ($template -split ';', 2)[0] } else { $null }
            $architecture = switch -Regex ($rawPlatform) {
                '^Intel$'   { 'x86'; break }
                '^Intel64$' { 'IA64'; break }
                '^x64$'     { 'x64'; break }
                '^Arm$'     { 'ARM'; break }
                '^Arm64$'   { 'ARM64'; break }
                default     { $rawPlatform }
            }

            $productLanguage = $properties['ProductLanguage']
            $languageName = $null
            if ($productLanguage -match '^\d+$') {
                try {
                    $languageName = [System.Globalization.CultureInfo]::GetCultureInfo(
                        [int] $productLanguage
                    ).EnglishName
                }
                catch {
                    $languageName = 'Unknown LCID'
                }
            }

            $allUsers = $properties['ALLUSERS']
            $msiInstallPerUser = $properties['MSIINSTALLPERUSER']
            $defaultInstallScope = if ($msiInstallPerUser -eq '1') {
                'PerUser'
            }
            elseif ($allUsers -eq '1') {
                'PerMachine'
            }
            elseif ($allUsers -eq '2') {
                'ContextDependent'
            }
            elseif ([string]::IsNullOrEmpty($allUsers)) {
                'PerUserDefault'
            }
            else {
                'Unspecified'
            }

            $minimumInstallerVersion = $null
            $versionNumber = 0
            if ($null -ne $installerVersionCode -and
                [int]::TryParse([string] $installerVersionCode, [ref] $versionNumber)) {
                $minimumInstallerVersion = '{0}.{1}' -f `
                    [math]::Floor($versionNumber / 100), ($versionNumber % 100)
            }

            $isCompressed = $null
            if ($null -ne $wordCount -and [string] $wordCount -match '^\d+$') {
                $isCompressed = (([int] $wordCount -band 2) -ne 0)
            }

            $signature = Get-AuthenticodeSignature -LiteralPath $File.FullName
            $signerSubject = if ($null -ne $signature.SignerCertificate) {
                $signature.SignerCertificate.Subject
            }
            else {
                $null
            }

            $resultData = [ordered] @{
                Path                       = $File.FullName
                FileName                   = $File.Name
                FileSizeMB                 = [math]::Round($File.Length / 1MB, 2)
                FileLastWriteTime          = $File.LastWriteTime
                ProductName                = $properties['ProductName']
                ProductVersion             = $properties['ProductVersion']
                Manufacturer               = $properties['Manufacturer']
                ProductCode                = $properties['ProductCode']
                UpgradeCode                = $properties['UpgradeCode']
                PackageCode                = $packageCode
                Architecture               = $architecture
                Template                   = $template
                ProductLanguage            = $productLanguage
                LanguageName               = $languageName
                DefaultInstallScope        = $defaultInstallScope
                ALLUSERS                   = $allUsers
                MSIINSTALLPERUSER          = $msiInstallPerUser
                InstallLevel               = $properties['INSTALLLEVEL']
                EstimatedInstalledSizeKB   = $properties['ARPSIZE']
                ARPComments                = $properties['ARPCOMMENTS']
                ARPContact                 = $properties['ARPCONTACT']
                ARPHelpLink                = $properties['ARPHELPLINK']
                ARPInstallLocation         = $properties['ARPINSTALLLOCATION']
                ARPNoModify                = $properties['ARPNOMODIFY']
                ARPNoRemove                = $properties['ARPNOREMOVE']
                ARPNoRepair                = $properties['ARPNOREPAIR']
                ARPUrlInfoAbout            = $properties['ARPURLINFOABOUT']
                ARPUrlUpdateInfo           = $properties['ARPURLUPDATEINFO']
                MinimumInstallerVersion    = $minimumInstallerVersion
                SummaryTitle               = $summaryTitle
                SummarySubject             = $summarySubject
                SummaryAuthor              = $summaryAuthor
                SummaryComments            = $summaryComments
                SummaryCreated             = $created
                SummaryLastSaved           = $lastSaved
                IsCompressed               = $isCompressed
                DigitalSignatureStatus     = [string] $signature.Status
                SignerSubject              = $signerSubject
            }

            if ($WithHash) {
                $resultData['SHA256'] = (Get-FileHash -LiteralPath $File.FullName `
                    -Algorithm SHA256).Hash
            }

            foreach ($name in $AdditionalProperty) {
                if ([string]::IsNullOrWhiteSpace($name)) {
                    continue
                }

                $resultData["Property_$name"] = $properties[$name]
            }

            [pscustomobject] $resultData
        }
        finally {
            if ($null -ne $view) {
                try { [void] (Invoke-ComMethod -ComObject $view -Name 'Close') }
                catch { Write-Verbose "Could not close the MSI database view: $_" }
            }

            Remove-ComReference $record
            Remove-ComReference $summary
            Remove-ComReference $view
            Remove-ComReference $database
        }
    }
}

process {
    foreach ($item in $Path) {
        if (-not [string]::IsNullOrWhiteSpace($item)) {
            $requestedPaths.Add($item)
        }
    }
}

end {
    if ($env:OS -ne 'Windows_NT') {
        throw 'Get-MsiInfo.ps1 requires Windows and the Windows Installer service.'
    }

    $msiFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

    foreach ($requestedPath in $requestedPaths) {
        try {
            $item = Get-Item -LiteralPath $requestedPath -ErrorAction Stop
            if ($item.PSIsContainer) {
                $foundFiles = Get-ChildItem -LiteralPath $item.FullName -Filter '*.msi' -File `
                    -Recurse:$Recurse -ErrorAction Stop
                foreach ($foundFile in $foundFiles) {
                    $msiFiles.Add($foundFile)
                }
            }
            elseif ($item.Extension -ieq '.msi') {
                $msiFiles.Add($item)
            }
            else {
                Write-Warning "Skipping non-MSI file: $($item.FullName)"
            }
        }
        catch {
            Write-Error "Could not resolve '$requestedPath': $($_.Exception.Message)" `
                -ErrorAction Continue
        }
    }

    $uniqueMsiFiles = @($msiFiles | Sort-Object -Property FullName -Unique)
    if ($uniqueMsiFiles.Count -eq 0) {
        Write-Warning 'No MSI files were found.'
        return
    }

    $installer = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $results = @(foreach ($msiFile in $uniqueMsiFiles) {
            try {
                Get-MsiMetadata -File $msiFile -Installer $installer `
                    -AdditionalProperty $Property -WithHash:$IncludeHash
            }
            catch {
                Write-Error "Could not read '$($msiFile.FullName)': $($_.Exception.Message)" `
                    -ErrorAction Continue
            }
        })

        if ($results.Count -eq 0) {
            Write-Warning 'No MSI information was available to copy.'
            return
        }

        $clipboardText = $results | Format-List -Property * | Out-String -Width 4096
        $clipboardText.Trim() | Set-Clipboard
        Write-Host "Copied MSI information for $($results.Count) package(s) to the clipboard."

        if ($PassThru) {
            $results
        }
    }
    finally {
        Remove-ComReference $installer
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
}
