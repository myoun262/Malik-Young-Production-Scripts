param(
    [Parameter(Mandatory)]
    [string]$Group,

    [switch]$Recursive
)

Import-Module ActiveDirectory -ErrorAction Stop

try {
    $groupObject = Get-ADGroup -Identity $Group -ErrorAction Stop

    $memberParams = @{
        Identity    = $groupObject
        ErrorAction = 'Stop'
    }

    if ($Recursive) {
        $memberParams.Recursive = $true
    }

    $userCount = @(
        Get-ADGroupMember @memberParams |
        Where-Object ObjectClass -eq 'user'
    ).Count

    [PSCustomObject]@{
        GroupName = $groupObject.Name
        UserCount = $userCount
        Recursive = [bool]$Recursive
    }
}
catch {
    Write-Error "Unable to count users in group '$Group': $($_.Exception.Message)"
}