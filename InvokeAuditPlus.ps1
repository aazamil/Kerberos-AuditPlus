# Kerberos Hardening Audit Script
# Run this on a Domain Controller with appropriate privileges

function Get-RegistryValue {
    param($Path, $Name)
    try {
        (Get-ItemProperty -Path $Path -ErrorAction Stop).$Name
    } catch {
        return $null
    }
}

function Check-PACValidation {
    $value = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "ValidateKdcPacSignature"
    if ($value -eq 1) { return "Enabled" }
    elseif ($value -eq 0) { return "Disabled" }
    else { return "Not Configured" }
}

function Check-KerberosArmoring {
    $gpo = Get-GPO -All | Where-Object { $_.DisplayName -like "*Default Domain Policy*" }
    if ($gpo) {
        $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
        if ($report -match "Kerberos client support for claims, compound authentication and Kerberos armoring.*Enabled") {
            return "Enabled in GPO"
        }
    }
    return "Not Detected"
}

function Check-AESEncryption {
    $computers = Get-ADComputer -Filter * -Properties msDS-SupportedEncryptionTypes
    $nonAES = $computers | Where-Object {
        ($_.'msDS-SupportedEncryptionTypes') -ne $null -and
        (($_.'msDS-SupportedEncryptionTypes' -band 0x18) -eq 0)
    }
    if ($nonAES.Count -eq 0) {
        return "All computers using AES"
    } else {
        return "Some computers not using AES (${($nonAES.Count)})"
    }
}

function Check-RC4Disabled {
    $key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    $rc4 = Get-RegistryValue -Path $key -Name "SupportedEncryptionTypes"
    if ($rc4 -ne $null -and ($rc4 -band 0x1) -eq 0) {
        return "RC4 Disabled"
    } else {
        return "RC4 Still Allowed"
    }
}

function Check-RC4OnlyAccounts {
    $accounts = Get-ADComputer -Filter * -Properties msDS-SupportedEncryptionTypes
    $rc4Only = $accounts | Where-Object {
        ($_.'msDS-SupportedEncryptionTypes') -ne $null -and
        (($_.'msDS-SupportedEncryptionTypes' -band 0x1) -ne 0) -and
        (($_.'msDS-SupportedEncryptionTypes' -band 0x1E) -eq 0)
    }
    if ($rc4Only.Count -eq 0) {
        return "No RC4-only accounts"
    } else {
        return "RC4-only accounts found (${($rc4Only.Count)})"
    }
}

function Check-ConstrainedDelegation {
    $delegated = Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties msDS-AllowedToDelegateTo
    if ($delegated.Count -gt 0) {
        return "Configured (${($delegated.Count)} accounts)"
    } else {
        return "None Detected"
    }
}

function Check-UnconstrainedDelegation {
    $unconstrained = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation
    if ($unconstrained.Count -eq 0) {
        return "No Unconstrained Delegation"
    } else {
        return "Unconstrained Delegation detected (${($unconstrained.Count)})"
    }
}

function Check-SmartCardAdmins {
    $admins = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Where-Object { $_.ObjectClass -eq "user" }
    $smartcardUsers = $admins | Where-Object {
        (Get-ADUser $_.DistinguishedName -Properties SmartcardLogonRequired).SmartcardLogonRequired -eq $true
    }
    if ($smartcardUsers.Count -eq $admins.Count) {
        return "All Domain Admins require Smart Cards"
    } else {
        return "Some Domain Admins do not require Smart Cards"
    }
}

function Check-SPNDuplicates {
    $spns = Get-ADObject -Filter { servicePrincipalName -like "*" } -Properties servicePrincipalName
    $allSPNs = $spns | ForEach-Object { $_.servicePrincipalName } | Where-Object { $_ -ne $null }
    $duplicates = $allSPNs | Group-Object | Where-Object { $_.Count -gt 1 }
    if ($duplicates.Count -eq 0) {
        return "No Duplicate SPNs"
    } else {
        return "Found Duplicate SPNs (${($duplicates.Count)})"
    }
}

function Check-LogonAuditing {
    $policy = auditpol /get /category:"Logon/Logoff"
    if ($policy -match "Logon\s+Success and Failure") {
        return "Logon Auditing Enabled"
    } else {
        return "Logon Auditing Not Fully Enabled"
    }
}

function Check-TGTLifetime {
    $settings = Get-ADDefaultDomainPasswordPolicy
    $tgtLifetimeHours = $settings.MaxTicketAge.TotalHours
    if ($tgtLifetimeHours -le 10) {
        return "TGT Lifetime OK (${tgtLifetimeHours}h)"
    } else {
        return "TGT Lifetime too long (${tgtLifetimeHours}h)"
    }
}

function Check-PrivilegedSIDHistory {
    $admins = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Where-Object { $_.ObjectClass -eq "user" }
    $sidHistoryFound = $admins | Where-Object {
        (Get-ADUser $_.DistinguishedName -Properties SIDHistory).SIDHistory.Count -gt 0
    }
    if ($sidHistoryFound.Count -eq 0) {
        return "No SIDHistory on Domain Admins"
    } else {
        return "SIDHistory present on Domain Admins (${($sidHistoryFound.Count)})"
    }
}

function Check-PreAuthDisabled {
    $users = Get-ADUser -Filter * -Properties userAccountControl
    $noPreAuth = $users | Where-Object { ($_.userAccountControl -band 0x400000) -ne 0 }
    if ($noPreAuth.Count -eq 0) {
        return "All users require Kerberos Pre-Authentication"
    } else {
        return "Accounts with Pre-Auth Disabled (${($noPreAuth.Count)})"
    }
}

function Check-KerberoastableAccounts {
    $spnUsers = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties ServicePrincipalName, userAccountControl
    $kerberoastable = $spnUsers | Where-Object {
        ($_.userAccountControl -band 0x200) -eq 0
    }
    if ($kerberoastable.Count -eq 0) {
        return "No potentially kerberoastable user accounts"
    } else {
        return "Potentially kerberoastable user accounts found (${($kerberoastable.Count)})"
    }
}

function Check-ResourceBasedDelegation {
    $computers = Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
    $rbcd = $computers | Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null }
    if ($rbcd.Count -eq 0) {
        return "No Resource-Based Delegation Configured"
    } else {
        return "Resource-Based Delegation found (${($rbcd.Count)})"
    }
}

function Check-TimeSkew {
    try {
        $offsetLine = w32tm /query /status | Where-Object { $_ -match 'Clock offset' }
        $offset = $offsetLine -replace '.*:\s*', ''
        $offsetSpan = [TimeSpan]::Parse($offset.TrimStart('-'))
        if ($offsetLine -like '*-*') { $offsetSpan = $offsetSpan.Negate() }
        if ([math]::Abs($offsetSpan.TotalMinutes) -gt 5) {
            return "Time skew detected (${([int][math]::Abs($offsetSpan.TotalMinutes))} min)"
        } else {
            return "Time synchronization within acceptable range"
        }
    } catch {
        return "Unable to determine time skew"
    }
}

function Check-NTLMUsage {
    $regValue = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic"
    switch ($regValue) {
        2 { return "NTLM Disabled" }
        1 { return "NTLM Allowed for Domain" }
        0 { return "NTLM Fully Allowed" }
        default { return "NTLM Restriction Not Configured" }
    }
}

# Run Checks
$results = [ordered]@{
    "PAC Validation"                 = Check-PACValidation
    "Kerberos Armoring (FAST)"      = Check-KerberosArmoring
    "AES Encryption"                = Check-AESEncryption
    "RC4 Encryption"                = Check-RC4Disabled
    "RC4-Only Accounts"             = Check-RC4OnlyAccounts
    "Constrained Delegation"        = Check-ConstrainedDelegation
    "Unconstrained Delegation"      = Check-UnconstrainedDelegation
    "Resource-Based Delegation"     = Check-ResourceBasedDelegation
    "Smart Card Enforcement"        = Check-SmartCardAdmins
    "Duplicate SPNs"                = Check-SPNDuplicates
    "Logon Auditing"                = Check-LogonAuditing
    "TGT Lifetime"                  = Check-TGTLifetime
    "SIDHistory on Admins"          = Check-PrivilegedSIDHistory
    "Kerberos Pre-Authentication"  = Check-PreAuthDisabled
    "Kerberoastable Accounts"       = Check-KerberoastableAccounts
    "Time Skew (DC vs Local)"       = Check-TimeSkew
    "NTLM Restriction Status"       = Check-NTLMUsage
}

# Output Results
Write-Host "`n=== Kerberos Hardening Check Results ===`n"
$results.GetEnumerator() | ForEach-Object {
    Write-Host ("{0,-35} : {1}" -f $_.Key, $_.Value)
}
