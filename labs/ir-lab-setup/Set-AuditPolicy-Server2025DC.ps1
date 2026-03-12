#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Server 2025 Domain Controller - Audit Policy Configurator v2.4
    Target : VM4 - Windows Server 2025 DC

.NOTES
    Author  : Security Engineering Roadmap | github: A-rjun-saji
    Version : 2.4
    Fixes   :
      - Fixed auditpol invocation: now uses /set correctly
      - Always passes /success:{enable|disable} and /failure:{enable|disable}
      - Improved auditpol validation using CSV output (/r)
      - Improved 4104 live test by spawning a new PowerShell session
      - Improved 4688 live test reliability
      - Fixed auto-fix logic so failed controls are retried correctly
      - Better logging and safer process execution
#>

[CmdletBinding()]
param(
    [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Results  = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:FixCount = 0

$script:LogFile = "$env:SystemDrive\AuditPolicy_DC_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:TranscriptPath = "$env:SystemDrive\AuditPolicy_DC_Transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Start-Transcript -Path $script:TranscriptPath -Append -Force

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO','PASS','FAIL','FIX','HEAD','WARN')]
        [string]$Level = 'INFO'
    )

    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts][$Level] $Message"

    $color = switch ($Level) {
        'PASS' { 'Green' }
        'FAIL' { 'Red' }
        'FIX'  { 'Yellow' }
        'HEAD' { 'Cyan' }
        'WARN' { 'Magenta' }
        default { 'White' }
    }

    Write-Host $line -ForegroundColor $color
    Add-Content -Path $script:LogFile -Value $line -Encoding UTF8
}

function Add-Result {
    param(
        [Parameter(Mandatory)]
        [string]$Control,

        [Parameter(Mandatory)]
        [ValidateSet('PASS','FAIL')]
        [string]$Status,

        [string]$Detail = ''
    )

    $script:Results.Add([PSCustomObject]@{
        Control = $Control
        Status  = $Status
        Detail  = $Detail
    })
}

function Get-AuditPolicyTargets {
    @(
        @{ Sub='Credential Validation';                  S=$true; F=$true  }
        @{ Sub='Kerberos Authentication Service';        S=$true; F=$true  }
        @{ Sub='Kerberos Service Ticket Operations';     S=$true; F=$true  }
        @{ Sub='Other Account Logon Events';             S=$true; F=$true  }
        @{ Sub='User Account Management';                S=$true; F=$true  }
        @{ Sub='Computer Account Management';            S=$true; F=$true  }
        @{ Sub='Security Group Management';              S=$true; F=$true  }
        @{ Sub='Other Account Management Events';        S=$true; F=$true  }
        @{ Sub='Logon';                                  S=$true; F=$true  }
        @{ Sub='Logoff';                                 S=$true; F=$false }
        @{ Sub='Account Lockout';                        S=$true; F=$false }
        @{ Sub='Special Logon';                          S=$true; F=$false }
        @{ Sub='Directory Service Access';               S=$true; F=$true  }
        @{ Sub='Directory Service Changes';              S=$true; F=$true  }
        @{ Sub='Directory Service Replication';          S=$true; F=$true  }
        @{ Sub='Sensitive Privilege Use';                S=$true; F=$true  }
        @{ Sub='Process Creation';                       S=$true; F=$false }
        @{ Sub='Audit Policy Change';                    S=$true; F=$true  }
        @{ Sub='Authentication Policy Change';           S=$true; F=$true  }
        @{ Sub='Authorization Policy Change';            S=$true; F=$false }
        @{ Sub='Security State Change';                  S=$true; F=$true  }
        @{ Sub='Security System Extension';              S=$true; F=$true  }
        @{ Sub='System Integrity';                       S=$true; F=$true  }
    )
}

function Get-AuditTargetByName {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    return (Get-AuditPolicyTargets | Where-Object { $_.Sub -eq $Name } | Select-Object -First 1)
}

function Set-AuditSubcategory {
    param(
        [Parameter(Mandatory)]
        [string]$SubCategory,

        [Parameter(Mandatory)]
        [bool]$Success,

        [Parameter(Mandatory)]
        [bool]$Failure
    )

    $successMode = if ($Success) { 'enable' } else { 'disable' }
    $failureMode = if ($Failure) { 'enable' } else { 'disable' }

    if ($WhatIf) {
        Write-Log " [WHATIF] Would set: $SubCategory (Success=$successMode Failure=$failureMode)" -Level WARN
        return $true
    }

    $args = @(
        '/set'
        "/subcategory:$SubCategory"
        "/success:$successMode"
        "/failure:$failureMode"
    )

    try {
        $output = & "$env:SystemRoot\System32\auditpol.exe" @args 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            return $true
        }

        Write-Log "auditpol failed (exit $exitCode) for '$SubCategory': $($output -join ' | ')" -Level WARN
        return $false
    }
    catch {
        Write-Log "EXCEPTION setting '$SubCategory': $($_.Exception.Message)" -Level WARN
        return $false
    }
}

function Test-AuditPolSetting {
    param(
        [Parameter(Mandatory)]
        [string]$Sub,

        [Parameter(Mandatory)]
        [bool]$NeedSuccess,

        [Parameter(Mandatory)]
        [bool]$NeedFailure
    )

    try {
        $raw = & "$env:SystemRoot\System32\auditpol.exe" /get "/subcategory:$Sub" /r 2>&1
        if ($LASTEXITCODE -ne 0 -or -not $raw) {
            return $false
        }

        $csv = $raw | ConvertFrom-Csv
        if (-not $csv) {
            return $false
        }

        $row = $csv | Where-Object { $_.Subcategory -eq $Sub } | Select-Object -First 1
        if (-not $row) {
            return $false
        }

        $setting = [string]$row.'Inclusion Setting'
        if ([string]::IsNullOrWhiteSpace($setting)) {
            return $false
        }

        $hasSuccess = $setting -match '\bSuccess\b'
        $hasFailure = $setting -match '\bFailure\b'
        $noAuditing = $setting -match '\bNo Auditing\b'

        if ($noAuditing) { return $false }
        if ($NeedSuccess -and -not $hasSuccess) { return $false }
        if ($NeedFailure -and -not $hasFailure) { return $false }
        if (-not $NeedSuccess -and $hasSuccess) { return $false }
        if (-not $NeedFailure -and $hasFailure) { return $false }

        return $true
    }
    catch {
        Write-Log "Test-AuditPolSetting exception for '$Sub': $($_.Exception.Message)" -Level WARN
        return $false
    }
}

function Test-RegDWord {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name,

        [int]$Expected = 1
    )

    try {
        $val = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
        return ($val -eq $Expected)
    }
    catch {
        return $false
    }
}

function Test-LiveEvent4688 {
    $before = (Get-Date).AddSeconds(-10)

    try {
        Start-Process -FilePath "cmd.exe" `
                      -ArgumentList "/c echo DC4688Test > nul" `
                      -WindowStyle Hidden `
                      -Wait `
                      -ErrorAction Stop
    }
    catch {
        Write-Log "Failed to spawn 4688 test process: $($_.Exception.Message)" -Level WARN
        return @{ Found = $false; HasCmdLine = $false }
    }

    Start-Sleep -Seconds 10

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4688
            StartTime = $before
        } -MaxEvents 500 -ErrorAction SilentlyContinue

        if (-not $events) {
            return @{ Found = $false; HasCmdLine = $false }
        }

        $match = $events | Where-Object {
            $_.Message -match '(?im)New Process Name:\s+.*\\cmd\.exe' -and
            $_.Message -match '(?im)Process Command Line:\s+.+'
        } | Select-Object -First 1

        if (-not $match) {
            return @{ Found = $false; HasCmdLine = $false }
        }

        $hasCmdLine = $match.Message -match '(?im)Process Command Line:\s+.+'
        return @{ Found = $true; HasCmdLine = $hasCmdLine }
    }
    catch {
        Write-Log "4688 live test exception: $($_.Exception.Message)" -Level WARN
        return @{ Found = $false; HasCmdLine = $false }
    }
}

function Test-LivePS4104 {
    $marker = "PS4104-$(Get-Random -Minimum 10000 -Maximum 999999)"
    $before = (Get-Date).AddSeconds(-5)

    try {
        $arg = "-NoProfile -ExecutionPolicy Bypass -Command `"Write-Output '$marker' | Out-Null`""
        Start-Process -FilePath "powershell.exe" `
                      -ArgumentList $arg `
                      -WindowStyle Hidden `
                      -Wait `
                      -ErrorAction Stop
    }
    catch {
        Write-Log "Failed to spawn PowerShell 4104 test process: $($_.Exception.Message)" -Level WARN
        return $false
    }

    Start-Sleep -Seconds 10

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-PowerShell/Operational'
            Id        = 4104
            StartTime = $before
        } -MaxEvents 200 -ErrorAction SilentlyContinue

        if (-not $events) {
            return $false
        }

        return ($null -ne ($events | Where-Object { $_.Message -match [regex]::Escape($marker) } | Select-Object -First 1))
    }
    catch {
        Write-Log "4104 live test exception: $($_.Exception.Message)" -Level WARN
        return $false
    }
}

function Invoke-PreFlight {
    Write-Log 'PHASE 1 - Pre-Flight Checks' -Level HEAD

    $os = Get-CimInstance Win32_OperatingSystem
    Write-Log " OS    : $($os.Caption)"
    Write-Log " Build : $($os.BuildNumber)"
    Write-Log " Host  : $env:COMPUTERNAME"
    Write-Log " User  : $env:USERNAME"

    if ($os.Caption -notmatch '2025') {
        Write-Log "WARNING: Script optimized for Server 2025 - detected: $($os.Caption)" -Level WARN
    }

    if (Get-SmbShare -Name SYSVOL -ErrorAction SilentlyContinue) {
        Write-Log 'SYSVOL share -> OK (DC appears promoted)' -Level PASS
    }
    else {
        Write-Log 'SYSVOL share missing -> DC may not be fully promoted' -Level WARN
    }

    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.DomainRole -in 4,5) {
        Write-Log 'Detected Domain Controller - Local audit changes may be overridden by Group Policy (e.g., Default Domain Controllers Policy).' -Level WARN
        Write-Log 'For persistent changes, configure Advanced Audit Policies in the GPO instead of locally.' -Level WARN
    }

    $auditpol = "$env:SystemRoot\System32\auditpol.exe"
    if (Test-Path $auditpol) {
        Write-Log 'auditpol.exe found -> OK' -Level PASS
    }
    else {
        Write-Log 'auditpol.exe NOT FOUND -> cannot continue' -Level FAIL
        exit 1
    }

    Write-Log 'IMPORTANT: Domain GPO (Default Domain Controllers Policy) overrides local policy on DCs' -Level WARN

    if ($WhatIf) {
        Write-Log 'MODE: DRY-RUN (WhatIf) - no changes will be made' -Level WARN
    }
}

function Set-AuditPolicies {
    Write-Log 'PHASE 2 - Configuring Advanced Audit Policies' -Level HEAD

    if ($WhatIf) {
        Write-Log '[WHATIF] Would enforce advanced audit policy mode (SCENoApplyLegacyAuditPolicy=1)' -Level WARN
    }
    else {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                         -Name 'SCENoApplyLegacyAuditPolicy' `
                         -Value 1 `
                         -Type DWord `
                         -Force `
                         -ErrorAction Stop
        Write-Log 'SCENoApplyLegacyAuditPolicy = 1 (enforce advanced audit)' -Level PASS
    }

    foreach ($p in Get-AuditPolicyTargets) {
        $ok = Set-AuditSubcategory -SubCategory $p.Sub -Success $p.S -Failure $p.F
        Write-Log "[SET] $($p.Sub) -> $(if ($ok) { 'OK' } else { 'FAILED' })" -Level $(if ($ok) { 'PASS' } else { 'FAIL' })
    }
}

function Set-RegistryLogging {
    Write-Log 'PHASE 2B - Registry-Based Enhanced Logging' -Level HEAD

    if ($WhatIf) {
        Write-Log '[WHATIF] Would configure registry logging keys' -Level WARN
        return
    }

    $auditPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    if (-not (Test-Path $auditPath)) {
        New-Item -Path $auditPath -Force | Out-Null
    }
    Set-ItemProperty -Path $auditPath -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord -Force
    Write-Log 'ProcessCreationIncludeCmdLine_Enabled = 1 -> OK' -Level PASS

    $sbPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (-not (Test-Path $sbPath)) {
        New-Item -Path $sbPath -Force | Out-Null
    }
    Set-ItemProperty -Path $sbPath -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -Force
    Write-Log 'Script Block Logging enabled -> OK' -Level PASS

    $modPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    if (-not (Test-Path $modPath)) {
        New-Item -Path $modPath -Force | Out-Null
    }
    Set-ItemProperty -Path $modPath -Name 'EnableModuleLogging' -Value 1 -Type DWord -Force

    $modNames = Join-Path $modPath 'ModuleNames'
    if (-not (Test-Path $modNames)) {
        New-Item -Path $modNames -Force | Out-Null
    }
    Set-ItemProperty -Path $modNames -Name '*' -Value '*' -Type String -Force
    Write-Log 'Module Logging enabled (all modules) -> OK' -Level PASS

    $transPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    if (-not (Test-Path $transPath)) {
        New-Item -Path $transPath -Force | Out-Null
    }

    Set-ItemProperty -Path $transPath -Name 'EnableTranscripting'    -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $transPath -Name 'EnableInvocationHeader' -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $transPath -Name 'OutputDirectory'        -Value "$env:SystemDrive\PSTranscripts" -Type String -Force

    $transDir = "$env:SystemDrive\PSTranscripts"
    if (-not (Test-Path $transDir)) {
        New-Item -Path $transDir -ItemType Directory -Force | Out-Null
        Write-Log "Created PowerShell transcript folder: $transDir" -Level PASS
    }

    Write-Log 'PowerShell Transcription -> OK' -Level PASS
}

function Set-EventLogSizes {
    Write-Log 'PHASE 3 - Event Log Maximum Sizes' -Level HEAD

    if ($WhatIf) {
        Write-Log '[WHATIF] Security=1GB, System/DS=512MB' -Level WARN
        return
    }

    $logs = @(
        @{ Name='Security';          MB=1024 }
        @{ Name='System';            MB=512  }
        @{ Name='Directory Service'; MB=512  }
    )

    foreach ($l in $logs) {
        $bytes = $l.MB * 1MB

        try {
            & wevtutil.exe sl $l.Name /ms:$bytes /rt:false 2>$null | Out-Null
            Write-Log "$($l.Name) log -> $($l.MB) MB - OK" -Level PASS
        }
        catch {
            Write-Log "$($l.Name) log resize failed: $($_.Exception.Message)" -Level FAIL
        }
    }
}

function Invoke-GPUpdate {
    Write-Log 'PHASE 4 - gpupdate /force' -Level HEAD

    if ($WhatIf) {
        Write-Log '[WHATIF] Would run gpupdate /force' -Level WARN
        return
    }

    try {
        $out = & gpupdate.exe /force 2>&1
        $last = ($out | Select-Object -Last 1)
        if ([string]::IsNullOrWhiteSpace($last)) {
            Write-Log 'gpupdate -> completed' -Level INFO
        }
        else {
            Write-Log "gpupdate -> $($last -replace '\s+', ' ')" -Level INFO
        }
        Start-Sleep -Seconds 6
    }
    catch {
        Write-Log "gpupdate failed: $($_.Exception.Message)" -Level WARN
    }
}

function Invoke-Validation {
    Write-Log 'PHASE 5 - Validation' -Level HEAD

    foreach ($c in Get-AuditPolicyTargets) {
        $ok = Test-AuditPolSetting -Sub $c.Sub -NeedSuccess $c.S -NeedFailure $c.F
        $status = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Log "$($c.Sub) -> $status" -Level $status
        Add-Result -Control $c.Sub -Status $status
    }

    $regChecks = @(
        @{ Label='CmdLine in 4688 (reg)'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit';     Name='ProcessCreationIncludeCmdLine_Enabled' }
        @{ Label='Script Block Logging';  Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging';   Name='EnableScriptBlockLogging' }
        @{ Label='Module Logging';        Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging';         Name='EnableModuleLogging' }
    )

    foreach ($r in $regChecks) {
        $ok = Test-RegDWord -Path $r.Path -Name $r.Name
        $status = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Log "$($r.Label) -> $status" -Level $status
        Add-Result -Control $r.Label -Status $status
    }

    foreach ($log in @('Security','Directory Service')) {
        try {
            $li = Get-WinEvent -ListLog $log -ErrorAction Stop
            $mb = [math]::Round($li.MaximumSizeInBytes / 1MB, 0)
            $min = if ($log -eq 'Security') { 1024 } else { 512 }
            $ok = $mb -ge $min
            $status = if ($ok) { 'PASS' } else { 'FAIL' }

            Write-Log "$log log = $mb MB (want >= $min) -> $status" -Level $status
            Add-Result -Control "$log Log Size" -Status $status
        }
        catch {
            Write-Log "$log log -> cannot read size" -Level FAIL
            Add-Result -Control "$log Log Size" -Status 'FAIL'
        }
    }

    Write-Log 'Running live 4688 (process creation + cmdline) test...' -Level HEAD
    $r4688 = Test-LiveEvent4688

    if ($r4688.Found -and $r4688.HasCmdLine) {
        Write-Log 'LIVE 4688 + command line -> PASS' -Level PASS
        Add-Result -Control 'LIVE 4688 + CmdLine' -Status 'PASS' -Detail 'Command line captured'
    }
    elseif ($r4688.Found) {
        Write-Log 'LIVE 4688 found but NO command line -> FAIL' -Level FAIL
        Add-Result -Control 'LIVE 4688 + CmdLine' -Status 'FAIL' -Detail 'CmdLine field empty (registry/policy not effective yet? May need reboot)'
    }
    else {
        Write-Log 'No 4688 event captured -> FAIL' -Level FAIL
        Add-Result -Control 'LIVE 4688 + CmdLine' -Status 'FAIL' -Detail 'No event -> Process Creation audit may not be active (check GPO)'
    }

    Write-Log 'Running live PowerShell 4104 (script block) test...' -Level HEAD
    $ok4104 = Test-LivePS4104
    $status4104 = if ($ok4104) { 'PASS' } else { 'FAIL' }

    Write-Log "LIVE 4104 Script Block -> $status4104" -Level $status4104
    Add-Result -Control 'LIVE PS ScriptBlock 4104' -Status $status4104 -Detail $(if (-not $ok4104) { 'May need reboot or GPO refresh / fresh session for registry to take effect' } else { '' })
}

function Invoke-AutoFix {
    Write-Log 'PHASE 6 - Auto-Fix round' -Level HEAD

    $failures = $script:Results | Where-Object { $_.Status -eq 'FAIL' }

    if (-not $failures) {
        Write-Log 'No failures detected -> auto-fix skipped' -Level PASS
        return
    }

    foreach ($f in $failures) {
        Write-Log "Attempting fix: $($f.Control)" -Level FIX
        $script:FixCount++

        $target = Get-AuditTargetByName -Name $f.Control

        if ($null -ne $target) {
            $null = Set-AuditSubcategory -SubCategory $target.Sub -Success $target.S -Failure $target.F
            continue
        }

        switch ($f.Control) {
            'CmdLine in 4688 (reg)' {
                $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
                if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                Set-ItemProperty -Path $p -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord -Force
            }

            'Script Block Logging' {
                $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
                if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                Set-ItemProperty -Path $p -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -Force
            }

            'Module Logging' {
                $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
                if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                Set-ItemProperty -Path $p -Name 'EnableModuleLogging' -Value 1 -Type DWord -Force
            }

            'Security Log Size' {
                & wevtutil.exe sl Security /ms:1073741824 /rt:false 2>$null | Out-Null
            }

            'Directory Service Log Size' {
                & wevtutil.exe sl "Directory Service" /ms:536870912 /rt:false 2>$null | Out-Null
            }

            default {
                if ($f.Control -like 'LIVE*') {
                    Write-Log 'Live test failure - usually needs reboot or fresh session / GPO apply' -Level WARN
                }
                else {
                    Write-Log "No auto-fix handler for: $($f.Control)" -Level WARN
                }
            }
        }
    }

    if (-not $WhatIf) {
        Write-Log 'Re-running gpupdate /force after fixes...' -Level FIX
        & gpupdate.exe /force 2>&1 | Out-Null
        Start-Sleep -Seconds 8
    }

    Write-Log 'PHASE 6B - Re-Validation after fixes' -Level HEAD
    $script:Results.Clear()
    Invoke-Validation
}

function Write-FinalReport {
    Write-Log '' -Level HEAD
    Write-Log '======================================================' -Level HEAD
    Write-Log '      AUDIT POLICY REPORT - Windows Server 2025 DC     ' -Level HEAD
    Write-Log " Host : $env:COMPUTERNAME   |   User : $env:USERNAME" -Level HEAD
    Write-Log " Time : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')    |   Log : $script:LogFile" -Level HEAD
    Write-Log " Mode : $(if ($WhatIf) { 'DRY RUN' } else { 'CHANGES APPLIED' })" -Level HEAD
    Write-Log '======================================================' -Level HEAD

    $pass  = ($script:Results | Where-Object { $_.Status -eq 'PASS' }).Count
    $fail  = ($script:Results | Where-Object { $_.Status -eq 'FAIL' }).Count
    $total = $script:Results.Count

    foreach ($r in $script:Results) {
        $detail = if ($r.Detail) { " | $($r.Detail)" } else { '' }
        Write-Log "[$($r.Status)] $($r.Control)$detail" -Level $r.Status
    }

    Write-Log '------------------------------------------------------'
    Write-Log "Total: $total   |   Passed: $pass   |   Failed: $fail"
    Write-Log "Auto-fix attempts: $($script:FixCount)"
    Write-Log '======================================================'

    if ($fail -gt 0) {
        Write-Log 'REMAINING FAILURES - Quick Troubleshooting Checklist:' -Level FAIL
        Write-Log ' 1. Most common -> Default Domain Controllers Policy overrides local settings' -Level FAIL
        Write-Log ' 2. Run: auditpol /get /category:*   -> check real applied policy' -Level FAIL
        Write-Log ' 3. Open gpmc.msc -> edit Default Domain Controllers Policy -> verify audit settings' -Level FAIL
        Write-Log ' 4. Live test failures often need reboot or 15-30 min wait' -Level FAIL
        Write-Log ' 5. Confirm you are Domain Admin (not only local admin)' -Level FAIL
        Write-Log ' 6. If on DC, configure Advanced Audit in GPO: Computer Config > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration' -Level FAIL
        Write-Log ' 7. Enable "Audit: Force audit policy subcategory settings" in GPO Security Options' -Level FAIL
    }
    else {
        Write-Log 'ALL CHECKS PASSED -> DC audit/logging fully configured' -Level PASS
        Write-Log 'Key events should now appear: 4624/4625/4634/4662/4672/4688/4706/4719/5136/4104 ...' -Level PASS
    }
}

try {
    Write-Log 'Windows Server 2025 DC Audit Policy Configurator v2.4 - Starting' -Level HEAD

    Invoke-PreFlight
    Set-AuditPolicies
    Set-RegistryLogging
    Set-EventLogSizes
    Invoke-GPUpdate
    Invoke-Validation
    Invoke-AutoFix
    Write-FinalReport
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level FAIL
    throw
}
finally {
    Stop-Transcript | Out-Null
}
