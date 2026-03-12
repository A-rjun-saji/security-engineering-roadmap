#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows 10 Enterprise (AD-Joined Endpoint) — Audit Policy Configurator v2
    Target : VM2 — Windows 10 Enterprise, domain-joined victim endpoint

.DESCRIPTION
    Phase 1  — Pre-Flight   : Verify OS, PS version, admin rights, AD join status
    Phase 2  — Configure    : Apply endpoint-specific audit subcategories + registry
    Phase 3  — Log Size     : Set Security log to 1 GB (2026 standard)
    Phase 4  — Enforce      : gpupdate /force
    Phase 5  — Validate     : Policy checks + live event generation
    Phase 6  — Auto-Fix     : Re-apply any failed control, re-validate
    Phase 7  — Report       : Final pass/fail summary

.NOTES
    Run as Administrator on Windows 10 Enterprise (domain-joined).
    PowerShell 5.1+ required.
    Author  : Security Engineering Roadmap | github: A-rjun-saji
    Branch  : phase-1-ir-foundations
    Version : 2.0 — Fixes $args bug, Get-WmiObject, IEX; adds missing subcategories
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$WhatIf   # Dry-run: shows what would be changed without applying
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Globals ──────────────────────────────────────────────────────────────────
$script:Results  = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:FixCount = 0
$LogFile         = "$env:SystemDrive\AuditPolicy_Win10_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Start-Transcript -Path "$env:SystemDrive\AuditPolicy_Win10_Transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log" -Append

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts][$Level] $Message"
    $color = switch ($Level) {
        'PASS' { 'Green' }  'FAIL' { 'Red' }
        'FIX'  { 'Yellow' } 'HEAD' { 'Cyan' }
        'WARN' { 'Magenta'} default { 'White' }
    }
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $LogFile -Value $line
}

function Add-Result {
    param([string]$Control, [string]$Status, [string]$Detail = '')
    $script:Results.Add([PSCustomObject]@{
        Control = $Control; Status = $Status; Detail = $Detail
    })
}

function Set-AuditSubcategory {
    param([string]$SubCategory, [bool]$Success, [bool]$Failure)
    # FIX: renamed from $args (reserved PS variable) to $auditArgs
    $auditArgs = "/subcategory:`"$SubCategory`""
    if ($Success) { $auditArgs += ' /success:enable' }
    if ($Failure) { $auditArgs += ' /failure:enable' }

    if ($WhatIf) {
        Write-Log "  [WHATIF] auditpol $auditArgs" -Level WARN
        return $true
    }
    $out = cmd /c "auditpol $auditArgs 2>&1"
    return ($LASTEXITCODE -eq 0)
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — PRE-FLIGHT CHECKS
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-PreFlight {
    Write-Log "PHASE 1 — Pre-Flight Checks" -Level HEAD

    # OS check — FIX: Get-CimInstance replaces deprecated Get-WmiObject
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    Write-Log "  OS      : $($os.Caption)"
    Write-Log "  Build   : $($os.BuildNumber)"
    Write-Log "  Host    : $env:COMPUTERNAME"
    Write-Log "  User    : $env:USERNAME"

    if ($os.Caption -notmatch 'Windows 10') {
        Write-Log "  WARNING: This script targets Windows 10. Detected: $($os.Caption)" -Level WARN
    }

    # AD join check
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($cs.PartOfDomain) {
        Write-Log "  AD Join : YES — Domain: $($cs.Domain)" -Level PASS
        Write-Log "  NOTE    : Domain GPO may override local audit settings after next GP refresh" -Level WARN
    } else {
        Write-Log "  AD Join : NO — Machine is not domain-joined" -Level WARN
    }

    # PowerShell version
    Write-Log "  PS Ver  : $($PSVersionTable.PSVersion)"
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Log "  FAIL: PowerShell 5.1+ required" -Level FAIL
        exit 1
    }

    if ($WhatIf) {
        Write-Log "  MODE    : DRY RUN (WhatIf) — No changes will be applied" -Level WARN
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — CONFIGURE AUDIT POLICIES (Endpoint-Specific)
# ─────────────────────────────────────────────────────────────────────────────
function Set-AuditPolicies {
    Write-Log "PHASE 2 — Configuring Endpoint Audit Policies" -Level HEAD

    # Prevent basic/advanced policy conflict
    if (-not $WhatIf) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
            -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Type DWord -Force
    }
    Write-Log "  SCENoApplyLegacyAuditPolicy = 1 (Advanced overrides Basic)"

    # ── Endpoint Audit Policy Table ───────────────────────────────────────────
    # Sub                              S       F      Rationale
    $policies = @(
        @{ Sub='Credential Validation';         S=$true;  F=$true  },  # 4624/4625 — auth monitoring
        @{ Sub='Logon';                         S=$true;  F=$true  },  # 4624 — session tracking
        @{ Sub='Logoff';                        S=$true;  F=$false },  # 4634 — session end
        @{ Sub='Account Lockout';               S=$true;  F=$false },  # 4740 — brute force detection
        @{ Sub='Special Logon';                 S=$true;  F=$false },  # 4964 — admin-equivalent logon
        @{ Sub='User Account Management';       S=$true;  F=$true  },  # 4720/4726/4738
        @{ Sub='Security Group Management';     S=$true;  F=$false },  # 4728/4732 — group changes
        @{ Sub='Sensitive Privilege Use';       S=$true;  F=$true  },  # 4672 — lateral movement
        @{ Sub='Process Creation';              S=$true;  F=$false },  # 4688 — execution tracking
        @{ Sub='Audit Policy Change';           S=$true;  F=$true  },  # 4719 — detect logging tampering
        @{ Sub='Authentication Policy Change';  S=$true;  F=$false },  # 4706 — trust/auth changes
        @{ Sub='Security State Change';         S=$true;  F=$true  }   # 4608 — system integrity
    )

    foreach ($p in $policies) {
        $ok = Set-AuditSubcategory -SubCategory $p.Sub -Success $p.S -Failure $p.F
        $lvl = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Log "  [SET] $($p.Sub) — $(if($ok){'OK'}else{'FAILED'})" -Level $lvl
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2B — REGISTRY SETTINGS
# ─────────────────────────────────────────────────────────────────────────────
function Set-RegistryLogging {
    Write-Log "PHASE 2B — Registry-Based Logging" -Level HEAD

    if ($WhatIf) {
        Write-Log "  [WHATIF] Would write CmdLine, ScriptBlock, ModuleLogging registry keys" -Level WARN
        return
    }

    # 1. Command-line capture in Event 4688
    $cmdPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    if (-not (Test-Path $cmdPath)) { New-Item -Path $cmdPath -Force | Out-Null }
    Set-ItemProperty -Path $cmdPath -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord -Force
    Write-Log "  [SET] CmdLine in Event 4688 — OK"

    # 2. PowerShell Script Block Logging (Event 4104)
    $sbPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (-not (Test-Path $sbPath)) { New-Item -Path $sbPath -Force | Out-Null }
    Set-ItemProperty -Path $sbPath -Name 'EnableScriptBlockLogging'            -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $sbPath -Name 'EnableScriptBlockInvocationLogging'  -Value 1 -Type DWord -Force
    Write-Log "  [SET] PowerShell Script Block Logging — OK"

    # 3. PowerShell Module Logging
    $modPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    if (-not (Test-Path $modPath)) { New-Item -Path $modPath -Force | Out-Null }
    Set-ItemProperty -Path $modPath -Name 'EnableModuleLogging' -Value 1 -Type DWord -Force
    $modNames = "$modPath\ModuleNames"
    if (-not (Test-Path $modNames)) { New-Item -Path $modNames -Force | Out-Null }
    Set-ItemProperty -Path $modNames -Name '*' -Value '*' -Type String -Force
    Write-Log "  [SET] PowerShell Module Logging (all modules) — OK"

    # 4. PowerShell Transcription (optional but recommended)
    $transPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    if (-not (Test-Path $transPath)) { New-Item -Path $transPath -Force | Out-Null }
    Set-ItemProperty -Path $transPath -Name 'EnableTranscripting'       -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $transPath -Name 'EnableInvocationHeader'    -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $transPath -Name 'OutputDirectory'           -Value "$env:SystemDrive\PSTranscripts" -Type String -Force
    Write-Log "  [SET] PowerShell Transcription → $env:SystemDrive\PSTranscripts — OK"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — SET SECURITY LOG SIZE (2026 Standard: 1 GB)
# ─────────────────────────────────────────────────────────────────────────────
function Set-SecurityLogSize {
    Write-Log "PHASE 3 — Configuring Security Event Log Size (1 GB)" -Level HEAD

    if ($WhatIf) {
        Write-Log "  [WHATIF] wevtutil sl Security /ms:1073741824 /rt:false" -Level WARN
        return
    }

    try {
        # 1 GB = 1073741824 bytes | /rt:false = do not overwrite unless full
        cmd /c "wevtutil sl Security /ms:1073741824 /rt:false" | Out-Null
        Write-Log "  [SET] Security log max size = 1 GB, retention = manual — OK" -Level PASS
    } catch {
        Write-Log "  [ERR] Failed to set log size: $($_.Exception.Message)" -Level FAIL
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — ENFORCE
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-GPUpdate {
    Write-Log "PHASE 4 — gpupdate /force" -Level HEAD
    if ($WhatIf) { Write-Log "  [WHATIF] Would run: gpupdate /force" -Level WARN; return }
    $out = cmd /c "gpupdate /force 2>&1"
    Write-Log "  $($out[-1])"
    Start-Sleep -Seconds 4
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5 — VALIDATE
# ─────────────────────────────────────────────────────────────────────────────
function Test-AuditPolSetting {
    param([string]$Sub, [bool]$NeedSuccess, [bool]$NeedFailure = $false)
    $raw  = cmd /c "auditpol /get /subcategory:`"$Sub`" 2>&1"
    $line = $raw | Where-Object { $_ -match [regex]::Escape($Sub) } | Select-Object -First 1
    if (-not $line)                            { return $false }
    if ($line -match 'No Auditing')            { return $false }
    if ($NeedSuccess -and $line -notmatch 'Success') { return $false }
    if ($NeedFailure -and $line -notmatch 'Failure') { return $false }
    return $true
}

function Test-RegDWord {
    param([string]$Path, [string]$Name, [int]$Expected = 1)
    try { return ((Get-ItemPropertyValue -Path $Path -Name $Name -EA Stop) -eq $Expected) }
    catch { return $false }
}

function Test-LiveEvent4688 {
    $marker = "AuditTest-$(Get-Date -Format 'HHmmssff')"
    $before = Get-Date
    # FIX: no Invoke-Expression — direct Start-Process call
    Start-Process -FilePath 'cmd.exe' -ArgumentList "/c echo $marker" -WindowStyle Hidden -Wait
    Start-Sleep -Seconds 3

    $events = Get-WinEvent -FilterHashtable @{
        LogName='Security'; Id=4688; StartTime=$before
    } -EA SilentlyContinue

    if (-not $events) { return @{ Found=$false; HasCmdLine=$false } }

    $match = $events | Where-Object { $_.Message -match [regex]::Escape($marker) }
    $found = ($null -ne $match)
    $hasCmdLine = $false
    if ($found) {
        $hasCmdLine = ($match | Select-Object -First 1).Message -match 'Process Command Line\s*:\s*\S+'
    }
    return @{ Found=$found; HasCmdLine=$hasCmdLine }
}

function Test-LivePS4104 {
    $marker = "PSTest_$(Get-Date -Format 'HHmmssff')"
    $before = Get-Date
    # FIX: no Invoke-Expression — direct Write-Output
    Write-Output $marker | Out-Null
    Start-Sleep -Seconds 3

    $events = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$before
    } -EA SilentlyContinue

    if (-not $events) { return $false }
    return ($null -ne ($events | Where-Object { $_.Message -match [regex]::Escape($marker) }))
}

function Invoke-Validation {
    Write-Log "PHASE 5 — Validation" -Level HEAD

    $checks = @(
        @{ Label='Credential Validation Audit';      Sub='Credential Validation';        S=$true;  F=$true  },
        @{ Label='Logon Audit';                      Sub='Logon';                        S=$true;  F=$true  },
        @{ Label='Logoff Audit';                     Sub='Logoff';                       S=$true;  F=$false },
        @{ Label='Account Lockout Audit';            Sub='Account Lockout';              S=$true;  F=$false },
        @{ Label='Special Logon Audit';              Sub='Special Logon';                S=$true;  F=$false },
        @{ Label='User Account Mgmt Audit';          Sub='User Account Management';      S=$true;  F=$true  },
        @{ Label='Security Group Mgmt Audit';        Sub='Security Group Management';    S=$true;  F=$false },
        @{ Label='Sensitive Privilege Use Audit';    Sub='Sensitive Privilege Use';      S=$true;  F=$true  },
        @{ Label='Process Creation Audit';           Sub='Process Creation';             S=$true;  F=$false },
        @{ Label='Audit Policy Change';              Sub='Audit Policy Change';          S=$true;  F=$true  },
        @{ Label='Auth Policy Change Audit';         Sub='Authentication Policy Change'; S=$true;  F=$false },
        @{ Label='Security State Change Audit';      Sub='Security State Change';        S=$true;  F=$true  }
    )

    foreach ($c in $checks) {
        $ok     = Test-AuditPolSetting -Sub $c.Sub -NeedSuccess $c.S -NeedFailure $c.F
        $status = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Log "  $($c.Label) — $status" -Level $status
        Add-Result $c.Label $status
    }

    # Registry checks
    $regChecks = @(
        @{ Label='CmdLine in Event 4688 (Reg)';
           Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit';
           Name='ProcessCreationIncludeCmdLine_Enabled' },
        @{ Label='PS Script Block Logging (Reg)';
           Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging';
           Name='EnableScriptBlockLogging' },
        @{ Label='PS Module Logging (Reg)';
           Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging';
           Name='EnableModuleLogging' }
    )

    foreach ($r in $regChecks) {
        $ok     = Test-RegDWord -Path $r.Path -Name $r.Name
        $status = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Log "  $($r.Label) — $status" -Level $status
        Add-Result $r.Label $status
    }

    # Security log size check (should be >= 1 GB)
    $logInfo = Get-WinEvent -ListLog 'Security'
    $logMB   = [math]::Round($logInfo.MaximumSizeInBytes / 1MB)
    $logOk   = $logInfo.MaximumSizeInBytes -ge 1073741824
    $status  = if ($logOk) { 'PASS' } else { 'FAIL' }
    Write-Log "  Security Log Size = $logMB MB — $status $(if(-not $logOk){'(needs ≥ 1024 MB)'})" -Level $status
    Add-Result 'Security Log Size ≥ 1 GB' $status

    # Live: Event 4688
    Write-Log "  Running live Event 4688 test..."
    $live = Test-LiveEvent4688
    if ($live.Found -and $live.HasCmdLine) {
        Write-Log "  LIVE 4688 + CmdLine — PASS" -Level PASS
        Add-Result 'LIVE Event 4688 + CmdLine' 'PASS' 'Event found, command line populated'
    } elseif ($live.Found) {
        Write-Log "  LIVE 4688 — FAIL: Event exists but CmdLine field is EMPTY" -Level FAIL
        Add-Result 'LIVE Event 4688 + CmdLine' 'FAIL' 'CmdLine field blank — registry key not applied'
    } else {
        Write-Log "  LIVE 4688 — FAIL: No event generated" -Level FAIL
        Add-Result 'LIVE Event 4688 + CmdLine' 'FAIL' 'No 4688 event — Process Creation audit not active'
    }

    # Live: Event 4104
    Write-Log "  Running live PS Script Block test (Event 4104)..."
    $ps4104  = Test-LivePS4104
    $status  = if ($ps4104) { 'PASS' } else { 'FAIL' }
    Write-Log "  LIVE PS ScriptBlock 4104 — $status" -Level $status
    Add-Result 'LIVE PS ScriptBlock Event 4104' $status
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6 — AUTO-FIX
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-AutoFix {
    Write-Log "PHASE 6 — Auto-Fix" -Level HEAD

    $failures = $script:Results | Where-Object Status -eq 'FAIL'
    if (-not $failures) {
        Write-Log "  No failures. Auto-Fix skipped." -Level PASS; return
    }

    foreach ($f in $failures) {
        Write-Log "  Fixing: $($f.Control)" -Level FIX
        $script:FixCount++

        switch -Wildcard ($f.Control) {
            'Credential Validation Audit'   { Set-AuditSubcategory 'Credential Validation'        $true $true  }
            'Logon Audit'                   { Set-AuditSubcategory 'Logon'                         $true $true  }
            'Logoff Audit'                  { Set-AuditSubcategory 'Logoff'                        $true $false }
            'Account Lockout Audit'         { Set-AuditSubcategory 'Account Lockout'               $true $false }
            'Special Logon Audit'           { Set-AuditSubcategory 'Special Logon'                 $true $false }
            'User Account Mgmt Audit'       { Set-AuditSubcategory 'User Account Management'       $true $true  }
            'Security Group Mgmt Audit'     { Set-AuditSubcategory 'Security Group Management'     $true $false }
            'Sensitive Privilege Use Audit' { Set-AuditSubcategory 'Sensitive Privilege Use'       $true $true  }
            'Process Creation Audit'        { Set-AuditSubcategory 'Process Creation'              $true $false }
            'Audit Policy Change'           { Set-AuditSubcategory 'Audit Policy Change'           $true $true  }
            'Auth Policy Change Audit'      { Set-AuditSubcategory 'Authentication Policy Change'  $true $false }
            'Security State Change Audit'   { Set-AuditSubcategory 'Security State Change'         $true $true  }
            'CmdLine in Event 4688 (Reg)' {
                $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
                if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                Set-ItemProperty -Path $p -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord -Force
            }
            'PS Script Block Logging (Reg)' {
                $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
                if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                Set-ItemProperty -Path $p -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -Force
            }
            'PS Module Logging (Reg)' {
                $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
                if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                Set-ItemProperty -Path $p -Name 'EnableModuleLogging' -Value 1 -Type DWord -Force
            }
            'Security Log Size*' {
                cmd /c "wevtutil sl Security /ms:1073741824 /rt:false" | Out-Null
            }
            'LIVE*' {
                Write-Log "    Live failure — downstream of above fixes. Will re-test." -Level FIX
            }
        }
    }

    Write-Log "  Re-running gpupdate /force after fixes..." -Level FIX
    cmd /c "gpupdate /force" | Out-Null
    Start-Sleep -Seconds 5

    Write-Log "PHASE 6B — Re-Validation" -Level HEAD
    $script:Results.Clear()
    Invoke-Validation
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 7 — FINAL REPORT
# ─────────────────────────────────────────────────────────────────────────────
function Write-FinalReport {
    Write-Log "`n══════════════════════════════════════════════════" -Level HEAD
    Write-Log "  AUDIT POLICY REPORT — Windows 10 Endpoint (VM2)" -Level HEAD
    Write-Log "  Host   : $env:COMPUTERNAME  |  User : $env:USERNAME"
    Write-Log "  Time   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Log "  Log    : $LogFile"
    Write-Log "  Mode   : $(if($WhatIf){'DRY RUN'}else{'APPLIED'})"
    Write-Log "══════════════════════════════════════════════════" -Level HEAD

    $pass  = ($script:Results | Where-Object Status -eq 'PASS').Count
    $fail  = ($script:Results | Where-Object Status -eq 'FAIL').Count
    $total = $script:Results.Count

    foreach ($r in $script:Results) {
        $detail = if ($r.Detail) { " | $($r.Detail)" } else { '' }
        Write-Log "  [$($r.Status)] $($r.Control)$detail" -Level $r.Status
    }

    Write-Log "──────────────────────────────────────────────────"
    Write-Log "  Total: $total  |  Passed: $pass  |  Failed: $fail"
    Write-Log "  Auto-Fix Attempts: $($script:FixCount)"
    Write-Log "══════════════════════════════════════════════════"

    if ($fail -gt 0) {
        Write-Log @"

  REMAINING FAILURES — Manual Checklist:
  ┌─────────────────────────────────────────────────────────────────┐
  │ 1. Confirm running as ADMINISTRATOR                             │
  │ 2. AD-joined: domain GPO may override local policy             │
  │    → Ask your AD admin to check GPOs linked to this machine OU │
  │ 3. Event log service running? → sc query eventlog              │
  │ 4. PS logging fail? → Get-ExecutionPolicy -List                │
  │ 5. Reboot and re-run this script if settings still not applied  │
  └─────────────────────────────────────────────────────────────────┘
"@ -Level FAIL
    } else {
        Write-Log "  ALL CONTROLS VERIFIED. Endpoint logging operational." -Level PASS
        Write-Log "  Active Event IDs: 4624,4625,4634,4672,4688,4719,4720,4726,4738,4740,4964,4104" -Level PASS
    }
}

# ── ENTRY POINT ───────────────────────────────────────────────────────────────
Write-Log "Windows 10 Endpoint Audit Policy Configurator v2 — Starting" -Level HEAD
Invoke-PreFlight
Set-AuditPolicies
Set-RegistryLogging
Set-SecurityLogSize
Invoke-GPUpdate
Invoke-Validation
Invoke-AutoFix
Write-FinalReport
Stop-Transcript
