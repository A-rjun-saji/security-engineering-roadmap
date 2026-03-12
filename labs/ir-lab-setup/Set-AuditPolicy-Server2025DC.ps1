#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Server 2025 Domain Controller — Audit Policy Configurator v2
    Target : VM4 — Windows Server 2025, Active Directory Domain Controller

.DESCRIPTION
    Phase 1  — Pre-Flight   : Verify OS, DC role, PS version
    Phase 2  — Configure    : DC-specific audit subcategories + registry
    Phase 3  — Log Size     : Security log = 1 GB, System log = 512 MB
    Phase 4  — Enforce      : gpupdate /force
    Phase 5  — Validate     : Policy checks + live event generation
    Phase 6  — Auto-Fix     : Re-apply failures + re-validate
    Phase 7  — Report       : Final pass/fail summary

    DC-SPECIFIC controls beyond the endpoint script:
      - Kerberos Authentication (4768, 4771, 4769) — Pass-the-Ticket, AS-REP Roasting
      - Kerberos Service Ticket Operations           — Golden/Silver Ticket detection
      - Directory Service Access/Changes (4662/5136) — AD object modification
      - Computer Account Management (4741/4743)      — Rogue machine account detection
      - Other Account Management Events              — Catch-all account ops
      - DS Replication (4928/4929)                   — DCSync attack detection

.NOTES
    Run as Administrator on Windows Server 2025 Domain Controller only.
    PowerShell 5.1+ required.
    Author  : Security Engineering Roadmap | github: A-rjun-saji
    Branch  : phase-1-ir-foundations
    Version : 2.0 — Fixes $args bug, Get-WmiObject, IEX; adds DC-specific controls
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$WhatIf   # Dry-run: shows what would be changed without applying
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Globals ───────────────────────────────────────────────────────────────────
$script:Results  = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:FixCount = 0
$LogFile         = "$env:SystemDrive\AuditPolicy_DC_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Start-Transcript -Path "$env:SystemDrive\AuditPolicy_DC_Transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log" -Append

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
# PHASE 1 — PRE-FLIGHT (DC-Specific)
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-PreFlight {
    Write-Log "PHASE 1 — Pre-Flight Checks (Domain Controller)" -Level HEAD

    # FIX: Get-CimInstance replaces deprecated Get-WmiObject
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    Write-Log "  OS      : $($os.Caption)"
    Write-Log "  Build   : $($os.BuildNumber)"
    Write-Log "  Host    : $env:COMPUTERNAME"

    if ($os.Caption -notmatch 'Server 2025') {
        Write-Log "  WARNING: This script targets Server 2025. Detected: $($os.Caption)" -Level WARN
    }

    # Verify ADDS role is installed (confirms this is actually a DC)
    $dcDiag = cmd /c "dcdiag /test:advertising /q 2>&1"
    if ($dcDiag -match 'passed') {
        Write-Log "  DC Role : Verified — dcdiag advertising test passed" -Level PASS
    } else {
        Write-Log "  DC Role : WARNING — dcdiag check inconclusive. Verify this is a DC." -Level WARN
    }

    # Check if SYSVOL is shared (confirms DC is functional)
    $sysvolShare = Get-SmbShare -Name 'SYSVOL' -ErrorAction SilentlyContinue
    if ($sysvolShare) {
        Write-Log "  SYSVOL  : Share present — DC is functional" -Level PASS
    } else {
        Write-Log "  SYSVOL  : NOT FOUND — DC may not be fully promoted" -Level WARN
    }

    # GPO warning — on DC, settings apply to Default Domain Controllers Policy
    Write-Log "  NOTE: On DCs, audit settings should ideally be applied via" -Level WARN
    Write-Log "        Default Domain Controllers Policy GPO (GPMC), not local policy." -Level WARN
    Write-Log "        This script applies local policy. Domain GPO takes precedence." -Level WARN

    if ($WhatIf) {
        Write-Log "  MODE    : DRY RUN (WhatIf) — No changes will be applied" -Level WARN
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — CONFIGURE AUDIT POLICIES (DC-Specific Full Set)
# ─────────────────────────────────────────────────────────────────────────────
function Set-AuditPolicies {
    Write-Log "PHASE 2 — Configuring Domain Controller Audit Policies" -Level HEAD

    if (-not $WhatIf) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
            -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Type DWord -Force
    }
    Write-Log "  SCENoApplyLegacyAuditPolicy = 1"

    # ── DC Audit Policy Table ─────────────────────────────────────────────────
    # Includes all endpoint policies PLUS DC-specific controls
    $policies = @(

        # ── Account Logon (Kerberos — DC-critical) ───────────────────────────
        # These subcategories only produce meaningful data on DCs
        @{ Sub='Credential Validation';               S=$true;  F=$true;  Note='4624/4625 — NTLM auth'       },
        @{ Sub='Kerberos Authentication Service';     S=$true;  F=$true;  Note='4768/4771 — AS-REP Roasting' },
        @{ Sub='Kerberos Service Ticket Operations';  S=$true;  F=$true;  Note='4769 — Silver/Golden Ticket' },
        @{ Sub='Other Account Logon Events';          S=$true;  F=$true;  Note='4649 — replay attack'        },

        # ── Account Management ────────────────────────────────────────────────
        @{ Sub='User Account Management';             S=$true;  F=$true;  Note='4720/4726/4738'              },
        @{ Sub='Computer Account Management';         S=$true;  F=$true;  Note='4741/4743 — rogue machines'  },
        @{ Sub='Security Group Management';           S=$true;  F=$true;  Note='4728/4732/4756'              },
        @{ Sub='Other Account Management Events';     S=$true;  F=$true;  Note='catch-all account ops'       },

        # ── Logon / Logoff ────────────────────────────────────────────────────
        @{ Sub='Logon';                               S=$true;  F=$true;  Note='4624'                        },
        @{ Sub='Logoff';                              S=$true;  F=$false; Note='4634'                        },
        @{ Sub='Account Lockout';                     S=$true;  F=$false; Note='4740 — brute force'          },
        @{ Sub='Special Logon';                       S=$true;  F=$false; Note='4964 — admin-equivalent'     },

        # ── Directory Services (DC-ONLY) ─────────────────────────────────────
        @{ Sub='Directory Service Access';            S=$true;  F=$true;  Note='4662 — AD object read'       },
        @{ Sub='Directory Service Changes';           S=$true;  F=$true;  Note='5136 — AD object modified'   },
        @{ Sub='Directory Service Replication';       S=$true;  F=$true;  Note='4928/4929 — DCSync detect'   },

        # ── Privilege Use ─────────────────────────────────────────────────────
        @{ Sub='Sensitive Privilege Use';             S=$true;  F=$true;  Note='4672 — lateral movement'     },

        # ── Detailed Tracking ─────────────────────────────────────────────────
        @{ Sub='Process Creation';                    S=$true;  F=$false; Note='4688'                        },

        # ── Policy Change ─────────────────────────────────────────────────────
        @{ Sub='Audit Policy Change';                 S=$true;  F=$true;  Note='4719 — detect log tampering' },
        @{ Sub='Authentication Policy Change';        S=$true;  F=$true;  Note='4706/4713 — Kerberos policy' },
        @{ Sub='Authorization Policy Change';         S=$true;  F=$false; Note='4704 — user rights change'   },

        # ── System ───────────────────────────────────────────────────────────
        @{ Sub='Security State Change';               S=$true;  F=$true;  Note='4608 — system integrity'     },
        @{ Sub='Security System Extension';           S=$true;  F=$true;  Note='4697 — service install'      },
        @{ Sub='System Integrity';                    S=$true;  F=$true;  Note='4616 — time tamper'          }
    )

    foreach ($p in $policies) {
        $ok  = Set-AuditSubcategory -SubCategory $p.Sub -Success $p.S -Failure $p.F
        $lvl = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Log "  [SET] $($p.Sub) — $(if($ok){'OK'}else{'FAILED'})  [$($p.Note)]" -Level $lvl
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2B — REGISTRY SETTINGS
# ─────────────────────────────────────────────────────────────────────────────
function Set-RegistryLogging {
    Write-Log "PHASE 2B — Registry-Based Logging" -Level HEAD

    if ($WhatIf) {
        Write-Log "  [WHATIF] Would write CmdLine, ScriptBlock, ModuleLogging, Transcription keys" -Level WARN
        return
    }

    # 1. CmdLine in Event 4688
    $cmdPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    if (-not (Test-Path $cmdPath)) { New-Item -Path $cmdPath -Force | Out-Null }
    Set-ItemProperty -Path $cmdPath -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord -Force
    Write-Log "  [SET] CmdLine in Event 4688 — OK"

    # 2. PowerShell Script Block Logging
    $sbPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (-not (Test-Path $sbPath)) { New-Item -Path $sbPath -Force | Out-Null }
    Set-ItemProperty -Path $sbPath -Name 'EnableScriptBlockLogging'           -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $sbPath -Name 'EnableScriptBlockInvocationLogging' -Value 1 -Type DWord -Force
    Write-Log "  [SET] PS Script Block Logging — OK"

    # 3. PowerShell Module Logging
    $modPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    if (-not (Test-Path $modPath)) { New-Item -Path $modPath -Force | Out-Null }
    Set-ItemProperty -Path $modPath -Name 'EnableModuleLogging' -Value 1 -Type DWord -Force
    $modNames = "$modPath\ModuleNames"
    if (-not (Test-Path $modNames)) { New-Item -Path $modNames -Force | Out-Null }
    Set-ItemProperty -Path $modNames -Name '*' -Value '*' -Type String -Force
    Write-Log "  [SET] PS Module Logging — OK"

    # 4. PowerShell Transcription
    $transPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    if (-not (Test-Path $transPath)) { New-Item -Path $transPath -Force | Out-Null }
    Set-ItemProperty -Path $transPath -Name 'EnableTranscripting'    -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $transPath -Name 'EnableInvocationHeader'  -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $transPath -Name 'OutputDirectory'         -Value "$env:SystemDrive\PSTranscripts" -Type String -Force
    Write-Log "  [SET] PS Transcription → $env:SystemDrive\PSTranscripts — OK"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — LOG SIZES (DC gets larger allocations)
# ─────────────────────────────────────────────────────────────────────────────
function Set-EventLogSizes {
    Write-Log "PHASE 3 — Event Log Size Configuration (DC)" -Level HEAD

    if ($WhatIf) {
        Write-Log "  [WHATIF] Security=1GB, System=512MB, Directory Service=512MB" -Level WARN
        return
    }

    $logSizes = @(
        @{ Log='Security';           Size=1073741824 },   # 1 GB
        @{ Log='System';             Size=536870912  },   # 512 MB
        @{ Log='Directory Service';  Size=536870912  }    # 512 MB — DC-specific AD log
    )

    foreach ($l in $logSizes) {
        try {
            cmd /c "wevtutil sl `"$($l.Log)`" /ms:$($l.Size) /rt:false" | Out-Null
            $mb = [math]::Round($l.Size / 1MB)
            Write-Log "  [SET] $($l.Log) log = $mb MB — OK" -Level PASS
        } catch {
            Write-Log "  [ERR] $($l.Log): $($_.Exception.Message)" -Level FAIL
        }
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
    Start-Sleep -Seconds 5   # DC GP refresh takes slightly longer
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5 — VALIDATE
# ─────────────────────────────────────────────────────────────────────────────
function Test-AuditPolSetting {
    param([string]$Sub, [bool]$NeedSuccess, [bool]$NeedFailure = $false)
    $raw  = cmd /c "auditpol /get /subcategory:`"$Sub`" 2>&1"
    $line = $raw | Where-Object { $_ -match [regex]::Escape($Sub) } | Select-Object -First 1
    if (-not $line)                                   { return $false }
    if ($line -match 'No Auditing')                   { return $false }
    if ($NeedSuccess -and $line -notmatch 'Success')  { return $false }
    if ($NeedFailure -and $line -notmatch 'Failure')  { return $false }
    return $true
}

function Test-RegDWord {
    param([string]$Path, [string]$Name, [int]$Expected = 1)
    try { return ((Get-ItemPropertyValue -Path $Path -Name $Name -EA Stop) -eq $Expected) }
    catch { return $false }
}

function Test-LiveEvent4688 {
    $marker = "DCTest-$(Get-Date -Format 'HHmmssff')"
    $before = Get-Date
    # FIX: no Invoke-Expression — direct Start-Process
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
        # Account Logon
        @{ Label='Credential Validation Audit';              Sub='Credential Validation';              S=$true;  F=$true  },
        @{ Label='Kerberos Auth Service Audit';              Sub='Kerberos Authentication Service';    S=$true;  F=$true  },
        @{ Label='Kerberos SvcTicket Ops Audit';             Sub='Kerberos Service Ticket Operations'; S=$true;  F=$true  },
        @{ Label='Other Account Logon Events Audit';         Sub='Other Account Logon Events';         S=$true;  F=$true  },
        # Account Management
        @{ Label='User Account Mgmt Audit';                  Sub='User Account Management';            S=$true;  F=$true  },
        @{ Label='Computer Account Mgmt Audit';              Sub='Computer Account Management';        S=$true;  F=$true  },
        @{ Label='Security Group Mgmt Audit';                Sub='Security Group Management';          S=$true;  F=$true  },
        @{ Label='Other Account Mgmt Audit';                 Sub='Other Account Management Events';    S=$true;  F=$true  },
        # Logon/Logoff
        @{ Label='Logon Audit';                              Sub='Logon';                              S=$true;  F=$true  },
        @{ Label='Logoff Audit';                             Sub='Logoff';                             S=$true;  F=$false },
        @{ Label='Account Lockout Audit';                    Sub='Account Lockout';                    S=$true;  F=$false },
        @{ Label='Special Logon Audit';                      Sub='Special Logon';                      S=$true;  F=$false },
        # Directory Services (DC-only)
        @{ Label='Directory Service Access Audit';           Sub='Directory Service Access';           S=$true;  F=$true  },
        @{ Label='Directory Service Changes Audit';          Sub='Directory Service Changes';          S=$true;  F=$true  },
        @{ Label='Directory Service Replication Audit';      Sub='Directory Service Replication';      S=$true;  F=$true  },
        # Privilege Use
        @{ Label='Sensitive Privilege Use Audit';            Sub='Sensitive Privilege Use';            S=$true;  F=$true  },
        # Detailed Tracking
        @{ Label='Process Creation Audit';                   Sub='Process Creation';                   S=$true;  F=$false },
        # Policy Change
        @{ Label='Audit Policy Change';                      Sub='Audit Policy Change';                S=$true;  F=$true  },
        @{ Label='Auth Policy Change Audit';                 Sub='Authentication Policy Change';       S=$true;  F=$true  },
        @{ Label='Auth Policy Change Audit';                 Sub='Authorization Policy Change';        S=$true;  F=$false },
        # System
        @{ Label='Security State Change Audit';              Sub='Security State Change';              S=$true;  F=$true  },
        @{ Label='Security System Extension Audit';          Sub='Security System Extension';          S=$true;  F=$true  },
        @{ Label='System Integrity Audit';                   Sub='System Integrity';                   S=$true;  F=$true  }
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

    # Log size checks
    foreach ($logName in @('Security','Directory Service')) {
        try {
            $li     = Get-WinEvent -ListLog $logName -EA Stop
            $mb     = [math]::Round($li.MaximumSizeInBytes / 1MB)
            $minReq = if ($logName -eq 'Security') { 1024 } else { 512 }
            $logOk  = $mb -ge $minReq
            $status = if ($logOk) { 'PASS' } else { 'FAIL' }
            Write-Log "  $logName Log = $mb MB (need ≥ $minReq MB) — $status" -Level $status
            Add-Result "$logName Log Size" $status
        } catch {
            Write-Log "  $logName Log — FAIL (log not accessible)" -Level FAIL
            Add-Result "$logName Log Size" 'FAIL'
        }
    }

    # Live: Event 4688
    Write-Log "  Running live Event 4688 test..."
    $live = Test-LiveEvent4688
    if ($live.Found -and $live.HasCmdLine) {
        Write-Log "  LIVE 4688 + CmdLine — PASS" -Level PASS
        Add-Result 'LIVE Event 4688 + CmdLine' 'PASS'
    } elseif ($live.Found) {
        Write-Log "  LIVE 4688 — FAIL: CmdLine field empty" -Level FAIL
        Add-Result 'LIVE Event 4688 + CmdLine' 'FAIL' 'CmdLine blank'
    } else {
        Write-Log "  LIVE 4688 — FAIL: No event generated" -Level FAIL
        Add-Result 'LIVE Event 4688 + CmdLine' 'FAIL' 'No 4688 event'
    }

    # Live: Event 4104
    Write-Log "  Running live PS Script Block test (Event 4104)..."
    $ps4104 = Test-LivePS4104
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
            'Credential Validation Audit'         { Set-AuditSubcategory 'Credential Validation'               $true $true  }
            'Kerberos Auth Service Audit'         { Set-AuditSubcategory 'Kerberos Authentication Service'     $true $true  }
            'Kerberos SvcTicket Ops Audit'        { Set-AuditSubcategory 'Kerberos Service Ticket Operations'  $true $true  }
            'Other Account Logon Events Audit'    { Set-AuditSubcategory 'Other Account Logon Events'          $true $true  }
            'User Account Mgmt Audit'             { Set-AuditSubcategory 'User Account Management'             $true $true  }
            'Computer Account Mgmt Audit'         { Set-AuditSubcategory 'Computer Account Management'         $true $true  }
            'Security Group Mgmt Audit'           { Set-AuditSubcategory 'Security Group Management'           $true $true  }
            'Other Account Mgmt Audit'            { Set-AuditSubcategory 'Other Account Management Events'     $true $true  }
            'Logon Audit'                         { Set-AuditSubcategory 'Logon'                               $true $true  }
            'Logoff Audit'                        { Set-AuditSubcategory 'Logoff'                              $true $false }
            'Account Lockout Audit'               { Set-AuditSubcategory 'Account Lockout'                     $true $false }
            'Special Logon Audit'                 { Set-AuditSubcategory 'Special Logon'                       $true $false }
            'Directory Service Access Audit'      { Set-AuditSubcategory 'Directory Service Access'            $true $true  }
            'Directory Service Changes Audit'     { Set-AuditSubcategory 'Directory Service Changes'           $true $true  }
            'Directory Service Replication Audit' { Set-AuditSubcategory 'Directory Service Replication'       $true $true  }
            'Sensitive Privilege Use Audit'       { Set-AuditSubcategory 'Sensitive Privilege Use'             $true $true  }
            'Process Creation Audit'              { Set-AuditSubcategory 'Process Creation'                    $true $false }
            'Audit Policy Change'                 { Set-AuditSubcategory 'Audit Policy Change'                 $true $true  }
            'Auth Policy Change Audit'            { Set-AuditSubcategory 'Authentication Policy Change'        $true $true  }
            'Security State Change Audit'         { Set-AuditSubcategory 'Security State Change'               $true $true  }
            'Security System Extension Audit'     { Set-AuditSubcategory 'Security System Extension'           $true $true  }
            'System Integrity Audit'              { Set-AuditSubcategory 'System Integrity'                    $true $true  }
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
            'Security Log Size' {
                cmd /c "wevtutil sl Security /ms:1073741824 /rt:false" | Out-Null
            }
            'Directory Service Log Size' {
                cmd /c "wevtutil sl `"Directory Service`" /ms:536870912 /rt:false" | Out-Null
            }
            'LIVE*' {
                Write-Log "    Live failure — downstream of above fixes." -Level FIX
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
    Write-Log "`n══════════════════════════════════════════════════════" -Level HEAD
    Write-Log "  AUDIT POLICY REPORT — Windows Server 2025 DC (VM4)"  -Level HEAD
    Write-Log "  Host   : $env:COMPUTERNAME  |  User : $env:USERNAME"
    Write-Log "  Time   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Log "  Log    : $LogFile"
    Write-Log "  Mode   : $(if($WhatIf){'DRY RUN'}else{'APPLIED'})"
    Write-Log "══════════════════════════════════════════════════════" -Level HEAD

    $pass  = ($script:Results | Where-Object Status -eq 'PASS').Count
    $fail  = ($script:Results | Where-Object Status -eq 'FAIL').Count
    $total = $script:Results.Count

    foreach ($r in $script:Results) {
        $detail = if ($r.Detail) { " | $($r.Detail)" } else { '' }
        Write-Log "  [$($r.Status)] $($r.Control)$detail" -Level $r.Status
    }

    Write-Log "──────────────────────────────────────────────────────"
    Write-Log "  Total: $total  |  Passed: $pass  |  Failed: $fail"
    Write-Log "  Auto-Fix Attempts: $($script:FixCount)"
    Write-Log "══════════════════════════════════════════════════════"

    if ($fail -gt 0) {
        Write-Log @"

  REMAINING FAILURES — DC Manual Checklist:
  ┌──────────────────────────────────────────────────────────────────────┐
  │ 1. Confirm running as Domain Admin (not just local admin)            │
  │ 2. Check Default Domain Controllers Policy in GPMC                  │
  │    → It may be overriding local audit settings                      │
  │    → Correct fix: edit audit policy INSIDE that GPO, not locally    │
  │ 3. Verify Event Log service: sc query eventlog                      │
  │ 4. Directory Service log missing? → DC not fully promoted yet       │
  │ 5. Kerberos subcategories missing? Confirm this IS the DC           │
  │    → These subcategories are only meaningful on domain controllers  │
  │ 6. Reboot may be required for Server 2025 registry changes          │
  └──────────────────────────────────────────────────────────────────────┘
"@ -Level FAIL
    } else {
        Write-Log "  ALL CONTROLS VERIFIED. DC logging operational." -Level PASS
        Write-Log "  Active: 4624,4625,4634,4662,4672,4688,4706,4719,4720,4726,4728,4738,4740,4741,4768,4769,4771,5136,4104" -Level PASS
    }
}

# ── ENTRY POINT ───────────────────────────────────────────────────────────────
Write-Log "Windows Server 2025 DC Audit Policy Configurator v2 — Starting" -Level HEAD
Invoke-PreFlight
Set-AuditPolicies
Set-RegistryLogging
Set-EventLogSizes
Invoke-GPUpdate
Invoke-Validation
Invoke-AutoFix
Write-FinalReport
Stop-Transcript
