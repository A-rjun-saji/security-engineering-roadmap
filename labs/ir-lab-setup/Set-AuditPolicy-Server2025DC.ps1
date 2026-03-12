#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Server 2025 Domain Controller - Audit Policy Configurator v2
    Target : VM4 - Windows Server 2025, Active Directory Domain Controller
.NOTES
    Run as Administrator. PowerShell 5.1+ required.
    Author  : Security Engineering Roadmap | github: A-rjun-saji
    Version : 2.1 - Syntax clean rebuild
#>

[CmdletBinding()]
param([switch]$WhatIf)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Results  = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:FixCount = 0
$LogFile         = "$env:SystemDrive\AuditPolicy_DC_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Start-Transcript -Path "$env:SystemDrive\AuditPolicy_DC_Transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log" -Append

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line  = "[$ts][$Level] $Message"
    $color = switch ($Level) {
        'PASS' { 'Green'   }
        'FAIL' { 'Red'     }
        'FIX'  { 'Yellow'  }
        'HEAD' { 'Cyan'    }
        'WARN' { 'Magenta' }
        default { 'White'  }
    }
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $LogFile -Value $line
}

function Add-Result {
    param([string]$Control, [string]$Status, [string]$Detail = '')
    $script:Results.Add([PSCustomObject]@{ Control = $Control; Status = $Status; Detail = $Detail })
}

function Set-AuditSubcategory {
    param([string]$SubCategory, [bool]$Success, [bool]$Failure)
    $auditArgs = "/subcategory:`"$SubCategory`""
    if ($Success) { $auditArgs += ' /success:enable' }
    if ($Failure) { $auditArgs += ' /failure:enable' }
    if ($WhatIf) { Write-Log "  [WHATIF] auditpol $auditArgs" -Level WARN; return $true }
    $null = cmd /c "auditpol $auditArgs 2>&1"
    return ($LASTEXITCODE -eq 0)
}

function Invoke-PreFlight {
    Write-Log 'PHASE 1 - Pre-Flight Checks' -Level HEAD
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    Write-Log "  OS    : $($os.Caption)"
    Write-Log "  Build : $($os.BuildNumber)"
    Write-Log "  Host  : $env:COMPUTERNAME"
    if ($os.Caption -notmatch 'Server 2025') { Write-Log "  WARNING: Detected: $($os.Caption)" -Level WARN }
    $sysvolShare = Get-SmbShare -Name 'SYSVOL' -ErrorAction SilentlyContinue
    if ($sysvolShare) { Write-Log '  SYSVOL : OK - DC is functional' -Level PASS }
    else { Write-Log '  SYSVOL : NOT FOUND - DC may not be fully promoted' -Level WARN }
    Write-Log '  NOTE: Domain GPO takes precedence over local policy on DCs.' -Level WARN
    if ($PSVersionTable.PSVersion.Major -lt 5) { Write-Log '  FAIL: PowerShell 5.1+ required' -Level FAIL; exit 1 }
    if ($WhatIf) { Write-Log '  MODE : DRY RUN - No changes will be applied' -Level WARN }
}

function Set-AuditPolicies {
    Write-Log 'PHASE 2 - Configuring DC Audit Policies' -Level HEAD
    if (-not $WhatIf) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Type DWord -Force
    }
    Write-Log '  SCENoApplyLegacyAuditPolicy = 1'

    $policies = @(
        @{ Sub = 'Credential Validation';               S = $true;  F = $true  },
        @{ Sub = 'Kerberos Authentication Service';     S = $true;  F = $true  },
        @{ Sub = 'Kerberos Service Ticket Operations';  S = $true;  F = $true  },
        @{ Sub = 'Other Account Logon Events';          S = $true;  F = $true  },
        @{ Sub = 'User Account Management';             S = $true;  F = $true  },
        @{ Sub = 'Computer Account Management';         S = $true;  F = $true  },
        @{ Sub = 'Security Group Management';           S = $true;  F = $true  },
        @{ Sub = 'Other Account Management Events';     S = $true;  F = $true  },
        @{ Sub = 'Logon';                               S = $true;  F = $true  },
        @{ Sub = 'Logoff';                              S = $true;  F = $false },
        @{ Sub = 'Account Lockout';                     S = $true;  F = $false },
        @{ Sub = 'Special Logon';                       S = $true;  F = $false },
        @{ Sub = 'Directory Service Access';            S = $true;  F = $true  },
        @{ Sub = 'Directory Service Changes';           S = $true;  F = $true  },
        @{ Sub = 'Directory Service Replication';       S = $true;  F = $true  },
        @{ Sub = 'Sensitive Privilege Use';             S = $true;  F = $true  },
        @{ Sub = 'Process Creation';                    S = $true;  F = $false },
        @{ Sub = 'Audit Policy Change';                 S = $true;  F = $true  },
        @{ Sub = 'Authentication Policy Change';        S = $true;  F = $true  },
        @{ Sub = 'Authorization Policy Change';         S = $true;  F = $false },
        @{ Sub = 'Security State Change';               S = $true;  F = $true  },
        @{ Sub = 'Security System Extension';           S = $true;  F = $true  },
        @{ Sub = 'System Integrity';                    S = $true;  F = $true  }
    )

    foreach ($p in $policies) {
        $ok  = Set-AuditSubcategory -SubCategory $p.Sub -Success $p.S -Failure $p.F
        $lvl = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Log "  [SET] $($p.Sub) - $(if ($ok) { 'OK' } else { 'FAILED' })" -Level $lvl
    }
}

function Set-RegistryLogging {
    Write-Log 'PHASE 2B - Registry-Based Logging' -Level HEAD
    if ($WhatIf) { Write-Log '  [WHATIF] Would write registry keys' -Level WARN; return }

    $cmdPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    if (-not (Test-Path $cmdPath)) { New-Item -Path $cmdPath -Force | Out-Null }
    Set-ItemProperty -Path $cmdPath -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord -Force
    Write-Log '  [SET] CmdLine in Event 4688 - OK'

    $sbPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (-not (Test-Path $sbPath)) { New-Item -Path $sbPath -Force | Out-Null }
    Set-ItemProperty -Path $sbPath -Name 'EnableScriptBlockLogging'           -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $sbPath -Name 'EnableScriptBlockInvocationLogging' -Value 1 -Type DWord -Force
    Write-Log '  [SET] PS Script Block Logging - OK'

    $modPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    if (-not (Test-Path $modPath)) { New-Item -Path $modPath -Force | Out-Null }
    Set-ItemProperty -Path $modPath -Name 'EnableModuleLogging' -Value 1 -Type DWord -Force
    $modNames = "$modPath\ModuleNames"
    if (-not (Test-Path $modNames)) { New-Item -Path $modNames -Force | Out-Null }
    Set-ItemProperty -Path $modNames -Name '*' -Value '*' -Type String -Force
    Write-Log '  [SET] PS Module Logging - OK'

    $transPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    if (-not (Test-Path $transPath)) { New-Item -Path $transPath -Force | Out-Null }
    Set-ItemProperty -Path $transPath -Name 'EnableTranscripting'    -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $transPath -Name 'EnableInvocationHeader' -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $transPath -Name 'OutputDirectory'        -Value "$env:SystemDrive\PSTranscripts" -Type String -Force
    Write-Log "  [SET] PS Transcription output: $env:SystemDrive\PSTranscripts - OK"
}

function Set-EventLogSizes {
    Write-Log 'PHASE 3 - Event Log Sizes' -Level HEAD
    if ($WhatIf) { Write-Log '  [WHATIF] Security=1GB, System=512MB, Directory Service=512MB' -Level WARN; return }

    $logSizes = @(
        @{ Log = 'Security';          Size = 1073741824 },
        @{ Log = 'System';            Size = 536870912  },
        @{ Log = 'Directory Service'; Size = 536870912  }
    )

    foreach ($l in $logSizes) {
        try {
            $null = cmd /c "wevtutil sl `"$($l.Log)`" /ms:$($l.Size) /rt:false 2>&1"
            $mb   = [math]::Round($l.Size / 1MB)
            Write-Log "  [SET] $($l.Log) = $mb MB - OK" -Level PASS
        } catch {
            Write-Log "  [ERR] $($l.Log): $($_.Exception.Message)" -Level FAIL
        }
    }
}

function Invoke-GPUpdate {
    Write-Log 'PHASE 4 - gpupdate /force' -Level HEAD
    if ($WhatIf) { Write-Log '  [WHATIF] Would run: gpupdate /force' -Level WARN; return }
    $out = cmd /c 'gpupdate /force 2>&1'
    Write-Log "  $($out[-1])"
    Start-Sleep -Seconds 5
}

function Test-AuditPolSetting {
    param([string]$Sub, [bool]$NeedSuccess, [bool]$NeedFailure = $false)
    $raw  = cmd /c "auditpol /get /subcategory:`"$Sub`" 2>&1"
    $line = $raw | Where-Object { $_ -match [regex]::Escape($Sub) } | Select-Object -First 1
    if (-not $line)                                  { return $false }
    if ($line -match 'No Auditing')                  { return $false }
    if ($NeedSuccess -and $line -notmatch 'Success') { return $false }
    if ($NeedFailure -and $line -notmatch 'Failure') { return $false }
    return $true
}

function Test-RegDWord {
    param([string]$Path, [string]$Name, [int]$Expected = 1)
    try { return ((Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop) -eq $Expected) }
    catch { return $false }
}

function Test-LiveEvent4688 {
    $marker = "DCTest-$(Get-Date -Format 'HHmmssff')"
    $before = Get-Date
    Start-Process -FilePath 'cmd.exe' -ArgumentList "/c echo $marker" -WindowStyle Hidden -Wait
    Start-Sleep -Seconds 3

    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $before } -ErrorAction SilentlyContinue
    if (-not $events) { return @{ Found = $false; HasCmdLine = $false } }

    $match      = $events | Where-Object { $_.Message -match [regex]::Escape($marker) }
    $found      = ($null -ne $match)
    $hasCmdLine = $false
    if ($found) {
        $hasCmdLine = ($match | Select-Object -First 1).Message -match 'Process Command Line\s*:\s*\S+'
    }
    return @{ Found = $found; HasCmdLine = $hasCmdLine }
}

function Test-LivePS4104 {
    $marker = "PSTest_$(Get-Date -Format 'HHmmssff')"
    $before = Get-Date
    Write-Output $marker | Out-Null
    Start-Sleep -Seconds 3

    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-PowerShell/Operational'
        Id        = 4104
        StartTime = $before
    } -ErrorAction SilentlyContinue

    if (-not $events) { return $false }
    return ($null -ne ($events | Where-Object { $_.Message -match [regex]::Escape($marker) }))
}

function Invoke-Validation {
    Write-Log 'PHASE 5 - Validation' -Level HEAD

    $checks = @(
        @{ Label = 'Credential Validation Audit';            Sub = 'Credential Validation';               S = $true;  F = $true  },
        @{ Label = 'Kerberos Auth Service Audit';            Sub = 'Kerberos Authentication Service';     S = $true;  F = $true  },
        @{ Label = 'Kerberos SvcTicket Ops Audit';           Sub = 'Kerberos Service Ticket Operations';  S = $true;  F = $true  },
        @{ Label = 'Other Account Logon Events Audit';       Sub = 'Other Account Logon Events';          S = $true;  F = $true  },
        @{ Label = 'User Account Mgmt Audit';                Sub = 'User Account Management';             S = $true;  F = $true  },
        @{ Label = 'Computer Account Mgmt Audit';            Sub = 'Computer Account Management';         S = $true;  F = $true  },
        @{ Label = 'Security Group Mgmt Audit';              Sub = 'Security Group Management';           S = $true;  F = $true  },
        @{ Label = 'Other Account Mgmt Audit';               Sub = 'Other Account Management Events';     S = $true;  F = $true  },
        @{ Label = 'Logon Audit';                            Sub = 'Logon';                               S = $true;  F = $true  },
        @{ Label = 'Logoff Audit';                           Sub = 'Logoff';                              S = $true;  F = $false },
        @{ Label = 'Account Lockout Audit';                  Sub = 'Account Lockout';                     S = $true;  F = $false },
        @{ Label = 'Special Logon Audit';                    Sub = 'Special Logon';                       S = $true;  F = $false },
        @{ Label = 'Directory Service Access Audit';         Sub = 'Directory Service Access';            S = $true;  F = $true  },
        @{ Label = 'Directory Service Changes Audit';        Sub = 'Directory Service Changes';           S = $true;  F = $true  },
        @{ Label = 'Directory Service Replication Audit';    Sub = 'Directory Service Replication';       S = $true;  F = $true  },
        @{ Label = 'Sensitive Privilege Use Audit';          Sub = 'Sensitive Privilege Use';             S = $true;  F = $true  },
        @{ Label = 'Process Creation Audit';                 Sub = 'Process Creation';                    S = $true;  F = $false },
        @{ Label = 'Audit Policy Change';                    Sub = 'Audit Policy Change';                 S = $true;  F = $true  },
        @{ Label = 'Auth Policy Change Audit';               Sub = 'Authentication Policy Change';        S = $true;  F = $true  },
        @{ Label = 'Authorization Policy Change Audit';      Sub = 'Authorization Policy Change';         S = $true;  F = $false },
        @{ Label = 'Security State Change Audit';            Sub = 'Security State Change';               S = $true;  F = $true  },
        @{ Label = 'Security System Extension Audit';        Sub = 'Security System Extension';           S = $true;  F = $true  },
        @{ Label = 'System Integrity Audit';                 Sub = 'System Integrity';                    S = $true;  F = $true  }
    )

    foreach ($c in $checks) {
        $ok     = Test-AuditPolSetting -Sub $c.Sub -NeedSuccess $c.S -NeedFailure $c.F
        $status = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Log "  $($c.Label) - $status" -Level $status
        Add-Result $c.Label $status
    }

    $regChecks = @(
        @{ Label = 'CmdLine in Event 4688 (Reg)';
           Path  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit';
           Name  = 'ProcessCreationIncludeCmdLine_Enabled' },
        @{ Label = 'PS Script Block Logging (Reg)';
           Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging';
           Name  = 'EnableScriptBlockLogging' },
        @{ Label = 'PS Module Logging (Reg)';
           Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging';
           Name  = 'EnableModuleLogging' }
    )

    foreach ($r in $regChecks) {
        $ok     = Test-RegDWord -Path $r.Path -Name $r.Name
        $status = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Log "  $($r.Label) - $status" -Level $status
        Add-Result $r.Label $status
    }

    foreach ($logName in @('Security', 'Directory Service')) {
        try {
            $li     = Get-WinEvent -ListLog $logName -ErrorAction Stop
            $mb     = [math]::Round($li.MaximumSizeInBytes / 1MB)
            $minReq = if ($logName -eq 'Security') { 1024 } else { 512 }
            $logOk  = $mb -ge $minReq
            $status = if ($logOk) { 'PASS' } else { 'FAIL' }
            Write-Log "  $logName Log = $mb MB (need >= $minReq MB) - $status" -Level $status
            Add-Result "$logName Log Size" $status
        } catch {
            Write-Log "  $logName Log - FAIL (not accessible)" -Level FAIL
            Add-Result "$logName Log Size" 'FAIL'
        }
    }

    Write-Log '  Running live Event 4688 test...'
    $live = Test-LiveEvent4688
    if ($live.Found -and $live.HasCmdLine) {
        Write-Log '  LIVE 4688 + CmdLine - PASS' -Level PASS
        Add-Result 'LIVE Event 4688 + CmdLine' 'PASS' 'Event found, command line populated'
    } elseif ($live.Found) {
        Write-Log '  LIVE 4688 - FAIL: CmdLine field empty' -Level FAIL
        Add-Result 'LIVE Event 4688 + CmdLine' 'FAIL' 'CmdLine blank'
    } else {
        Write-Log '  LIVE 4688 - FAIL: No event generated' -Level FAIL
        Add-Result 'LIVE Event 4688 + CmdLine' 'FAIL' 'No 4688 event'
    }

    Write-Log '  Running live PS Script Block test (Event 4104)...'
    $ps4104 = Test-LivePS4104
    $status  = if ($ps4104) { 'PASS' } else { 'FAIL' }
    Write-Log "  LIVE PS ScriptBlock 4104 - $status" -Level $status
    Add-Result 'LIVE PS ScriptBlock Event 4104' $status
}

function Invoke-AutoFix {
    Write-Log 'PHASE 6 - Auto-Fix' -Level HEAD

    $failures = $script:Results | Where-Object { $_.Status -eq 'FAIL' }
    if (-not $failures) { Write-Log '  No failures. Auto-Fix skipped.' -Level PASS; return }

    foreach ($f in $failures) {
        Write-Log "  Fixing: $($f.Control)" -Level FIX
        $script:FixCount++

        switch -Wildcard ($f.Control) {
            'Credential Validation Audit'         { $null = Set-AuditSubcategory 'Credential Validation'               $true $true  }
            'Kerberos Auth Service Audit'         { $null = Set-AuditSubcategory 'Kerberos Authentication Service'     $true $true  }
            'Kerberos SvcTicket Ops Audit'        { $null = Set-AuditSubcategory 'Kerberos Service Ticket Operations'  $true $true  }
            'Other Account Logon Events Audit'    { $null = Set-AuditSubcategory 'Other Account Logon Events'          $true $true  }
            'User Account Mgmt Audit'             { $null = Set-AuditSubcategory 'User Account Management'             $true $true  }
            'Computer Account Mgmt Audit'         { $null = Set-AuditSubcategory 'Computer Account Management'         $true $true  }
            'Security Group Mgmt Audit'           { $null = Set-AuditSubcategory 'Security Group Management'           $true $true  }
            'Other Account Mgmt Audit'            { $null = Set-AuditSubcategory 'Other Account Management Events'     $true $true  }
            'Logon Audit'                         { $null = Set-AuditSubcategory 'Logon'                               $true $true  }
            'Logoff Audit'                        { $null = Set-AuditSubcategory 'Logoff'                              $true $false }
            'Account Lockout Audit'               { $null = Set-AuditSubcategory 'Account Lockout'                     $true $false }
            'Special Logon Audit'                 { $null = Set-AuditSubcategory 'Special Logon'                       $true $false }
            'Directory Service Access Audit'      { $null = Set-AuditSubcategory 'Directory Service Access'            $true $true  }
            'Directory Service Changes Audit'     { $null = Set-AuditSubcategory 'Directory Service Changes'           $true $true  }
            'Directory Service Replication Audit' { $null = Set-AuditSubcategory 'Directory Service Replication'       $true $true  }
            'Sensitive Privilege Use Audit'       { $null = Set-AuditSubcategory 'Sensitive Privilege Use'             $true $true  }
            'Process Creation Audit'              { $null = Set-AuditSubcategory 'Process Creation'                    $true $false }
            'Audit Policy Change'                 { $null = Set-AuditSubcategory 'Audit Policy Change'                 $true $true  }
            'Auth Policy Change Audit'            { $null = Set-AuditSubcategory 'Authentication Policy Change'        $true $true  }
            'Authorization Policy Change Audit'   { $null = Set-AuditSubcategory 'Authorization Policy Change'         $true $false }
            'Security State Change Audit'         { $null = Set-AuditSubcategory 'Security State Change'               $true $true  }
            'Security System Extension Audit'     { $null = Set-AuditSubcategory 'Security System Extension'           $true $true  }
            'System Integrity Audit'              { $null = Set-AuditSubcategory 'System Integrity'                    $true $true  }
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
                $null = cmd /c 'wevtutil sl Security /ms:1073741824 /rt:false 2>&1'
            }
            'Directory Service Log Size' {
                $null = cmd /c 'wevtutil sl "Directory Service" /ms:536870912 /rt:false 2>&1'
            }
            'LIVE*' {
                Write-Log '    Live failure - downstream of above fixes.' -Level FIX
            }
        }
    }

    Write-Log '  Re-running gpupdate /force after fixes...' -Level FIX
    $null = cmd /c 'gpupdate /force 2>&1'
    Start-Sleep -Seconds 5

    Write-Log 'PHASE 6B - Re-Validation' -Level HEAD
    $script:Results.Clear()
    Invoke-Validation
}

function Write-FinalReport {
    Write-Log '' -Level HEAD
    Write-Log '======================================================' -Level HEAD
    Write-Log '  AUDIT POLICY REPORT - Windows Server 2025 DC (VM4)' -Level HEAD
    Write-Log "  Host : $env:COMPUTERNAME  |  User : $env:USERNAME"
    Write-Log "  Time : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Log "  Log  : $LogFile"
    Write-Log "  Mode : $(if ($WhatIf) { 'DRY RUN' } else { 'APPLIED' })"
    Write-Log '======================================================' -Level HEAD

    $pass  = ($script:Results | Where-Object { $_.Status -eq 'PASS' }).Count
    $fail  = ($script:Results | Where-Object { $_.Status -eq 'FAIL' }).Count
    $total = $script:Results.Count

    foreach ($r in $script:Results) {
        $detail = if ($r.Detail) { " | $($r.Detail)" } else { '' }
        Write-Log "  [$($r.Status)] $($r.Control)$detail" -Level $r.Status
    }

    Write-Log '------------------------------------------------------'
    Write-Log "  Total: $total  |  Passed: $pass  |  Failed: $fail"
    Write-Log "  Auto-Fix Attempts: $($script:FixCount)"
    Write-Log '======================================================'

    if ($fail -gt 0) {
        Write-Log '  REMAINING FAILURES - DC Manual Checklist:' -Level FAIL
        Write-Log '  1. Confirm running as Domain Admin' -Level FAIL
        Write-Log '  2. Check Default Domain Controllers Policy in GPMC' -Level FAIL
        Write-Log '  3. Verify Event Log service: sc query eventlog' -Level FAIL
        Write-Log '  4. Directory Service log missing? DC may not be fully promoted' -Level FAIL
        Write-Log '  5. Kerberos subcategories only apply on actual DCs' -Level FAIL
        Write-Log '  6. Reboot may be required for Server 2025 registry changes' -Level FAIL
    } else {
        Write-Log '  ALL CONTROLS VERIFIED. DC logging operational.' -Level PASS
        Write-Log '  Active: 4624,4625,4634,4662,4672,4688,4706,4719,4720,4726,4728,4738,4740,4741,4768,4769,4771,5136,4104' -Level PASS
    }
}

# ENTRY POINT
Write-Log 'Windows Server 2025 DC Audit Policy Configurator v2.1 - Starting' -Level HEAD
Invoke-PreFlight
Set-AuditPolicies
Set-RegistryLogging
Set-EventLogSizes
Invoke-GPUpdate
Invoke-Validation
Invoke-AutoFix
Write-FinalReport
Stop-Transcript
