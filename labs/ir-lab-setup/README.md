# Incident Response Lab — Setup Scripts

This folder contains setup and configuration scripts for the IR lab environment.
All scripts target VM2 (Windows 10 Enterprise) and VM4 (Windows Server 2025 DC).

---

## Documentation

| Document | Description |
|---|---|
| [IR Lab Setup Guide — Section 1](./ir-lab-setup-guide-section1.pdf) | Full lab build guide — VM setup, network config, tool installation, audit policy, MITRE ATT&CK coverage |

---

## Scripts in This Folder

| Script | Target | Purpose |
|---|---|---|
| `install-atomicredteam.ps1` | VM2 — Windows 10 | Installs Atomic Red Team for adversary simulation |
| `Set-AuditPolicy-Win10Endpoint.ps1` | VM2 — Windows 10 | Configures, enforces, validates, and self-heals endpoint audit logging |
| `Set-AuditPolicy-Server2025DC.ps1` | VM4 — Server 2025 DC | Configures, enforces, validates, and self-heals DC audit logging |

---

## 1. Atomic Red Team Setup

This script installs Atomic Red Team on a Windows endpoint, validates the Atomic test library,
and optionally runs a safe PowerShell-based test for telemetry and detection verification.

### Requirements

- Windows 10 / Windows Server
- PowerShell 5+
- Administrator PowerShell session
- Internet connection
- Sysmon installed for endpoint telemetry
- Wazuh agent installed if SIEM validation is required

### Installation

Run this in **PowerShell (Administrator)**:

```powershell
powershell -ExecutionPolicy Bypass -Command "IEX (IWR https://raw.githubusercontent.com/A-rjun-saji/security-engineering-roadmap/main/labs/ir-lab-setup/install-atomicredteam.ps1)"
```

---

## 2. Windows Audit Policy Configuration (v2.7)

These scripts implement NIST SP 800-61 aligned audit logging.
Each script runs in **8 phases** matching the log output exactly:

| Phase | Action | Mechanism |
|---|---|---|
| Phase 2 — Configure | Apply all audit subcategories | `auditpol /set /subcategory:` |
| Phase 2B — Registry | CmdLine, PS ScriptBlock, PS Module | HKLM registry writes |
| Phase 3 — Log Size | Security log = 1 GB minimum | `wevtutil sl Security /ms:` |
| Phase 4 — Enforce | `gpupdate /force` + settle delay | Group Policy refresh |
| Phase 5 — Validate | Check each control + live events | `auditpol /get /r` + WinEvent |
| Phase 5 — Auto-Fix | Interactive per-control remediation | `[A]uto / [M]anual / [S]kip` prompt |
| Phase 5B — Re-Validate | Single-control re-validation after fix | `Invoke-SingleValidation` |
| Phase 6 — Report | Live auditpol dashboard + colour summary | `Write-SuccessDashboard` + `C:\*.log` |

Both scripts include:

- **Interactive remediation** — after validation, each failed control is presented one by one.
  The operator chooses `[A]` Auto-fix, `[M]` Manual (with step-by-step instructions printed inline), or `[S]` Skip.
  Manual fixes wait for operator confirmation before re-validating.
- **Live event generation tests** — 4688 (process creation + command line) and 4104 (PS script block)
  are triggered and verified in the Security and PowerShell/Operational logs respectively.
- **Live auditpol dashboard** — every passed control is re-read from `auditpol /get /r` at the end
  and printed with its actual `Inclusion Setting` value (e.g. `Success and Failure`).
- **Coloured console output** — green PASS, red FAIL, yellow FIX, magenta WARN.
- **Timestamped log file** saved to `C:\AuditPolicy_DC_<timestamp>.log`.
- **`-WhatIf`** dry-run mode — previews all changes without applying them.
- **`-NonInteractive`** switch — skips all prompts and auto-fixes everything (for unattended runs).

---

### 2a. VM2 — Windows 10 Endpoint

**Script:** `Set-AuditPolicy-Win10Endpoint.ps1`

```powershell
# Run as Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Set-AuditPolicy-Win10Endpoint.ps1

# Dry run (no changes applied)
.\Set-AuditPolicy-Win10Endpoint.ps1 -WhatIf

# Unattended — auto-fix all failures without prompts
.\Set-AuditPolicy-Win10Endpoint.ps1 -NonInteractive
```

**Audit subcategories configured (12 total):**

| Subcategory | Success | Failure | Event IDs | Detection Use Case |
|---|---|---|---|---|
| Credential Validation | ✔ | ✔ | 4624, 4625 | Brute force, password spraying |
| Logon | ✔ | ✔ | 4624, 4625 | Session tracking, failed logon |
| Logoff | ✔ | — | 4634 | Session end |
| Account Lockout | ✔ | — | 4740 | Brute force detection |
| Special Logon | ✔ | — | 4964 | Admin-equivalent logon |
| User Account Management | ✔ | ✔ | 4720, 4726, 4738 | Account creation / deletion / modification |
| Security Group Management | ✔ | ✔ | 4728, 4732 | Group membership changes |
| Sensitive Privilege Use | ✔ | ✔ | 4672 | Lateral movement, privilege abuse |
| Process Creation | ✔ | — | 4688 + CmdLine | Execution tracking, encoded payloads |
| Audit Policy Change | ✔ | ✔ | 4719 | Attacker disabling logging |
| Authentication Policy Change | ✔ | ✔ | 4706, 4713 | Trust / auth policy modifications |
| Security State Change | ✔ | ✔ | 4608, 4616 | System integrity baseline |

**Additional registry settings applied:**

| Setting | Registry Path | Value |
|---|---|---|
| Command line in Event 4688 | `...\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled` | 1 |
| PS Script Block Logging (4104) | `...\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging` | 1 |
| PS Module Logging | `...\PowerShell\ModuleLogging\EnableModuleLogging` | 1 |
| PS Transcription | `...\PowerShell\Transcription\EnableTranscripting` | 1 |
| Transcription output | `...\PowerShell\Transcription\OutputDirectory` | `C:\PSTranscripts` |

**Event log sizes set:**

| Log | Size |
|---|---|
| Security | 1 GB (1024 MB) |

---

### 2b. VM4 — Windows Server 2025 Domain Controller

**Script:** `Set-AuditPolicy-Server2025DC.ps1`

```powershell
# Run as Domain Admin on the DC
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Set-AuditPolicy-Server2025DC.ps1

# Dry run (no changes applied)
.\Set-AuditPolicy-Server2025DC.ps1 -WhatIf

# Unattended — auto-fix all failures without prompts
.\Set-AuditPolicy-Server2025DC.ps1 -NonInteractive
```

**Audit subcategories configured (24 total):**

| Subcategory | Success | Failure | Event IDs | Detection Use Case |
|---|---|---|---|---|
| Credential Validation | ✔ | ✔ | 4624, 4625 | Brute force, NTLM attacks |
| Kerberos Authentication Service | ✔ | ✔ | 4768, 4771 | AS-REP Roasting, Pass-the-Ticket |
| Kerberos Service Ticket Operations | ✔ | ✔ | 4769 | Golden / Silver Ticket attacks |
| Other Account Logon Events | ✔ | ✔ | 4776 | NTLM credential validation catch-all |
| User Account Management | ✔ | ✔ | 4720, 4726, 4738 | Account creation / deletion / modification |
| Computer Account Management | ✔ | ✔ | 4741, 4743 | Rogue machine account creation |
| Security Group Management | ✔ | ✔ | 4728, 4732 | Group membership changes |
| Other Account Management Events | ✔ | ✔ | — | Catch-all account operations |
| Logon | ✔ | ✔ | 4624, 4625 | Session tracking, failed logon |
| Logoff | ✔ | — | 4634 | Session end |
| Account Lockout | ✔ | — | 4740 | Brute force detection |
| Special Logon | ✔ | — | 4964 | Admin-equivalent logon |
| Directory Service Access | ✔ | ✔ | 4662 | AD object read (BloodHound enumeration) |
| Directory Service Changes | ✔ | ✔ | 5136 | AD object modified — privilege escalation |
| Directory Service Replication | ✔ | ✔ | 4928, 4929 | DCSync attack — replication initiated |
| **Detailed Directory Service Replication** | **✔** | **✔** | **4928, 4929** | **DCSync full coverage — replication detail (T1207)** |
| Sensitive Privilege Use | ✔ | ✔ | 4672 | Admin privilege usage, lateral movement |
| Process Creation | ✔ | — | 4688 + CmdLine | Execution tracking, encoded payloads |
| Audit Policy Change | ✔ | ✔ | 4719 | Attacker disabling logging |
| Authentication Policy Change | ✔ | ✔ | 4706, 4713 | Kerberos / trust policy modification |
| Authorization Policy Change | ✔ | — | 4704 | User rights assignment changes |
| Security State Change | ✔ | ✔ | 4608, 4616 | System time tampering, integrity baseline |
| Security System Extension | ✔ | ✔ | 4697 | Malicious service installation — persistence |
| System Integrity | ✔ | ✔ | 4612, 4615 | Audit log integrity violations |

> **Note on `Detailed Directory Service Replication`:** This subcategory was added in v2.7
> to close the DCSync detection gap (MITRE T1207). Without it, replication events are partially
> captured but the specific detail events that expose `lsadump::dcsync` are missing.
> Both `Directory Service Replication` AND `Detailed Directory Service Replication` must be
> enabled for complete coverage.

**Additional registry settings applied:**

| Setting | Registry Path | Value |
|---|---|---|
| Command line in Event 4688 | `...\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled` | 1 |
| PS Script Block Logging (4104) | `...\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging` | 1 |
| PS Module Logging | `...\PowerShell\ModuleLogging\EnableModuleLogging` | 1 |
| PS Transcription | `...\PowerShell\Transcription\EnableTranscripting` | 1 |
| Transcription output | `...\PowerShell\Transcription\OutputDirectory` | `C:\PSTranscripts` |

**Event log sizes set:**

| Log | Size |
|---|---|
| Security | 1 GB (1024 MB) |
| Directory Service | 512 MB |
| System | 512 MB |

**Expected final score on a clean run:**

```
SCORE: 31 / 31 PASSED  (100%)   |   FAILED: 0   |   Fix attempts: 0
ALL CONTROLS PASSED - DC audit/logging fully configured
Events now firing: 4624 4625 4634 4662 4672 4688 4706 4719 5136 4104
```

> **GPO override warning:** On a Domain Controller, the Default Domain Controllers Policy (DDCP)
> takes precedence over local policy at every GPO refresh. This script applies local policy and
> is authoritative for lab/testing environments. For permanent production deployment, configure
> audit settings inside the DDCP via `gpmc.msc`:
> `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration`

---

## MITRE ATT&CK Coverage

| Technique | Name | Detected By |
|---|---|---|
| T1078 | Valid Accounts | 4624, 4625, 4672, 4964 |
| T1003 | OS Credential Dumping | 4688 (lsass access), 4672 |
| T1059 | Command & Scripting Interpreter | 4688 + CmdLine, 4104 |
| T1484 | GPO / Domain Policy Modification | 4719, 5136 |
| T1550 | Pass-the-Hash / Pass-the-Ticket | 4768, 4769, 4771 |
| T1136 | Create Account | 4720, 4741 |
| T1098 | Account Manipulation | 4728, 4738, 4732 |
| T1207 | Rogue Domain Controller (DCSync) | 4928, 4929 — requires **both** DS Replication subcategories |

---

## Changelog

| Version | Change |
|---|---|
| v2.7 | Added `Detailed Directory Service Replication` subcategory — closes DCSync (T1207) detection gap. Total DC controls: 31. |
| v2.6 | Fixed `wevtutil /ms:` argument split bug. Fixed `Write-Log ''` crash under `Set-StrictMode`. Added live auditpol verification dashboard. |
| v2.5 | Fixed `$args` reserved variable bug (root cause of all v2.4 auditpol failures). Fixed subcategory quoting. Fixed CSV BOM parsing. Added interactive `[A]/[M]/[S]` remediation loop. |
| v2.4 | Initial release (contained auditpol invocation bugs). |

---

## Reference

- NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide
- Microsoft Security Audit Policy Recommendations — Windows Server 2025
- CIS Benchmark — Windows 10 / Windows Server 2025
- MITRE ATT&CK Enterprise Matrix — [attack.mitre.org](https://attack.mitre.org)
- [github.com/A-rjun-saji/security-engineering-roadmap](https://github.com/A-rjun-saji/security-engineering-roadmap) | Branch: `main` | Path: `labs/ir-lab-setup/`
