# Incident Response Lab – Setup Scripts

This folder contains setup and configuration scripts for the IR lab environment.
All scripts target VM2 (Windows 10 Enterprise) and VM4 (Windows Server 2025 DC).

---

## Scripts in This Folder

| Script | Target | Purpose |
|---|---|---|
| `install-atomicredteam.ps1` | VM2 — Windows 10 | Installs Atomic Red Team for adversary simulation |
| `Set-AuditPolicy-Win10Endpoint.ps1` | VM2 — Windows 10 | Configures, enforces, and validates endpoint audit logging |
| `Set-AuditPolicy-Server2025DC.ps1` | VM4 — Server 2025 DC | Configures, enforces, and validates DC audit logging |

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

## 2. Windows Audit Policy Configuration

These scripts implement NIST SP 800-61 aligned audit logging.
Each script runs in 7 phases: Configure → Registry → Log Size → Enforce → Validate → Auto-Fix → Report.

Both scripts include:
- Self-healing auto-fix loop (re-applies any failed control automatically)
- Live event generation tests (4688 + 4104) to confirm logging is actually working
- Colored pass/fail console output + timestamped log file saved to `C:\`
- `-WhatIf` dry-run mode to preview changes without applying them

### 2a. VM2 — Windows 10 Endpoint

**Script:** `Set-AuditPolicy-Win10Endpoint.ps1`

```powershell
# Run as Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Set-AuditPolicy-Win10Endpoint.ps1

# Dry run (no changes applied)
.\Set-AuditPolicy-Win10Endpoint.ps1 -WhatIf
```

**Audit subcategories configured (12 total):**

| Subcategory | Event IDs | Detection Use Case |
|---|---|---|
| Credential Validation | 4624, 4625 | Brute force, password spraying |
| Logon | 4624 | Session tracking |
| Logoff | 4634 | Session end |
| Account Lockout | 4740 | Brute force detection |
| Special Logon | 4964 | Admin-equivalent logon |
| User Account Management | 4720, 4726, 4738 | Account creation/deletion/modification |
| Security Group Management | 4728, 4732 | Group membership changes |
| Sensitive Privilege Use | 4672 | Lateral movement |
| Process Creation | 4688 + CmdLine | Execution tracking, encoded payloads |
| Audit Policy Change | 4719 | Attacker disabling your logging |
| Authentication Policy Change | 4706 | Trust/auth modifications |
| Security State Change | 4608 | System integrity baseline |

**Additional registry settings applied:**
- Command-line arguments captured in Event 4688
- PowerShell Script Block Logging (Event 4104)
- PowerShell Module Logging (all modules)
- PowerShell Transcription → `C:\PSTranscripts`
- Security event log size set to 1 GB

---

### 2b. VM4 — Windows Server 2025 Domain Controller

**Script:** `Set-AuditPolicy-Server2025DC.ps1`

```powershell
# Run as Domain Admin on the DC
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Set-AuditPolicy-Server2025DC.ps1

# Dry run (no changes applied)
.\Set-AuditPolicy-Server2025DC.ps1 -WhatIf
```

**DC-specific subcategories (23 total — includes all endpoint controls plus):**

| Subcategory | Event IDs | Detection Use Case |
|---|---|---|
| Kerberos Authentication Service | 4768, 4771 | AS-REP Roasting, Pass-the-Ticket |
| Kerberos Service Ticket Operations | 4769 | Golden/Silver Ticket attacks |
| Other Account Logon Events | 4649 | Replay attacks |
| Computer Account Management | 4741, 4743 | Rogue machine account creation |
| Other Account Management Events | — | Catch-all account operations |
| Directory Service Access | 4662 | AD object read (BloodHound enumeration) |
| Directory Service Changes | 5136 | AD object modification |
| Directory Service Replication | 4928, 4929 | DCSync attack detection |
| Authentication Policy Change | 4706, 4713 | Kerberos policy modification |
| Authorization Policy Change | 4704 | User rights assignment |
| Security System Extension | 4697 | Malicious service installation |
| System Integrity | 4616 | System time tampering |

**Additional log sizes set:**
- Security log: 1 GB
- Directory Service log: 512 MB
- System log: 512 MB

> **Note:** On a Domain Controller, the correct long-term approach is to configure
> audit policy inside the **Default Domain Controllers Policy** GPO via GPMC.
> This script applies local policy and will be overridden by domain GPO on the next refresh.
> Use this script for lab/testing environments.

---

## Reference

- NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide
- Microsoft Security Audit Policy Recommendations (Windows Server 2025)
- CIS Benchmark — Windows 10 / Windows Server 2025
- MITRE ATT&CK — Relevant techniques: T1078, T1003, T1059, T1550, T1484
