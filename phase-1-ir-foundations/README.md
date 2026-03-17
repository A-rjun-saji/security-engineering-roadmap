# Phase 1 – Incident Response Foundations

**Goal**  
Convert SOC analyst background into a security engineer's mental model — owning investigations, controls, implementation decisions, and clear communication with infra/dev teams.

**Why this phase first**  
The real gap is not missing alerts — it's leading response, reasoning about controls, making containment/eradication choices, and documenting with audit-quality precision.

**Core Responsibilities Supported**  
- Incident investigation & root cause analysis  
- Structured incident response & containment  
- Security control reasoning  
- Identity & access decisions during incidents  
- Technical handoff to infrastructure & development teams

---

## 1.1 – IR Foundations

**Main Resource**  
📄 [**Incident Response Foundations – Professional Guide (PDF)**](./incident-response-foundations-guide.pdf)  

This 8+ page document covers:  
- Event vs Alert vs Incident (with funnel diagram)  
- Severity, Impact, Urgency & priority matrix  
- Containment, Eradication, Recovery phases (NIST SP 800-61)  
- Evidence preservation basics (volatile-first, chain of custody, hashing)  
- High-quality incident documentation (structure, examples)  
- Core processes: triage workflow, playbooks/runbooks, escalation logic  
- Advanced topics: detection-to-response mapping, MITRE ATT&CK coverage, automation opportunities, RCA (5 Whys/Fishbone), post-incident review metrics  

Built for practitioners — structured vocabulary, decision frameworks, operational playbooks, and real-world examples.

**Key Diagrams Included**  
- Event → Alert → Incident funnel  
- Priority matrix (Severity × Impact)  
- Evidence collection order (volatile to non-volatile)  
- Triage decision tree  
- MITRE ATT&CK coverage sample map  

**Status** ✅ Complete  
**Reference** NIST SP 800-61 Computer Security Incident Handling Guide

---

## 1.2 – Investigation & Basic Forensics

**Main Resource**  
📄 [**1.2 Investigation and Basic Forensics Notes (PDF)**](./1.2_Investigation_and_Basic_Forensics_Notes.pdf)  

A 44-page ground-up learning document covering digital forensics as it applies to security investigation. Built for practitioners with no prior forensics background.

**What's covered — 10 phases, 45 topics:**

| Phase | Content |
|---|---|
| 0 – Orient Yourself | What forensics is, all branches of forensic science |
| 1 – Three Fields | Cybersecurity vs Digital Forensics vs Cyber Forensics, DFIR connection |
| 2 – Divisions & Scope | All 10 digital forensics divisions, scope justification |
| 3 – Evidence Fundamentals | Volatile/non-volatile, Order of Volatility (RFC 3227), chain of custody |
| 4 – Timestamps & Timeline | Linux/Windows timestamps, timestomping detection, Plaso, Hayabusa |
| 5 – Windows Host Forensics | Registry, Prefetch, Shimcache, Amcache, Event IDs, Sysmon, browser artifacts |
| 6 – Linux Host Forensics | Log structure, shell history, persistence mechanisms, /proc filesystem |
| 7 – Memory Forensics | RAM contents, memory acquisition, process tree, Volatility 3 plugins |
| 8 – Network Forensics | DNS logs, firewall/proxy, NetFlow, PCAP, Zeek, Zone.Identifier |
| 9 – Malware Behavior | Initial signals, fileless indicators, persistence patterns |
| 10 – Advanced Analysis | Timeline correlation, TP vs benign admin, escalation notes, kill chain mapping |

**Domains Covered**  
`Host Forensics` · `Memory Forensics` · `Network Forensics` · `Malware Artifact Forensics`

**Status** ✅ Complete  
**Reference** RFC 3227 · MITRE ATT&CK · NIST SP 800-86

---

**Phase 1 Overall Status**  
✅ 1.1 IR Foundations — uploaded  
✅ 1.2 Investigation & Basic Forensics — uploaded  
🔲 Hands-on lab outputs — in progress  
🔲 Markdown breakdowns — planned

**Tags**  
`#IncidentResponse` `#DigitalForensics` `#DFIR` `#BlueTeam` `#NIST` `#Cybersecurity` `#SOC` `#SecurityEngineering` `#WindowsForensics` `#MemoryForensics` `#NetworkForensics`

*Last updated: March 17, 2026*
