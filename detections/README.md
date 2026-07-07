# 🎯 MITRE ATT&CK Detection Writeups

30 detection writeups built from real attack simulations using Atomic Red Team against a live Windows Server target with Sysmon telemetry, detected in Splunk with custom SPL queries.

---

## 🔧 Lab Setup

| Component | Details |
|---|---|
| SIEM | Splunk |
| Telemetry | Sysmon (XmlWinEventLog) |
| Attack Framework | Atomic Red Team |
| Target | Windows Server 2019 |
| Attacker | Kali Linux |

**Base SPL query used across all detections:**
```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| rex field=_raw "Image: (?<Image>[^\r\n]+)"
| rex field=_raw "CommandLine: (?<CommandLine>[^\r\n]+)"
| rex field=_raw "ParentImage: (?<ParentImage>[^\r\n]+)"
| rex field=_raw "User: (?<User>[^\r\n]+)"
| rex field=_raw "UtcTime: (?<UtcTime>[^\r\n]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

---

## 📋 Writeup Format

Each writeup follows this structure:
- **Technique** — MITRE ATT&CK technique name and ID
- **Tactic** — Kill chain phase
- **Atomic Test** — Exact test number used with `Invoke-AtomicTest`
- **What it does** — Plain English explanation of the attack
- **SPL Detection** — The Splunk query that catches it
- **Screenshot** — Evidence of the detection firing

---

## 📁 All 30 Detections

| # | File | Technique | Tactic |
|---|---|---|---|
| 1 | [T1003-credential-dumping.md](./T1003-credential-dumping.md) | OS Credential Dumping | Credential Access |
| 2 | [T1012-query-registry.md](./T1012-query-registry.md) | Query Registry | Discovery |
| 3 | [T1016-network-config.md](./T1016-network-config.md) | System Network Configuration Discovery | Discovery |
| 4 | [T1033-whoami.md](./T1033-whoami.md) | System Owner/User Discovery | Discovery |
| 5 | [T1041-exfiltration-c2.md](./T1041-exfiltration-c2.md) | Exfiltration Over C2 Channel | Exfiltration |
| 6 | [T1049-network-connections.md](./T1049-network-connections.md) | System Network Connections Discovery | Discovery |
| 7 | [T1053-005-scheduled-task.md](./T1053-005-scheduled-task.md) | Scheduled Task | Persistence |
| 8 | [T1057-process-discovery.md](./T1057-process-discovery.md) | Process Discovery | Discovery |
| 9 | [T1059-001-powershell.md](./T1059-001-powershell.md) | PowerShell | Execution |
| 10 | [T1059-003-cmd-shell.md](./T1059-003-cmd-shell.md) | Windows Command Shell | Execution |
| 11 | [T1069-local-group-discovery.md](./T1069-local-group-discovery.md) | Local Group Discovery | Discovery |
| 12 | [T1070-003-clear-history.md](./T1070-003-clear-history.md) | Clear Command History | Defense Evasion |
| 13 | [T1070-004-file-deletion.md](./T1070-004-file-deletion.md) | File Deletion | Defense Evasion |
| 14 | [T1082-system-info.md](./T1082-system-info.md) | System Information Discovery | Discovery |
| 15 | [T1083-file-directory-discovery.md](./T1083-file-directory-discovery.md) | File and Directory Discovery | Discovery |
| 16 | [T1087-local-account-discovery.md](./T1087-local-account-discovery.md) | Local Account Discovery | Discovery |
| 17 | [T1105-ingress-tool-transfer.md](./T1105-ingress-tool-transfer.md) | Ingress Tool Transfer | C2 |
| 18 | [T1112-modify-registry.md](./T1112-modify-registry.md) | Modify Registry | Defense Evasion |
| 19 | [T1113-screen-capture.md](./T1113-screen-capture.md) | Screen Capture | Collection |
| 20 | [T1115-clipboard-data.md](./T1115-clipboard-data.md) | Clipboard Data | Collection |
| 21 | [T1120-peripheral-devices.md](./T1120-peripheral-devices.md) | Peripheral Device Discovery | Discovery |
| 22 | [T1124-system-time-discovery.md](./T1124-system-time-discovery.md) | System Time Discovery | Discovery |
| 23 | [T1135-network-share-discovery.md](./T1135-network-share-discovery.md) | Network Share Discovery | Discovery |
| 24 | [T1197-bits-jobs.md](./T1197-bits-jobs.md) | BITS Jobs | Persistence |
| 25 | [T1201-password-policy.md](./T1201-password-policy.md) | Password Policy Discovery | Discovery |
| 26 | [T1218-011-rundll32.md](./T1218-011-rundll32.md) | Rundll32 | Defense Evasion |
| 27 | [T1486-ransomware-encryption.md](./T1486-ransomware-encryption.md) | Data Encrypted for Impact | Impact |
| 28 | [T1518-001-security-software.md](./T1518-001-security-software.md) | Security Software Discovery | Discovery |
| 29 | [T1529-system-shutdown.md](./T1529-system-shutdown.md) | System Shutdown/Reboot | Impact |
| 30 | [T1547-001-registry-run-key.md](./T1547-001-registry-run-key.md) | Registry Run Keys | Persistence |

---

## 🗺️ MITRE ATT&CK Coverage by Tactic

| Tactic | Count | Techniques |
|---|---|---|
| Discovery | 13 | T1012, T1016, T1033, T1049, T1057, T1069, T1082, T1083, T1087, T1120, T1124, T1135, T1518 |
| Defense Evasion | 5 | T1070.003, T1070.004, T1112, T1218.011, T1036 |
| Execution | 2 | T1059.001, T1059.003 |
| Persistence | 2 | T1053.005, T1197 |
| Collection | 3 | T1113, T1115, T1041 |
| Credential Access | 1 | T1003 |
| Exfiltration | 1 | T1041 |
| Impact | 2 | T1486, T1529 |
| C2 | 1 | T1105 |

---

## ⚠️ Disclaimer

All simulations performed in an isolated lab environment. No production systems or unauthorized networks involved.
