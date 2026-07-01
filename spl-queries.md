# SPL Detection Queries — 30 MITRE ATT&CK Techniques

All Splunk detection queries used in this lab. Each query is mapped to its
MITRE ATT&CK technique and written to minimize false positives while
catching real attacker behavior in Windows event logs.

**Index:** windows  
**Log Source:** WinEventLog:Microsoft-Windows-Sysmon/Operational  
**Sysmon Config:** SwiftOnSecurity  

---

## Phase 1 — Discovery

### T1033 — System Owner/User Discovery (whoami)
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*whoami.exe"
| eval Severity="Medium"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1082 — System Information Discovery (systeminfo)
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*systeminfo.exe"
| eval Severity="Medium"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1057 — Process Discovery (tasklist)
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*tasklist.exe"
| eval Severity="Medium"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1016 — Network Configuration Discovery (ipconfig)
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*ipconfig.exe"
| eval Severity="Medium"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1049 — Network Connections Discovery (netstat)
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*netstat.exe"
| eval Severity="Medium"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1087.001 — Local Account Discovery (net user)
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*net.exe" CommandLine="*user*"
| eval Severity="Medium"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1069.001 — Local Group Discovery (net localgroup)
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*net.exe" CommandLine="*localgroup*"
| eval Severity="Medium"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1135 — Network Share Discovery (net share)
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*net.exe" CommandLine="*share*"
| eval Severity="Medium"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1083 — File and Directory Discovery (dir/tree)
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 CommandLine="*dir*" OR CommandLine="*tree*"
| eval Severity="Low"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1012 — Query Registry (reg query)
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*reg.exe" CommandLine="*query*"
| eval Severity="Medium"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

---

## Phase 2 — Execution

### T1059.001 — PowerShell Encoded Commands
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*powershell.exe"
CommandLine="*-EncodedCommand*" OR CommandLine="*-enc*" OR CommandLine="*-e *"
| eval Severity="High"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1059.003 — Windows Command Shell (cmd.exe)
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*cmd.exe" CommandLine="*/c*"
| eval Severity="Medium"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

---

## Phase 3 — Persistence

### T1053.005 — Scheduled Task (schtasks)
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*schtasks.exe" CommandLine="*/create*"
| eval Severity="High"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1547.001 — Registry Run Keys
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=13 TargetObject="*\\CurrentVersion\\Run*"
| eval Severity="High"
| table _time, ComputerName, User, TargetObject, Details, Severity
| sort -_time
```

### T1105 — Ingress Tool Transfer
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=11 TargetFilename="*.exe" Image="*powershell.exe"
| eval Severity="High"
| table _time, ComputerName, User, Image, TargetFilename, Severity
| sort -_time
```

---

## Phase 4 — Defense Evasion

### T1218.011 — Rundll32 Abuse
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*rundll32.exe"
CommandLine="*javascript*" OR CommandLine="*http*" OR CommandLine="*shell*"
| eval Severity="High"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1070.004 — File Deletion
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=23
| eval Severity="Medium"
| table _time, ComputerName, User, Image, TargetFilename, Severity
| sort -_time
```

### T1070.003 — Clear Command History
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
CommandLine="*Clear-History*" OR CommandLine="*HistorySavePath*" OR CommandLine="*clearhistory*"
| eval Severity="High"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1112 — Modify Registry (disable security)
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=13 TargetObject="*Windows Defender*" OR TargetObject="*DisableAntiSpyware*"
| eval Severity="Critical"
| table _time, ComputerName, User, TargetObject, Details, Severity
| sort -_time
```

---

## Phase 5 — Discovery 2

### T1124 — System Time Discovery
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 CommandLine="*net time*" OR CommandLine="*w32tm*"
| eval Severity="Low"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1113 — Screen Capture
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
CommandLine="*screenshot*" OR CommandLine="*Screen.PrimaryScreen*" OR CommandLine="*CopyFromScreen*"
| eval Severity="High"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1115 — Clipboard Data
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 CommandLine="*Get-Clipboard*" OR CommandLine="*GetText*"
| eval Severity="High"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

---

## Phase 6 — Collection

### T1560.001 — Archive Collected Data
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
CommandLine="*Compress-Archive*" OR CommandLine="*-DestinationPath*" OR CommandLine="*zip*"
| eval Severity="High"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1041 — Exfiltration Over C2 Channel
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3 Image="*powershell.exe" DestinationPort=443
| eval Severity="Critical"
| stats count by _time, ComputerName, User, DestinationIp, DestinationPort, Severity
| sort -_time
```

---

## Phase 7 — Impact

### T1486 — Data Encrypted for Impact (ransomware)
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=11
| stats count by ComputerName, Image
| where count > 20
| eval Severity="Critical"
| table _time, ComputerName, Image, count, Severity
| sort -count
```

### T1201 — Password Policy Discovery
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*net.exe" CommandLine="*accounts*"
| eval Severity="Medium"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1518.001 — Security Software Discovery
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
CommandLine="*SecurityCenter*" OR CommandLine="*AntiVirusProduct*" OR CommandLine="*Get-MpComputerStatus*"
| eval Severity="High"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1120 — Peripheral Device Discovery
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
CommandLine="*Win32_DiskDrive*" OR CommandLine="*Win32_USBHub*" OR CommandLine="*Win32_PnPEntity*"
| eval Severity="Medium"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1197 — BITS Jobs
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*bitsadmin.exe" CommandLine="*transfer*"
| eval Severity="High"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

### T1529 — System Shutdown/Reboot
```
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*shutdown.exe"
| eval Severity="Critical"
| table _time, ComputerName, User, CommandLine, ParentImage, Severity
| sort -_time
```

---

## Severity Reference

| Level | Meaning |
|---|---|
| Low | Informational — common commands worth logging |
| Medium | Suspicious — investigate in context |
| High | Likely malicious — prioritize review |
| Critical | Immediate response required |
