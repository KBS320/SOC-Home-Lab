# T1059.001 — PowerShell Encoded Commands

## What This Attack Does

The attacker uses PowerShell with Base64 encoded commands to hide what
they are actually running. Encoding the command makes it harder for
security tools to read and block it. This is one of the most common
techniques used by real malware and ransomware in the wild because
PowerShell is built into every Windows machine.

## How I Simulated It

Tool: Manual PowerShell execution
Note: Atomic Red Team Test 1 (Mimikatz) was blocked by Windows Defender.
Instead, a manual Base64 encoded PowerShell command was executed directly
to demonstrate the T1059.001 technique.

Command executed on Windows target:

powershell -e aQBwAGMAbwBuAGYAZwA=

This decodes and executes ipconfig using the -EncodedCommand flag,
demonstrating how attackers hide commands in Base64 to evade detection.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- User: WINDOWS\khaled
- CommandLine: powershell -e aQBwAGMAbwBuAGYAZwA=

## SPL Detection Query

index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "powershell" "-e"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage

## Result

Splunk successfully detected encoded PowerShell execution.
Alert fired within seconds of the command running on the target.

## Screenshots
<img width="1002" height="36" alt="T1059-001-windows png" src="https://github.com/user-attachments/assets/8c355721-362e-4049-8ac9-c5aa04813d88" />
<img width="1915" height="1015" alt="T1059-001-splunk png" src="https://github.com/user-attachments/assets/79f947c8-f796-456c-82f7-54b29d87d49a" />
