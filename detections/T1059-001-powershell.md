# T1059.001 — PowerShell Encoded Commands

## What This Attack Does

The attacker uses PowerShell with Base64 encoded commands to hide what
they are actually running. Encoding the command makes it harder for
security tools to read and block it. This is one of the most common
techniques used by real malware and ransomware in the wild because
PowerShell is built into every Windows machine.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1059.001 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: powershell.exe -EncodedCommand <base64string>

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*powershell.exe" CommandLine="*-EncodedCommand*" OR CommandLine="*-enc*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected encoded PowerShell execution.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
