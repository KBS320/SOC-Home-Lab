# T1115 — Clipboard Data

## What This Attack Does

The attacker steals whatever is currently copied in the clipboard.
People copy and paste passwords, API keys, credit card numbers, internal
URLs, and sensitive documents constantly throughout the day. By capturing
clipboard contents the attacker can grab credentials and sensitive data
without ever touching the files on disk, making this very hard to detect
with traditional file-monitoring tools.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1115 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: powershell.exe Get-Clipboard

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 CommandLine="*Get-Clipboard*" OR CommandLine="*GetText*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected clipboard data access.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
