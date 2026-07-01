# T1135 — Network Share Discovery (net share)

## What This Attack Does

The attacker runs net share to find all shared folders on the machine.
Shared folders are goldmines — they often contain sensitive files,
documents, and data that can be stolen. They also reveal how the
organization shares files internally which helps plan the next move.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1135 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\net.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: net share

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*net.exe" CommandLine="*share*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected net share execution.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
