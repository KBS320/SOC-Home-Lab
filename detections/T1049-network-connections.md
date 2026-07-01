# T1049 — System Network Connections Discovery (netstat)

## What This Attack Does

The attacker runs netstat to see all active network connections on the
machine. This shows them what external IPs the machine is talking to,
what ports are open, and what services are listening. This helps them
understand the network exposure and find other systems to pivot to.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1049 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\netstat.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: netstat -ano

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*netstat.exe"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected netstat execution.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
