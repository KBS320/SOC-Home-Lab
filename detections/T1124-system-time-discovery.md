# T1124 — System Time Discovery

## What This Attack Does

The attacker queries the system time and timezone of the target machine.
This helps them understand when business hours are in the target's
timezone so they can time their most destructive actions — like
deploying ransomware — for nights or weekends when no one is watching.
Knowing the local time also helps correlate events across multiple
compromised machines in different regions.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1124 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\cmd.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: net time && w32tm /query /status

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 CommandLine="*net time*" OR CommandLine="*w32tm*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected system time discovery commands.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
