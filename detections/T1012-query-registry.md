# T1012 — Query Registry (reg query)

## What This Attack Does

The attacker queries the Windows registry to find sensitive information
stored there — saved credentials, installed software, auto-run programs,
and security configurations. The registry is a goldmine for attackers
because many applications store configuration data and sometimes even
passwords there in plain text.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1012 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\reg.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*reg.exe" CommandLine="*query*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected registry query execution.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
