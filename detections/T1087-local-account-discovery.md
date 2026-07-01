# T1087.001 — Local Account Discovery (net user)

## What This Attack Does

The attacker runs net user to list all local user accounts on the machine.
This tells them which accounts exist, which ones might have weak passwords,
and which ones they could target for privilege escalation. Finding an
admin account they can compromise is a major win for the attacker.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1087.001 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\net.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: net user

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*net.exe" CommandLine="*user*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected net user execution.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
