# T1069.001 — Local Group Discovery (net localgroup)

## What This Attack Does

The attacker runs net localgroup to find out which groups exist on the
machine and who belongs to them. The main target is the Administrators
group — knowing who has admin rights tells the attacker which accounts
are worth targeting to gain elevated privileges on the system.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1069.001 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\net.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: net localgroup administrators

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*net.exe" CommandLine="*localgroup*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected net localgroup execution.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
