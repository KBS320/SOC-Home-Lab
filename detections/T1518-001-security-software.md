# T1518.001 — Security Software Discovery

## What This Attack Does

The attacker enumerates what security software is installed and running
on the machine — antivirus, EDR agents, firewalls, and monitoring tools.
Knowing exactly which security products are deployed helps the attacker
choose techniques that are less likely to be caught by those specific
tools. This is the attacker doing research on their opponent before
deciding their next move.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1518.001 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: powershell.exe Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 CommandLine="*SecurityCenter*" OR CommandLine="*AntiVirusProduct*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected security software enumeration.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
