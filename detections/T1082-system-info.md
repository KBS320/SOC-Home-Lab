# T1082 — System Information Discovery (systeminfo)

## What This Attack Does

The attacker runs systeminfo to pull detailed information about the target
machine — OS version, hostname, hotfixes installed, RAM, network adapters.
This tells them exactly what they are working with and helps identify
missing patches they can exploit.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1082 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\systeminfo.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: systeminfo

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*systeminfo.exe"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected systeminfo execution.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
