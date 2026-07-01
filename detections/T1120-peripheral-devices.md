# T1120 — Peripheral Device Discovery

## What This Attack Does

The attacker enumerates USB drives, external hard drives, and other
peripheral devices connected to the machine. External storage devices
are valuable targets — they often contain backups, sensitive files,
or can be used as an alternative exfiltration path that bypasses
network monitoring. Finding a USB drive full of sensitive data is
a major win for an attacker.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1120 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: powershell.exe Get-WmiObject Win32_DiskDrive

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 CommandLine="*Win32_DiskDrive*" OR CommandLine="*Win32_USBHub*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected peripheral device enumeration.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
