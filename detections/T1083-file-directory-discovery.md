# T1083 — File and Directory Discovery (dir/tree)

## What This Attack Does

The attacker runs dir and tree commands to browse the file system and
map out what files and folders exist on the machine. They are looking
for sensitive documents, configuration files, credentials, databases,
or anything worth stealing. This is the attacker doing reconnaissance
on the data sitting on the compromised machine.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1083 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\cmd.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: dir C:\ /s /b

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 CommandLine="*dir*" OR CommandLine="*tree*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected file and directory enumeration.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
