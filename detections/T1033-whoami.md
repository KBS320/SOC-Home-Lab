# T1033 — System Owner/User Discovery (whoami)

## What This Attack Does

The attacker runs whoami to find out which user account they are operating
under on the compromised machine. This tells them their privilege level —
are they a regular user or a local admin or SYSTEM? This is almost always
one of the first commands run after gaining access to a machine.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1033 -TestNumbers 1

This runs whoami and related user discovery commands via PowerShell.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\whoami.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: whoami

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*whoami.exe"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected the whoami execution.
The alert fired within seconds of the command running on the target machine.

## Screenshot

<img width="1008" height="42" alt="T1033-windows png" src="https://github.com/user-attachments/assets/57770ad1-9ecb-4e85-93d2-9f817496ff89" />
<img width="1915" height="936" alt="T1033-splunk png" src="https://github.com/user-attachments/assets/f8923832-6046-45e8-b1a6-a02aa747c979" />

