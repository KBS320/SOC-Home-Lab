# T1087.001 — Local Account Discovery (net user)

## What This Attack Does

The attacker runs net user to list all local user accounts on the machine.
This tells them which accounts exist, which ones might have weak passwords,
and which ones they could target for privilege escalation. Finding an
admin account they can compromise is a major win for the attacker.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1087.001 -TestNumbers 8

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

<img width="1002" height="141" alt="T1087-windows png" src="https://github.com/user-attachments/assets/4f156810-10d0-4c71-8493-1982dc23f90f" />
<img width="1912" height="1006" alt="T1087-splunk" src="https://github.com/user-attachments/assets/3b373844-51f6-46ec-b72e-d7d0b65bcb9e" />


