# T1053.005 — Scheduled Task (schtasks)

## What This Attack Does

The attacker creates a scheduled task that automatically runs their
malicious code every time the machine starts or at a set time interval.
This is how attackers survive reboots — even if the machine restarts,
their code runs again automatically without them doing anything.
This is one of the most common persistence techniques used in real attacks.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1053.005 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\schtasks.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: schtasks /create /tn "MaliciousTask" /tr cmd.exe /sc onstart

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*schtasks.exe" CommandLine="*/create*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected scheduled task creation.
Alert fired within seconds of the command running on the target.

## Screenshot

<img width="1002" height="216" alt="T1053-windows png" src="https://github.com/user-attachments/assets/c0df8d11-4a3d-4e7e-9482-4ef71831c4ff" />
<img width="1915" height="1032" alt="T1053-splunk png" src="https://github.com/user-attachments/assets/43fe3dd0-6a1b-42c3-aabf-b46c59e463c7" />

