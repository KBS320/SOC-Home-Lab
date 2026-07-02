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

<img width="1002" height="96" alt="T1012-windows png" src="https://github.com/user-attachments/assets/1a38d257-d11e-4e30-bed1-455e93bc1b71" />
<img width="1907" height="1025" alt="T1012-splunk png(1)" src="https://github.com/user-attachments/assets/55e4deb1-b91f-423a-bb88-ab0b122f88b3" />
<img width="1911" height="998" alt="T1012-splunk png(2)" src="https://github.com/user-attachments/assets/42136cb1-a2a0-4eb3-97ec-0cd2066d7b9a" />
