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

<img width="1007" height="82" alt="T1082-windows png" src="https://github.com/user-attachments/assets/47cb0179-4162-4178-b2d5-40d4b8fd7695" />
<img width="1913" height="932" alt="T1082-splunk png" src="https://github.com/user-attachments/assets/3b4bdf62-b4a0-407d-ad33-57ae8380c305" />
