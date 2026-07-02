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

<img width="982" height="116" alt="T1082-windows png" src="https://github.com/user-attachments/assets/d5fd6a05-2fb6-4cde-b373-99765994d7d8" />
<img width="1912" height="966" alt="T1082-splunk png" src="https://github.com/user-attachments/assets/453af195-a13f-4a04-a2fa-79a0c3211755" />


