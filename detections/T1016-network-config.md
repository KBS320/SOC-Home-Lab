# T1016 — System Network Configuration Discovery (ipconfig)

## What This Attack Does

The attacker runs ipconfig to map out the network they landed on.
This reveals the IP address, subnet, default gateway, and DNS servers.
With this info they can understand the network layout and plan
lateral movement to other machines on the same network.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1016 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\ipconfig.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: ipconfig /all

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*ipconfig.exe"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected ipconfig execution.
Alert fired within seconds of the command running on the target.

## Screenshot

<img width="1003" height="120" alt="T1016-windows png" src="https://github.com/user-attachments/assets/e007f51b-54d2-4796-9961-f87ef26b4c30" />
<img width="1912" height="1006" alt="T1016-windows" src="https://github.com/user-attachments/assets/687ba8a9-c471-4f9b-a648-76cbdea9019d" />

