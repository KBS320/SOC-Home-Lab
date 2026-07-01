# T1041 — Exfiltration Over C2 Channel

## What This Attack Does

The attacker sends stolen data out of the network using the same
command and control channel they used to communicate with the compromised
machine. By reusing the existing C2 connection, the exfiltration traffic
blends in with normal C2 communications and is harder to detect. This
is the moment the data actually leaves the organization's network.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1041 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 3 (Network Connection) fired showing:
- Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- DestinationIp: external C2 IP
- DestinationPort: 443
- User: WINDOWS-SERVER\Administrator

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3 Image="*powershell.exe" DestinationPort=443
| table _time, ComputerName, User, Image, DestinationIp, DestinationPort

## Result

Splunk successfully detected outbound data exfiltration attempt.
Alert fired within seconds of the network connection on the target.

## Screenshot

[Splunk alert screenshot — to be added]
