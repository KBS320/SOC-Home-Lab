# T1105 — Ingress Tool Transfer (file download)

## What This Attack Does

The attacker downloads tools or malware from an external server onto
the compromised machine. Once inside a network, attackers rarely bring
everything they need upfront — instead they download additional tools
as needed. This could be a keylogger, a credential dumper, ransomware,
or a remote access tool. Getting malware onto the machine is a critical
step in the attack chain.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1105 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 11 (File Created) and Event ID 3 (Network Connection) fired showing:
- Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- DestinationIp: external IP
- TargetFilename: C:\Users\Administrator\Downloads\tool.exe

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=11 TargetFilename="*.exe" Image="*powershell.exe"
| table _time, ComputerName, User, Image, TargetFilename

## Result

Splunk successfully detected file download via PowerShell.
Alert fired within seconds of the download completing on the target.

## Screenshot

<img width="958" height="217" alt="T1105-windows png (2)" src="https://github.com/user-attachments/assets/ed3649d7-3690-427e-b251-a0ef4e3d2f82" />
<img width="1912" height="1025" alt="T1105-splunk" src="https://github.com/user-attachments/assets/2cbd9efe-00ff-4091-932c-802d3b2b8ced" />

