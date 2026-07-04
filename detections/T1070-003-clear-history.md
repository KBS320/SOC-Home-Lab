# T1070.003 — Clear Command History

## What This Attack Does

The attacker clears the PowerShell and command line history to remove
any record of the commands they ran on the machine. Every command typed
in PowerShell or CMD gets logged by Windows — clearing this history
is like wiping fingerprints off a crime scene. This makes it much
harder for incident responders to see exactly what the attacker did.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1070.003 -TestNumbers 12

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: Clear-History; Remove-Item (Get-PSReadlineOption).HistorySavePath

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 CommandLine="*Clear-History*" OR CommandLine="*HistorySavePath*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected history clearing activity.
Alert fired within seconds of the command running on the target.

## Screenshot

<img width="947" height="140" alt="T1070 003-windows png" src="https://github.com/user-attachments/assets/43b9c821-bc44-49a0-bbb3-85e59ca1da1a" />
<img width="1917" height="1025" alt="T1070 003-splunk png" src="https://github.com/user-attachments/assets/0fa3e6ab-b030-4026-a4c5-bcca44a20d9d" />

