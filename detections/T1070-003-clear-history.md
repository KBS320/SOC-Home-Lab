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

Invoke-AtomicTest T1070.003 -TestNumbers 1

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

[Splunk alert screenshot — to be added]
