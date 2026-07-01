# T1560.001 — Archive Collected Data (zip files)

## What This Attack Does

Before exfiltrating stolen data, the attacker compresses and archives
all the files they collected into a zip or archive file. This serves
two purposes — it makes the data smaller and faster to transfer, and
it can also help bypass data loss prevention tools that scan individual
files but might miss packed archives. This is the final preparation
step before the data leaves the network.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1560.001 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: Compress-Archive -Path C:\Users\Administrator\Documents -DestinationPath C:\temp\exfil.zip

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 CommandLine="*Compress-Archive*" OR CommandLine="*-DestinationPath*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected archive creation activity.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
