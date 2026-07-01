# T1070.004 — File Deletion (erase evidence)

## What This Attack Does

After completing their mission, the attacker deletes files they created
or downloaded during the attack to remove evidence of their presence.
This is a cleanup step designed to make forensic investigation harder.
Deleting malware, scripts, and logs makes it difficult for incident
responders to reconstruct what happened on the machine.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1070.004 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 23 (File Delete) fired showing:
- Image: C:\Windows\System32\cmd.exe
- TargetFilename: C:\Users\Administrator\malicious.exe
- User: WINDOWS-SERVER\Administrator

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=23
| table _time, ComputerName, User, Image, TargetFilename

## Result

Splunk successfully detected file deletion activity.
Alert fired within seconds of the deletion on the target.

## Screenshot

[Splunk alert screenshot — to be added]
