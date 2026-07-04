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

Invoke-AtomicTest T1070.004 -TestNumbers 4

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

<img width="953" height="295" alt="T1070 004-windows png" src="https://github.com/user-attachments/assets/c566ce55-20ee-4bed-a9d5-62005ba7252f" />
<img width="1913" height="1023" alt="T1070 004-splunk png" src="https://github.com/user-attachments/assets/126cb50a-3716-4a26-a5e3-a66d49d28802" />


