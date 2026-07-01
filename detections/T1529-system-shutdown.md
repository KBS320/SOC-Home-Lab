# T1529 — System Shutdown/Reboot (destroy evidence and leave)

## What This Attack Does

After completing their mission, the attacker shuts down or reboots the
compromised machine. This is the final cleanup step — a forced reboot
clears certain types of memory-based evidence, interrupts any active
incident response sessions, and can trigger destructive payloads on
reboot. For ransomware attacks, a reboot is often triggered to complete
the encryption process and display the ransom note.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1529 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\shutdown.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: shutdown /r /t 0 /f

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*shutdown.exe"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected forced system shutdown command.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
