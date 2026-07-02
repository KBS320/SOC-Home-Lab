# T1057 — Process Discovery (tasklist)

## What This Attack Does

The attacker runs tasklist to see every process currently running on the
machine. This helps them identify security tools like antivirus or EDR
agents running in the background, and also shows them what software is
installed and active. If they spot a security tool they will try to
kill it before moving further.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1057 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\tasklist.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: tasklist

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*tasklist.exe"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected tasklist execution.
Alert fired within seconds of the command running on the target.

## Screenshot

<img width="997" height="655" alt="T1057-windows png" src="https://github.com/user-attachments/assets/f0bf328a-8141-4a8c-a29b-64e7b979d1ac" />
<img width="1912" height="1007" alt="T1057-splunk" src="https://github.com/user-attachments/assets/ccbb24a4-85df-4228-962a-51602d2672ba" />


