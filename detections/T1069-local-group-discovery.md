# T1069.001 — Local Group Discovery (net localgroup)

## What This Attack Does

The attacker runs net localgroup to find out which groups exist on the
machine and who belongs to them. The main target is the Administrators
group — knowing who has admin rights tells the attacker which accounts
are worth targeting to gain elevated privileges on the system.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1069.001 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\net.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: net localgroup administrators

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*net.exe" CommandLine="*localgroup*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected net localgroup execution.
Alert fired within seconds of the command running on the target.

## Screenshot

<img width="997" height="112" alt="T1069-windows png" src="https://github.com/user-attachments/assets/af58eae5-3093-468c-bf9e-64afc6de7de3" />
<img width="1912" height="1010" alt="T1069-splunk" src="https://github.com/user-attachments/assets/ad8274da-014f-431e-911b-97991a763e68" />

