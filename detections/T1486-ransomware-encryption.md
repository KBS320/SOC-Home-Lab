# T1486 — Data Encrypted for Impact (ransomware simulation)

## What This Attack Does

The attacker encrypts files on the victim machine to make them
inaccessible, then demands a ransom payment to restore access.
This is ransomware. It is the most financially damaging cyberattack
type in existence today, costing organizations billions of dollars
annually. Detecting the encryption process early — before it spreads
to all files — is critical to minimizing damage.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1486 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 11 (File Created) fired in rapid succession showing:
- Multiple files being written with new extensions
- Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- TargetFilename: C:\Users\Administrator\Documents\file.encrypted
- User: WINDOWS-SERVER\Administrator

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=11
| stats count by TargetFilename, Image
| where count > 20
| table _time, ComputerName, Image, TargetFilename, count

## Result

Splunk successfully detected mass file encryption activity.
The high volume of file writes in a short time triggered the alert.

## Screenshot

[Splunk alert screenshot — to be added]
