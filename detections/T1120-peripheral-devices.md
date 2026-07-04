# T1120 — Peripheral Device Discovery

## What This Attack Does

An attacker enumerates hardware and peripheral devices connected to
a compromised system — USB drives, network adapters, printers, and
other plug-and-play devices. This can reveal removable storage
devices that might hold sensitive data, identify security or
monitoring hardware, or help the attacker understand the physical
environment they've gained access to.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1120 -TestNumbers 1

This test queries the `Win32_PnPEntity` WMI class, which lists all
plug-and-play hardware on the system (name, description, and
manufacturer for each device), and writes the results to a
collection file for exfiltration or review.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing the full
PowerShell script:
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- User: `WINDOWS\khaled`
- ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- CommandLine:
  `Get-WMIObject Win32_PnPEntity | Format-Table Name, Description, Manufacturer > $env:TEMP\T1120_collection.txt`
  `$Space,$Heading,$Break,$Data = Get-Content $env:TEMP\T1120_collection.txt`
  `@($Heading; $Break; $Data | Sort-Object -Unique) | ? {$_.trim() -ne "" } | Set-Content $env:TEMP\T1120_collection.txt`

Note: Since this command runs inside the existing PowerShell session
rather than spawning a new process, both Image and ParentImage show
`powershell.exe` — this is expected behavior for in-session PowerShell
commands, not a detection gap.

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "Win32_PnPEntity"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Result

Splunk successfully detected the peripheral device discovery attempt,
capturing the full WMI query and the file-writing logic used to
collect and stage hardware inventory data.

## Screenshot

<img width="867" height="147" alt="T1120-windows" src="https://github.com/user-attachments/assets/c949a8bb-1864-4257-a2b5-98f1f1a09093" />
<img width="1915" height="1027" alt="T1120-splunk" src="https://github.com/user-attachments/assets/47c0b4e9-3478-4dc8-9136-84eedc9d89d5" />
