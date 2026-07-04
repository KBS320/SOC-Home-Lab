# T1120 — Peripheral Device Discovery

**Tactic:** Discovery  **Technique:** T1120  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker enumerates hardware and peripheral devices connected to the machine
— USB drives, network adapters, printers, and other plug-and-play devices. This
reveals removable storage that might hold sensitive data or be used to exfiltrate
it, identifies security/monitoring hardware, and helps the attacker understand the
physical environment they've reached.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1120 -TestNumbers 1

Test #1 ("Win32_PnPEntity Hardware Inventory") queries the `Win32_PnPEntity` WMI
class — which lists every plug-and-play device (name, description, manufacturer)
— and writes the results to a collection file, then de-duplicates and rewrites it:
`Get-WMIObject Win32_PnPEntity | Format-Table Name, Description, Manufacturer > $env:TEMP\T1120_collection.txt`

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired once, capturing the full PowerShell
script:
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- User: `WINDOWS\khaled`
- ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- CommandLine (key portions):
  `Get-WMIObject Win32_PnPEntity | Format-Table Name, Description, Manufacturer > $env:TEMP\T1120_collection.txt`,
  then reads the file back and rewrites a de-duplicated, sorted version to
  `$env:TEMP\T1120_collection.txt`

Note: because this ran inside the existing PowerShell session rather than spawning
a new child process, both Image and ParentImage show `powershell.exe` — expected
behavior for in-session commands, not a detection gap.

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

## Detection Logic

The query keys on `Win32_PnPEntity`, the WMI class used to enumerate plug-and-play
hardware. This is a fairly high-fidelity indicator: WMI hardware inventory via
PowerShell has limited routine interactive use, and the class name is specific
enough to avoid most false positives. The stronger signal is the full behavior in
this one event — a WMI hardware query whose output is redirected to a file in
`%temp%`. That's not just discovery; it's discovery being *staged*, which points
toward collection and eventual exfiltration.

## False Positives / Tuning

Some inventory and asset-management tooling legitimately queries WMI hardware
classes, so pair `Win32_PnPEntity` with context to reduce noise: output
redirected to a temp/staging file, a non-interactive parent, or the same session
running other discovery/collection commands. The broader detection covers related
WMI recon classes too — `Win32_USBHub`, `Win32_DiskDrive`, `Win32_LogicalDisk`,
`Win32_NetworkAdapter` — which attackers use for the same hardware-profiling goal.

## Result

Splunk detected the peripheral-device discovery in a single process-creation
event, capturing the full WMI query and the file-writing logic used to collect
and stage the hardware inventory. The log shows both the enumeration and the
`%temp%` staging file, tying this Discovery action forward toward collection and
exfiltration.

## Screenshots

**Attack executed on Windows 11 target (WMI hardware inventory):**
<img width="867" alt="T1120 peripheral device discovery on Windows 11" src="https://github.com/user-attachments/assets/c949a8bb-1864-4257-a2b5-98f1f1a09093" />

**Detection in Splunk — Win32_PnPEntity query staged to temp file:**
<img width="1915" alt="T1120 detection in Splunk showing Win32_PnPEntity hardware inventory" src="https://github.com/user-attachments/assets/47c0b4e9-3478-4dc8-9136-84eedc9d89d5" />
