# T1012 — Query Registry (reg query)

**Tactic:** Discovery  **Technique:** T1012  **Log Source:** Sysmon Event ID 1 (Process Creation)

## What This Attack Does

The attacker queries the Windows registry to find sensitive information stored
there — saved credentials, installed software, auto-run programs, and security
configurations. The registry is a goldmine because many applications store
config data, and sometimes even passwords, in plain text.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows Server target (192.168.56.102):

    Invoke-AtomicTest T1012 -TestNumbers 1

This runs `reg query` against a CurrentVersion key to enumerate registry data.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: `C:\Windows\System32\reg.exe`
- User: `WINDOWS-SERVER\Administrator`
- CommandLine: `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "reg.exe" "query"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

`reg.exe` launching with a `query` argument is the signature here. The command
is native to Windows and used legitimately by admins and installers, so on its
own it is low-fidelity — best treated as an enrichment signal rather than a
standalone alert.

## False Positives / Tuning

`reg query` runs constantly during normal admin work and software installs. The
broad `*query*` match returned 22 events in this run, including related
registry-query activity beyond the Atomic test itself. In production this would
be tuned to reduce noise — for example, scoping to an unusual ParentImage
(`powershell.exe` or `cmd.exe` from a non-interactive process), execution
outside a maintenance window, or `reg query` chained with other discovery
commands (whoami, systeminfo, net user) from the same parent in a short window.

## Result

Splunk detected the `reg query` execution via process-creation logging. The
event captured the full command line, confirming which registry hive the
attacker targeted — useful for scoping what information may have been accessed.

## Screenshots

**Attack executed on Windows Server target:**
<img width="1002" alt="T1012 reg query executed on Windows Server" src="https://github.com/user-attachments/assets/1a38d257-d11e-4e30-bed1-455e93bc1b71" />

**Splunk detection — 22 events returned (part 1 of 2):**
<img width="1907" alt="T1012 Splunk detection results part 1" src="https://github.com/user-attachments/assets/55e4deb1-b91f-423a-bb88-ab0b122f88b3" />

**Splunk detection — continued (part 2 of 2):**
<img width="1911" alt="T1012 Splunk detection results part 2" src="https://github.com/user-attachments/assets/42136cb1-a2a0-4eb3-97ec-0cd2066d7b9a" />
