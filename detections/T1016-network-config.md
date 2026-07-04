# T1016 — System Network Configuration Discovery (ipconfig)

**Tactic:** Discovery  **Technique:** T1016  **Log Source:** Sysmon Event ID 1 (Process Creation)

## What This Attack Does

The attacker runs `ipconfig` to map out the network they landed on. This
reveals the IP address, subnet, default gateway, and DNS servers. With this
info they can understand the network layout and plan lateral movement to other
machines on the same network.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows Server target (192.168.56.102):

    Invoke-AtomicTest T1016 -TestNumbers 1

This runs `ipconfig /all` to enumerate full network configuration.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: `C:\Windows\System32\ipconfig.exe`
- User: `WINDOWS-SERVER\Administrator`
- CommandLine: `ipconfig /all`

## SPL Detection Query

```spl
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\ipconfig.exe"
| table _time, ComputerName, User, CommandLine, ParentImage
| sort -_time
```

## Detection Logic

Any execution of `ipconfig.exe` is the signature. It's a native Windows tool
used constantly by admins, so on its own this is low-fidelity — best used as
an enrichment signal rather than a standalone alert. The `/all` flag is a mild
escalator, since attackers favor it for the fuller output (DNS, MAC, DHCP).

## False Positives / Tuning

`ipconfig` runs during normal troubleshooting, login scripts, and automated
health checks, so it fires often on its own. To cut noise, correlate on: an
unusual ParentImage (`powershell.exe` or `cmd.exe` spawned by a non-interactive
process), or `ipconfig` chained with other discovery commands (whoami,
systeminfo, net user, netstat) from the same parent in a short window. A lone
`ipconfig` is rarely worth an alert; a burst of discovery commands is.

## Result

Splunk detected the `ipconfig /all` execution via process-creation logging,
capturing the full command line and confirming the attacker enumerated network
configuration on the target.

## Screenshots

**Attack executed on Windows Server target:**
<img width="1003" alt="T1016 ipconfig executed on Windows Server" src="https://github.com/user-attachments/assets/e007f51b-54d2-4796-9961-f87ef26b4c30" />

**Detection in Splunk:**
<img width="1912" alt="T1016 detection in Splunk" src="https://github.com/user-attachments/assets/687ba8a9-c471-4f9b-a648-76cbdea9019d" />
