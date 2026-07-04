# T1016 — System Network Configuration Discovery (ipconfig)

**Tactic:** Discovery  **Technique:** T1016  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker enumerates the network configuration of the machine they landed on
— IP address, subnet, default gateway, DNS servers, interfaces, and NetBIOS
info. With this they can understand the network layout and plan lateral movement
to other machines on the same network.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1016 -TestNumbers 1

This test doesn't just run one command — it chains several network-discovery
commands together through `cmd.exe`:
`ipconfig /all`, `netsh interface show interface`, `arp -a`, `nbtstat -n`,
and `net config`. Each spawns its own process, so a single test produces
multiple Sysmon events.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 5 times — once for the parent
`cmd.exe` and once for each chained tool:
- User: `WINDOWS\khaled`
- Parent CommandLine: `cmd.exe /c ipconfig /all & netsh interface show interface & arp -a & nbtstat -n & net config`
- Child processes: `ipconfig.exe`, `netsh.exe`, `nbtstat.exe`, `net.exe`
- All spawned by `C:\Windows\System32\cmd.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "ipconfig"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query matches any Sysmon event containing the string `ipconfig`, then uses
`rex` to pull Image, CommandLine, ParentImage, and User from the raw XML. It's a
broad string match, so it's high-recall but low-precision. The stronger signal
here isn't `ipconfig` alone — it's the **parent `cmd.exe` running five discovery
commands back-to-back in under a second**, which is far more suspicious than any
single command on its own.

## False Positives / Tuning

`ipconfig` runs during normal troubleshooting, login scripts, and health checks,
so on its own it's noisy. The high-fidelity version of this detection keys off
the *pattern*: a single parent process (`cmd.exe` or `powershell.exe`) spawning
multiple network-discovery children (`ipconfig`, `arp`, `nbtstat`, `netsh`,
`net`) inside a short time window. One `ipconfig` is rarely worth an alert; five
chained discovery commands from one parent is a classic recon burst.

## Result

Splunk detected the full discovery chain — 5 process-creation events from one
`cmd.exe` parent — capturing every command line and confirming the attacker
enumerated network configuration on the target in a single automated sweep.

## Screenshots

**Attack executed on Windows 11 target:**
<img width="1003" alt="T1016 network discovery test executed on Windows 11" src="https://github.com/user-attachments/assets/e007f51b-54d2-4796-9961-f87ef26b4c30" />

**Detection in Splunk — 5 events from one cmd.exe parent:**
<img width="1912" alt="T1016 detection in Splunk showing 5 chained discovery commands" src="https://github.com/user-attachments/assets/687ba8a9-c471-4f9b-a648-76cbdea9019d" />
