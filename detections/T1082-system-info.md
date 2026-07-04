# T1082 — System Information Discovery (systeminfo)

**Tactic:** Discovery  **Technique:** T1082  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker runs `systeminfo` to pull detailed information about the machine —
OS version, hostname, installed hotfixes, RAM, and network adapters. This tells
them exactly what they're working with and, critically, which patches are
missing — pointing them toward known exploits they can use for privilege
escalation or lateral movement.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the target host (192.168.56.102):

    Invoke-AtomicTest T1082 -TestNumbers 1

Test #1 ("System Information Discovery") runs `systeminfo` and then queries the
registry for attached disks, chaining both through `cmd.exe`:
`systeminfo & reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum`.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 5 times:
- User: `WINDOWS\khaled`
- Parent CommandLine: `cmd.exe /c systeminfo & reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum`
- Child processes: three `systeminfo.exe` executions and one `reg.exe`
  (`reg query ...Disk\Enum`)
- Parent chain: `powershell.exe` → `cmd.exe` → `systeminfo.exe` / `reg.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "systeminfo"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query matches any Sysmon event containing `systeminfo`, then rex-extracts the
key fields. `systeminfo` alone is low-fidelity — it's a legitimate diagnostic
tool. The stronger signal is the combination captured here: `systeminfo` paired
with a `reg query` for disk enumeration, both spawned from a `powershell.exe` →
`cmd.exe` chain. That's scripted host-profiling — an attacker fingerprinting the
box (OS, patches, storage) — rather than an admin checking one thing manually.

## False Positives / Tuning

`systeminfo` runs during legitimate inventory, support, and audit work, so it's
noisy on its own. Tune by keying on a non-interactive parent
(`powershell.exe`/`cmd.exe` from automation) or by correlating `systeminfo` with
other discovery commands (`reg query`, `whoami`, `ipconfig`, `net user`) from the
same parent in a short window. A single `systeminfo` is routine; a host-profiling
burst is worth investigating.

## Result

Splunk detected the host-profiling sequence — 5 process-creation events capturing
`systeminfo` and the chained `reg query` disk enumeration. The logs confirm the
attacker fingerprinted the machine's configuration and storage in a single
automated sweep.

## Screenshots

**Attack executed on target host (systeminfo enumeration):**
<img width="982" alt="T1082 systeminfo executed on target host" src="https://github.com/user-attachments/assets/d5fd6a05-2fb6-4cde-b373-99765994d7d8" />

**Detection in Splunk — 5 events, systeminfo plus reg query disk enumeration:**
<img width="1912" alt="T1082 detection in Splunk showing systeminfo and reg query" src="https://github.com/user-attachments/assets/453af195-a13f-4a04-a2fa-79a0c3211755" />
