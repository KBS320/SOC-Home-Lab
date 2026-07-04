# T1069.001 — Local Group Discovery (net localgroup)

**Tactic:** Discovery  **Technique:** T1069.001  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker runs `net localgroup` to list the groups on the machine and who
belongs to them. The prize is the **Administrators** group — knowing which
accounts hold admin rights tells the attacker exactly who to target for
privilege escalation. It's a standard early step in mapping the local privilege
landscape after gaining a foothold.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1069.001 -TestNumbers 2

Test #2 ("Basic Permission Groups Discovery — Local") runs two queries in
sequence: `net localgroup` to enumerate all local groups, then
`net localgroup "Administrators"` to list the members of the admin group.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 5 times:
- User: `WINDOWS\khaled`
- Parent CommandLine: `cmd.exe /c net localgroup & net localgroup "Administrators"`
- Child processes: `net.exe` / `net1.exe` for both `net localgroup` and
  `net localgroup "Administrators"` (Windows spawns `net1.exe` under `net.exe`)
- Parent chain: `powershell.exe` → `cmd.exe` → `net.exe` → `net1.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "localgroup"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query matches any Sysmon event containing `localgroup`, then rex-extracts the
key fields. `net localgroup` on its own is medium-fidelity — more targeted than a
generic `net` command, since there's limited routine reason to enumerate the
Administrators group. The stronger signal is `net localgroup "Administrators"`
specifically (attacker hunting for admin accounts), especially when spawned from
a script host (`powershell.exe` → `cmd.exe`) rather than typed by an admin. Note
the `net.exe` → `net1.exe` pairing: Windows delegates `net localgroup` to
`net1.exe`, so both appear in the logs for a single command.

## False Positives / Tuning

Some inventory and audit scripts enumerate local groups legitimately, so this
isn't zero-noise. Tune by prioritizing queries that specifically target
`Administrators` (or other privileged groups), a non-interactive parent, or
`net localgroup` appearing alongside other discovery commands (`net user`,
`whoami`, `net group`) from the same parent in a short window. A single audit
query is benign; admin-group enumeration inside a discovery burst is not.

## Result

Splunk detected the full group-discovery sequence — 5 process-creation events
capturing both `net localgroup` queries and the `net.exe`/`net1.exe` pairing.
The logs confirm the attacker enumerated local groups and specifically listed
the Administrators membership on the target.

## Screenshots

**Attack executed on Windows 11 target (local group enumeration):**
<img width="997" alt="T1069.001 net localgroup executed on Windows 11" src="https://github.com/user-attachments/assets/af58eae5-3093-468c-bf9e-64afc6de7de3" />

**Detection in Splunk — 5 events, both localgroup queries:**
<img width="1912" alt="T1069.001 detection in Splunk showing net localgroup enumeration" src="https://github.com/user-attachments/assets/ad8274da-014f-431e-911b-97991a763e68" />
