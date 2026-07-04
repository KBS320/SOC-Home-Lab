# T1087.001 — Local Account Discovery (net user)

**Tactic:** Discovery  **Technique:** T1087.001  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker enumerates the local user accounts on the machine to learn which
accounts exist, which are privileged, and which they might target for escalation
or reuse. This test goes further than a single `net user` — it also lists user
profile folders, dumps saved credentials with `cmdkey`, and enumerates groups,
building a full picture of who's on the box and what secrets are cached.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1087.001 -TestNumbers 8

Test #8 ("Enumerate all accounts on Windows — Local") chains several
account-discovery commands through `cmd.exe`:
`net user`, `dir c:\Users\`, `cmdkey /list`, `net localgroup "Users"`, and
`net localgroup`.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 5 times:
- User: `WINDOWS\khaled`
- Parent CommandLine: `cmd.exe /c net user & dir c:\Users\ & cmdkey.exe /list & net localgroup "Users" & net localgroup`
- Child processes: `net.exe` (`net user`), `cmdkey.exe` (`cmdkey /list`),
  `net.exe` (`net localgroup "Users"`), `net.exe` (`net localgroup`)
- Parent chain: `powershell.exe` → `cmd.exe` → `net.exe` / `cmdkey.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "net user"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query keys on `net user`, but the more interesting artifact in this event is
`cmdkey.exe /list` — it enumerates *stored credentials* on the machine, which is
a meaningful step up from plain account discovery. `cmdkey /list` has almost no
routine interactive use, so it's a higher-fidelity indicator than `net user`
alone. The overall tell is the pattern: accounts + profile folders + saved
creds + groups enumerated back-to-back from one `cmd.exe` parent — a scripted
credential-and-account sweep, not an admin checking one account.

## False Positives / Tuning

`net user` and `net localgroup` appear in legitimate admin and audit activity, so
those alone are noisy. Prioritize the stronger signals from this chain:
`cmdkey /list` (saved-credential enumeration), the full account-discovery burst
from a single parent in a short window, or a non-interactive parent process.
Alerting specifically on `cmdkey /list` — rather than the generic `net` commands
— gives a much cleaner signal, since credential enumeration is rarely benign.

## Result

Splunk detected the full account-and-credential discovery sweep — 5
process-creation events capturing `net user`, the `cmdkey /list` credential dump,
profile-folder listing, and group enumeration. The logs confirm the attacker
profiled every local account and checked for cached credentials in a single
automated pass.

## Screenshots

**Attack executed on Windows 11 target (account enumeration):**
<img width="1002" alt="T1087.001 net user account enumeration on Windows 11" src="https://github.com/user-attachments/assets/4f156810-10d0-4c71-8493-1982dc23f90f" />

**Detection in Splunk — 5 events including cmdkey /list credential enumeration:**
<img width="1912" alt="T1087.001 detection in Splunk showing account and credential discovery" src="https://github.com/user-attachments/assets/3b373844-51f6-46ec-b72e-d7d0b65bcb9e" />
