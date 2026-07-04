# T1547.001 — Registry Run Keys

**Tactic:** Persistence  **Technique:** T1547.001  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker adds an entry to a Windows registry Run key so their program launches
automatically every time the user logs in. The Run key exists to start legitimate
software at login, but attackers abuse it to make sure their payload always comes
back after a reboot or logout. It's one of the oldest and most reliable
persistence mechanisms in the attacker playbook — simple, effective, and easy to
overlook.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1547.001 -TestNumbers 1

Test #1 ("Reg Key Run") adds a Run-key value that points to an executable, so it
runs at each logon:
`REG ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"`
The operation completed successfully (exit code 0).

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 3 times, capturing the `REG ADD`
command that created the persistence entry:
- User: `WINDOWS\khaled`
- Parent CommandLine: `cmd.exe /c REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"`
- Child process: `reg.exe` executing the `REG ADD ...\CurrentVersion\Run`
- Parent chain: `powershell.exe` → `cmd.exe` → `reg.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "CurrentVersion\\Run"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query keys on the `CurrentVersion\Run` path, catching writes to the autorun
location at the command level (`REG ADD`) rather than relying only on Sysmon's
Registry Value Set event (Event ID 13). Catching the `reg add` command preserves
the full entry — the value name (`"Atomic Red Team"`) and the target executable
(`C:\Path\AtomicRedTeam.exe`) — so a responder immediately sees *what* was set to
persist. High-value escalators: a Run-key value pointing to an executable in a
temp/user/unusual path, and `reg add` spawned from a script host rather than an
installer's own signed binary. Note both `HKCU\...\Run` (per-user) and
`HKLM\...\Run` (all-users) keys matter — this test used HKCU.

## False Positives / Tuning

Legitimate software registers Run-key entries during install, so this isn't
zero-noise. Separate benign from malicious by: the target path (temp, Downloads,
ProgramData, or a bare `.exe` in a user dir is suspicious; `Program Files` is
usually fine), the parent process (`reg.exe` from `cmd.exe`/`powershell.exe` vs.
from a signed installer), and whether the entry appears alongside other intrusion
activity. Pair the command-level detection here with Event ID 13 monitoring of the
Run keys for a second, complementary view, and consider a baseline of known-good
Run entries so new additions stand out.

## Result

Splunk detected the Run-key persistence across 3 process-creation events,
preserving the full `REG ADD` command — the autorun value name and the executable
it points to. The log gives a responder exactly what they need to find and remove
the persistence: which key, which value, and which file runs at logon.

## Screenshots

**Attack executed on Windows 11 target (Run-key persistence via REG ADD):**
<img width="1002" alt="T1547.001 registry Run key persistence on Windows 11" src="https://github.com/user-attachments/assets/3d944171-6ad8-46d1-aad0-1d44207ae879" />

**Detection in Splunk — 3 events, REG ADD to CurrentVersion\Run:**
<img width="1917" alt="T1547.001 detection in Splunk showing Run key registry persistence" src="https://github.com/user-attachments/assets/3ec4fe98-a8f2-4065-8b4e-bf184c47d323" />
