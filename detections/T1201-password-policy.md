# T1201 — Password Policy Discovery

**Tactic:** Discovery  **Technique:** T1201  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

Before attempting to guess or crack passwords, an attacker checks the target's
password policy — minimum length, complexity, lockout threshold, and expiry. This
tells them how aggressive they can be with brute-force or password-spraying
without tripping an account lockout, and helps them craft guesses that will meet
the complexity rules. It's reconnaissance that directly shapes a later credential
attack.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1201 -TestNumbers 6

Note: Tests #1–5 and #8 are Linux/macOS-only; #9–10 require Active Directory
domain membership (this lab is a standalone Windows 11 host — `net accounts`
even reports `Computer role: WORKSTATION`); #12 is AWS-specific. Test #6
("Examine local password policy — Windows") was the correct fit: it runs the
built-in `net accounts` command with no domain or extra tooling required, and
returned the local policy (min/max password age, lockout threshold, etc.).

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 2 times, showing the full chain:
- User: `WINDOWS\khaled`
- Parent CommandLine: `cmd.exe /c net accounts`
- Child process: `net.exe` running `net accounts`
- Parent chain: `powershell.exe` → `cmd.exe` → `net.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "net accounts"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query keys on `net accounts` — the command that dumps the local password and
lockout policy. This is medium-to-high fidelity: there's limited routine reason
for a user to run `net accounts`, and it has a specific offensive purpose
(sizing up how hard the account-lockout defenses are before a password attack).
The signal strengthens when it's spawned from a script host (`powershell.exe` →
`cmd.exe`) rather than typed by an admin, and especially when it appears shortly
before authentication activity (failed logons, `net use`, spraying attempts).

## False Positives / Tuning

Auditors and hardening scripts sometimes run `net accounts` legitimately, so pair
it with context: a non-interactive parent, or `net accounts` appearing alongside
account-discovery commands (`net user`, `net localgroup`) or immediately before a
spike in logon failures. Because password-policy discovery is a precursor to
credential attacks, treating it as an early-warning signal — and correlating it
with subsequent authentication events — is more valuable than alerting on it in
isolation.

## Result

Splunk detected the password-policy discovery across 2 process-creation events,
capturing the full `powershell.exe` → `cmd.exe` → `net.exe` chain with the exact
command preserved at each stage. The log confirms the attacker enumerated the
local password and lockout policy — reconnaissance that typically precedes a
brute-force or password-spray attempt.

## Screenshots

**Attack executed on Windows 11 target (net accounts — local password policy):**
<img width="862" alt="T1201 password policy discovery on Windows 11" src="https://github.com/user-attachments/assets/9723bf93-51c1-4c66-bff8-5357158d5102" />

**Detection in Splunk — 2 events, powershell → cmd → net accounts chain:**
<img width="1917" alt="T1201 detection in Splunk showing net accounts password policy" src="https://github.com/user-attachments/assets/903071db-116f-4624-ba3b-d199a80087e4" />
