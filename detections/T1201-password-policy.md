# T1201 — Password Policy Discovery

## What This Attack Does

Before attempting to guess or crack passwords, an attacker often
checks the target's password policy first — things like minimum
length, complexity requirements, lockout threshold, and how often
passwords expire. This tells them how aggressive they can be with
brute-force or password-spray attempts without triggering an account
lockout, and helps them craft passwords likely to meet requirements.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1201 -TestNumbers 6

Note: Tests #1–5 and #8 in this technique are Linux/macOS-only.
Tests #9–10 require Active Directory domain membership, which this
lab doesn't have (standalone Windows Server, no domain controller).
Test #12 is AWS-specific. Test #6 ("Examine local password policy -
Windows") was the correct fit — it runs the built-in `net accounts`
command with no domain or extra tooling required.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired twice, showing the full
process chain:

**Event 1:**
- Image: `C:\Windows\System32\cmd.exe`
- User: `WINDOWS\khaled`
- CommandLine: `"cmd.exe" /c net accounts`
- ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

**Event 2:**
- Image: `C:\Windows\System32\net.exe`
- User: `WINDOWS\khaled`
- CommandLine: `net  accounts`
- ParentImage: `C:\Windows\System32\cmd.exe`

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

## Result

Splunk successfully detected the password policy discovery attempt,
capturing the full process chain from `powershell.exe` → `cmd.exe` →
`net.exe`, with the exact command line preserved at each stage.

## Screenshot

<img width="862" height="366" alt="T1201-windows png" src="https://github.com/user-attachments/assets/9723bf93-51c1-4c66-bff8-5357158d5102" />
<img width="1917" height="1030" alt="T1201-splunk png" src="https://github.com/user-attachments/assets/903071db-116f-4624-ba3b-d199a80087e4" />
