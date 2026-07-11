# Wazuh SOC Home Lab — Stack Deployment (Suricata + Wazuh + ELK)

A second, independent lab built to get hands-on with an open-source SIEM stack and
network intrusion detection — complementary to the Splunk-based detection work in
[`/detections`](../detections/README.md).

**Scope, stated plainly:** this lab is a **pipeline engineering** exercise, not a
detection-content exercise. The Splunk lab is where the 30 hand-written detections
live. What I set out to prove here was that I could build the plumbing — a fully
TLS-encrypted log pipeline from a network sensor all the way to a dashboard — and
verify it end to end. Custom detection content is the next phase and has started
(see [Custom Detections](#custom-detections) below).

---

## Stack

- Elasticsearch 7.17.13
- Kibana 7.17.13 + Wazuh plugin 4.5.4
- Wazuh Manager 4.5.4
- Filebeat 7.17.13
- Suricata 6.0.4 (51,851 ET Open signatures)

## Host

- Ubuntu 22.04 Desktop on VirtualBox
- 10GB RAM, 60GB disk
- IP: 192.168.56.103

## Architecture

```
Suricata (NIDS) → Wazuh Manager (HIDS + log analysis) → Filebeat → Elasticsearch → Kibana
```

Full TLS between every hop in the pipeline.

---

## Verified Working

- **Full TLS pipeline confirmed end to end:** Suricata → Wazuh → Filebeat → Elasticsearch → Kibana
- **245 security events ingested** and searchable in Kibana
- **Live signature fired end to end:** Suricata caught `GPL ATTACK_RESPONSE id check returned root`
  (Rule 86601) and the alert landed in the Kibana dashboard

### An honest note on that alert

Rule 86601 is an ET Open signature with `signature_severity: Informational` and
`action: allowed` — it is a low-severity rule, and it is the *only* signature that
fired during this test. I am including it because it proves the **pipeline works**,
not because it proves a sophisticated detection.

Likewise, the Technique/Tactic columns are empty for the Suricata alerts in the
screenshots below. Wazuh's MITRE ATT&CK module is enabled and does map its own
built-in ruleset (visible in the "Top MITRE ATT&CKs" panel), but the ET Open
Suricata signatures pass through without ATT&CK metadata. That gap is exactly what
the custom rules below are for.

---

## Custom Detections

Detection content I have written for this stack lives in
[`local_rules.xml`](local_rules.xml).

| Technique | Rule | Log source |
| --------- | ---- | ---------- |
| T1055 — Process Injection | Custom rules in `local_rules.xml` | Sysmon on Windows 11 endpoint (192.168.56.102) |

Roadmap: port a subset of the 30 Splunk detections in
[`/detections`](../detections/README.md) into Wazuh rules so the same techniques are
covered on both stacks.

---

## Screenshots

**Kibana security events dashboard**

![Kibana security events dashboard](kibana-security-events-dashboard.png)

**Security alerts table**

![Kibana security alerts table](kibana-security-alerts-table.png)

**Suricata alert detail**

![Suricata alert detail](kibana-suricata-alert-detail.png)
