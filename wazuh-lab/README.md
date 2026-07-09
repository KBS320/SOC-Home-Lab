# Wazuh SOC Home Lab — Single Host Deployment

A second, independent detection lab built to get hands-on with an open-source SIEM stack and network intrusion detection — complementary to the Splunk-based lab in [`/detections`](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/README.md).

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

## Verified Working

- Full TLS pipeline confirmed end to end: Suricata → Wazuh → Filebeat → Elasticsearch → Kibana
- Live detection fired correctly: GPL ATTACK_RESPONSE id check returned root (Rule 86601)
- 245 security events collected
- MITRE ATT&CK mapping enabled in the Kibana dashboard

## Screenshots

**Kibana security events dashboard**

![Kibana security events dashboard](https://raw.githubusercontent.com/KBS320/SOC-Home-Lab/main/wazuh-lab/kibana-security-events-dashboard.png)

**Security alerts table**

![Kibana security alerts table](https://raw.githubusercontent.com/KBS320/SOC-Home-Lab/main/wazuh-lab/kibana-security-alerts-table.png)

**Suricata alert detail**

![Suricata alert detail](https://raw.githubusercontent.com/KBS320/SOC-Home-Lab/main/wazuh-lab/kibana-suricata-alert-detail.png)
