# Wazuh SOC Home Lab — Single Host Deployment
 
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
 
## Verified Working
- Full TLS pipeline: Suricata → Wazuh → Filebeat → Elasticsearch → Kibana
- Live detection: GPL ATTACK_RESPONSE id check returned root (Rule 86601)
- 245 security events collected
- MITRE ATT&CK mapping in Kibana dashboard
