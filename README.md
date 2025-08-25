# SOC Analyst Home Lab Portfolio

This repo documents my hands-on SOC analyst lab, simulating real-world detection, investigation, and incident response.  
Environment includes **Wazuh**, **Splunk Free**, **Azure Sentinel (trial)**, **Sysmon + OSQuery telemetry**, **threat intelligence feeds (OTX, Abuse.ch)**, and **adversarial simulations (brute force, phishing, malware, exfiltration, Atomic Red Team).**

---

## Portfolio Structure
---

## Vulnerability Reports (VulnReports/)
| CVE ID | Title | Severity | Status | Report |
|--------|-------|----------|--------|--------|
| CVE-2023-4863 | Heap buffer overflow in libwebp | Critical | Mitigated | [Report](VulnReports/CVE-2023-4863.md) |
| CVE-2024-1234 | Example Windows Kernel vuln | High | Open | [Report](VulnReports/CVE-2024-1234.md) |

---

## Detection Reports (Detections/)
Writeups on simulated adversarial activity and how it was detected in SIEM.

| Attack Type | MITRE ATT&CK ID | Agent | Detection | Report |
|-------------|-----------------|-------|-----------|--------|
| RDP Brute Force | T1110 | Dell (Windows) | Failed logins + account lockout | [Report](Detections/RDP_BruteForce.md) |
| Credential Dumping (Mimikatz) | T1003 | Dell (Windows) | Sysmon event 10 + Wazuh alert | [Report](Detections/Mimikatz_CredDump.md) |
| File Integrity Change | T1070 | Macbook | FIM event triggered | [Report](Detections/Mac_FIM_Test.md) |

---

## Incident Response Playbooks (Incident_Playbooks/)
Each playbook documents a full SOC-style incident workflow: detection → triage → investigation → response → lessons learned.

| Incident | Trigger | Impact | Playbook |
|----------|---------|--------|----------|
| Suspicious Login | Brute force from Kali | Potential RDP compromise | [Playbook](Incident_Playbooks/BruteForce_Playbook.md) |
| Malware Alert | EICAR test file | AV triggered, confirmed detection | [Playbook](Incident_Playbooks/EICAR_Playbook.md) |

---

## Threat Intelligence Integration
- **AlienVault OTX** → API integrated in Wazuh, subscribed to key pulses:  
  - AlienVault Official  
  - Abuse.ch MalwareBazaar / URLhaus  
  - Windows Malware IOCs  
  - macOS Malware IOCs  
  - Recent Critical CVEs  
- **Detection examples**:  
  - IOC match with Emotet C2 domain  
  - Known ransomware IP blocked  

---

## Lab Setup Notes (Lab_Docs/)
- [Wazuh Manager/Dashboard Setup](Lab_Docs/Wazuh_Setup.md)  
- [Splunk Free Setup](Lab_Docs/Splunk_Setup.md)  
- [Sysmon + OSQuery Deployment](Lab_Docs/Sysmon_OSQuery.md)  
- [OTX Integration Config](Lab_Docs/OTX_Config.md)  

---

## Skills Demonstrated
- SIEM: Wazuh, Splunk, Sentinel (trial)  
- EDR-like telemetry: Sysmon, OSQuery  
- Threat Intel: OTX, Abuse.ch  
- Adversarial Simulation: brute force, phishing, malware, exfiltration, Atomic Red Team  
- Incident Response: detection → investigation → root cause → remediation → reporting  
- Scripting: Python, PowerShell, Bash (automation for log parsing & enrichment)  

---