# Azure Sentinel SOC Lab

A hands-on home lab simulating enterprise Security Operations Center (SOC) workflows using Microsoft Sentinel. Built to demonstrate practical skills in SIEM management, detection engineering, KQL query writing, and incident response.

---

## 🧰 Lab Overview

| Component | Technology |
|---|---|
| SIEM | Microsoft Sentinel |
| Log Analytics | Azure Log Analytics Workspace |
| Data Sources | Windows Event Logs, Azure AD / Entra ID, Syslog (Linux), Azure Activity |
| Detection | KQL Scheduled Analytics Rules |
| SOAR | Azure Logic Apps (Playbooks) |
| Threat Intel | Watchlists + external IP feeds |

---

## 📁 Repository Structure

```
sentinel-soc-lab/
├── README.md
├── architecture/
│   └── lab-diagram.png          # High-level architecture diagram
├── detection-rules/
│   ├── brute-force-detection.kql
│   ├── impossible-travel.kql
│   └── new-admin-after-hours.kql
├── playbooks/
│   └── ip-enrichment-virustotal.json
├── runbooks/
│   ├── brute-force-ir-runbook.md
│   └── account-compromise-runbook.md
└── screenshots/
    └── (sanitized screenshots of Sentinel dashboards and incidents)
```

---

## 🔍 Detection Rules

Each `.kql` file in `/detection-rules` is a standalone Sentinel analytics rule. Rules are written to be generic and portable — no hardcoded tenant IDs, workspace names, or internal resource identifiers.

| Rule | Tactic (MITRE) | Severity |
|---|---|---|
| Brute Force Detection | Credential Access (T1110) | High |
| Impossible Travel | Initial Access (T1078) | Medium |
| New Admin After Hours | Persistence (T1098) | High |

---

## 📋 Runbooks

Incident response runbooks in `/runbooks` document the triage and response process for each detection rule. Each runbook follows the NIST SP 800-61 incident response lifecycle:

1. **Preparation**
2. **Detection & Analysis**
3. **Containment, Eradication & Recovery**
4. **Post-Incident Activity**

---

## 🤖 Playbooks

Logic App playbooks in `/playbooks` automate response actions triggered by Sentinel incidents. Current playbooks:

- **IP Enrichment via VirusTotal** — automatically queries VirusTotal on any incident containing an external IP and appends the result as an incident comment.

---

## 🧠 Skills Demonstrated

- Microsoft Sentinel deployment and configuration
- Data connector setup and log ingestion
- KQL (Kusto Query Language) for threat detection
- MITRE ATT&CK framework mapping
- Incident triage and response workflows
- SOAR automation with Azure Logic Apps
- Security documentation and runbook writing

---

## ⚠️ Disclaimer

This lab was built in an isolated Azure sandbox environment for educational and portfolio purposes. All screenshots have been sanitized — tenant IDs, subscription IDs, email addresses, and internal resource names have been redacted.

---

## 📌 Status

🟡 In Progress — actively building out detection rules and playbooks.
