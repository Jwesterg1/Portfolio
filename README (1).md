# Architecture

This folder contains architecture diagrams for the Azure Sentinel SOC Lab.

## Lab Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Azure Tenant                         │
│                                                         │
│  ┌──────────────┐     ┌──────────────────────────────┐  │
│  │  Entra ID    │────▶│   Log Analytics Workspace    │  │
│  │  (Azure AD)  │     │                              │  │
│  │              │     │  ┌────────────────────────┐  │  │
│  │ - Sign-in    │     │  │  Microsoft Sentinel    │  │  │
│  │   logs       │     │  │                        │  │  │
│  │ - Audit logs │     │  │  - Analytics Rules     │  │  │
│  └──────────────┘     │  │  - Incidents           │  │  │
│                       │  │  - Workbooks           │  │  │
│  ┌──────────────┐     │  │  - Watchlists          │  │  │
│  │  Windows VM  │────▶│  │  - Playbooks (SOAR)    │  │  │
│  │              │     │  └────────────────────────┘  │  │
│  │ - Security   │     └──────────────────────────────┘  │
│  │   Events     │                   │                   │
│  │ - Sysmon     │                   │                   │
│  └──────────────┘            ┌──────▼──────┐            │
│                              │ Logic Apps  │            │
│  ┌──────────────┐            │  Playbooks  │            │
│  │   Linux VM   │────▶       │             │            │
│  │              │     LAW    │ - IP Enrich │            │
│  │ - Syslog     │            │ - Notify    │            │
│  │ - Auth logs  │            └─────────────┘            │
│  └──────────────┘                                       │
│                                                         │
│  ┌──────────────┐                                       │
│  │ Azure Activity│───▶ (ingested automatically)         │
│  │ Logs         │                                       │
│  └──────────────┘                                       │
└─────────────────────────────────────────────────────────┘
```

## Data Flow

1. **Log Sources** generate events (VMs, Entra ID, Azure Activity)
2. **Azure Monitor Agent (AMA)** ships logs to the **Log Analytics Workspace**
3. **Microsoft Sentinel** runs **Analytics Rules** (KQL) against the LAW on a schedule
4. When a rule fires, Sentinel creates an **Incident**
5. **Logic App Playbooks** are triggered automatically or manually to enrich/respond
6. Analysts triage incidents in the **Sentinel Incidents** queue using runbooks

## Components

| Component | Purpose | SKU/Tier |
|---|---|---|
| Log Analytics Workspace | Central log store | Pay-as-you-go |
| Microsoft Sentinel | SIEM/SOAR layer | Trial (31 days) then consumption |
| Windows Server VM | Log source — Windows events | Standard_B2s |
| Ubuntu VM | Log source — Syslog | Standard_B1s |
| Logic Apps | Playbook automation | Consumption |
| Defender for Cloud | Vulnerability posture | Free tier |
