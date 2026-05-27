# Incident Response Runbook: Brute Force / Password Spray

**Runbook ID:** IR-001  
**Version:** 1.0  
**MITRE ATT&CK Tactic:** Credential Access  
**MITRE Technique:** T1110 – Brute Force  
**Severity:** High  
**Triggering Rule:** `brute-force-detection.kql`

---

## 1. Preparation

### Prerequisites
- Access to Microsoft Sentinel incident queue
- Read access to Log Analytics Workspace
- Ability to query `SecurityEvent` and `SigninLogs` tables
- Access to identity management system (Active Directory / Entra ID)
- Communication channel to notify affected users or account owners

### Key Event IDs
| Event ID | Description |
|---|---|
| 4625 | Failed logon (Windows) |
| 4624 | Successful logon (Windows) |
| 4648 | Logon attempt with explicit credentials |
| 4771 | Kerberos pre-auth failure |

---

## 2. Detection & Analysis

### Step 2.1 – Validate the Alert
Confirm the incident is not a false positive before escalating.

```kql
// Check the volume and pattern of failures from the flagged IP
SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4625
| where IpAddress == "<FLAGGED_IP>"
| summarize Count = count() by TargetUserName, IpAddress, bin(TimeGenerated, 1m)
| order by TimeGenerated desc
```

**Ask:**
- Is the IP an internal scanner, vulnerability scanner, or known monitoring tool?
- Is the volume consistent with a user mistyping their password, or systematic enumeration?
- Are multiple usernames being targeted (spray) or a single account (stuffing)?

---

### Step 2.2 – Determine Attack Type

| Pattern | Likely Attack |
|---|---|
| Many failures → 1 account | Traditional brute force |
| 1–2 failures × many accounts | Password spray |
| Failures + immediate success | Credential stuffing / valid creds obtained |
| Off-hours + service accounts | Automated attack |

```kql
// Did any failures result in a successful login?
SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID in (4624, 4625)
| where IpAddress == "<FLAGGED_IP>"
| summarize
    Failures = countif(EventID == 4625),
    Successes = countif(EventID == 4624)
    by IpAddress, TargetUserName
| where Successes > 0
```

---

### Step 2.3 – Scope the Impact

```kql
// What accounts were successfully logged into after failures?
SecurityEvent
| where TimeGenerated >= ago(2h)
| where EventID == 4624
| where IpAddress == "<FLAGGED_IP>"
| project TimeGenerated, TargetUserName, IpAddress, LogonType, WorkstationName
```

```kql
// Has the IP appeared in any other alerts recently?
SecurityAlert
| where TimeGenerated >= ago(7d)
| where Entities has "<FLAGGED_IP>"
| project TimeGenerated, AlertName, Severity, Description
```

---

### Step 2.4 – Enrich the Source IP
- Query VirusTotal, AbuseIPDB, or Shodan for reputation data
- Check if IP is listed on any threat intel feeds
- Determine ASN / hosting provider (residential, cloud, Tor, VPN?)

---

## 3. Containment

### Step 3.1 – Short-Term Containment

**If attack is ongoing and external:**
- Block the source IP at the firewall / NSG (Network Security Group)
- Add IP to Sentinel watchlist for ongoing monitoring

**If a successful login occurred:**
- **Immediately disable or reset** the compromised account
- Revoke active sessions:
  - Azure AD: Entra ID → User → Revoke Sessions
  - On-prem AD: `Disable-ADAccount` or lock via ADUC

**If attack is internal (lateral movement):**
- Isolate the source host from the network
- Notify the system owner

---

### Step 3.2 – Notify Stakeholders
- Notify the account owner if a successful login occurred
- Escalate to senior analyst or incident commander if multiple accounts are compromised
- Log all actions taken in the Sentinel incident timeline

---

## 4. Eradication & Recovery

### Step 4.1 – Eradication
- Confirm no persistence mechanisms were established (new accounts, scheduled tasks, registry keys)
- Audit recently modified accounts:
  ```kql
  SecurityEvent
  | where TimeGenerated >= ago(24h)
  | where EventID in (4720, 4738, 4732)  // Created, Modified, Group change
  | project TimeGenerated, EventID, SubjectUserName, TargetUserName
  ```

### Step 4.2 – Recovery
- Re-enable accounts after password reset + MFA verification
- Confirm no unauthorized access to sensitive data or resources during the window
- Remove the source IP block if it was a false positive (e.g., misconfigured service account)

---

## 5. Post-Incident Activity

### Step 5.1 – Documentation
Record the following in the Sentinel incident:
- [ ] Attack timeline (first failure → last event)
- [ ] Source IP(s) and geolocation
- [ ] Accounts targeted and any successful compromises
- [ ] Containment actions taken and timestamps
- [ ] Whether MFA was enforced on affected accounts

### Step 5.2 – Lessons Learned
- Was MFA enabled on targeted accounts? If not, flag for remediation.
- Should the detection threshold be tuned (too noisy / too quiet)?
- Were any gaps identified in log coverage?

### Step 5.3 – Recommended Hardening
| Recommendation | Priority |
|---|---|
| Enforce MFA on all accounts | Critical |
| Implement account lockout policy | High |
| Enable Entra ID Identity Protection | High |
| Deploy Conditional Access policies | Medium |
| Consider CAPTCHA on login portals | Medium |

---

## References
- [MITRE ATT&CK T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)
- [NIST SP 800-61 – Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [Microsoft: Investigate alerts in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/investigate-cases)
