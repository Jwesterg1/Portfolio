# Incident Response Runbook: Account Compromise

**Runbook ID:** IR-002  
**Version:** 1.0  
**MITRE ATT&CK Tactic:** Initial Access, Persistence  
**MITRE Technique:** T1078 – Valid Accounts, T1098 – Account Manipulation  
**Severity:** High  
**Triggering Rules:** `impossible-travel.kql`, `new-admin-after-hours.kql`

---

## 1. Preparation

### Prerequisites
- Access to Microsoft Sentinel incident queue
- Access to Entra ID (Azure AD) admin portal
- Ability to query `SigninLogs`, `AuditLogs`, `SecurityEvent`
- Contact method for affected user (email, Slack, phone)
- Escalation path to IAM/IT team for account actions

### Indicators of Compromise (IOCs) — Account Compromise
- Login from unusual geography or impossible travel distance
- Login at unusual hours with no prior pattern
- New admin account or role assignment outside business hours
- MFA bypass or authentication from unregistered device
- Mass download or email forwarding rule creation post-login

---

## 2. Detection & Analysis

### Step 2.1 – Confirm the Incident

```kql
// Review all recent sign-in activity for the flagged user
SigninLogs
| where TimeGenerated >= ago(24h)
| where UserPrincipalName == "<FLAGGED_UPN>"
| project
    TimeGenerated,
    IPAddress,
    Location,
    AppDisplayName,
    ClientAppUsed,
    DeviceDetail,
    ResultType,
    ResultDescription,
    ConditionalAccessStatus
| order by TimeGenerated desc
```

**Questions to answer:**
- Did the user confirm they were traveling or using a VPN?
- Does the login device match a known registered device?
- Was MFA satisfied, bypassed, or not required?

---

### Step 2.2 – Establish a Timeline

```kql
// Build a full activity timeline for the user across log sources
let SuspectUser = "<FLAGGED_UPN>";
let TimeWindow = 48h;

union
(
    SigninLogs
    | where TimeGenerated >= ago(TimeWindow)
    | where UserPrincipalName == SuspectUser
    | extend Activity = strcat("Sign-in: ", AppDisplayName, " (", tostring(ResultType), ")")
    | project TimeGenerated, Activity, IPAddress, Location
),
(
    AuditLogs
    | where TimeGenerated >= ago(TimeWindow)
    | where InitiatedBy has SuspectUser
    | extend Activity = strcat("Audit: ", OperationName)
    | project TimeGenerated, Activity, IPAddress = "", Location = ""
),
(
    SecurityEvent
    | where TimeGenerated >= ago(TimeWindow)
    | where TargetUserName == tostring(split(SuspectUser, "@")[0])
    | extend Activity = strcat("SecEvent: ", Activity)
    | project TimeGenerated, Activity, IPAddress = IpAddress, Location = ""
)
| order by TimeGenerated asc
```

---

### Step 2.3 – Check for Post-Compromise Activity

```kql
// Look for suspicious admin actions taken by the account after the anomalous login
AuditLogs
| where TimeGenerated >= ago(24h)
| where InitiatedBy has "<FLAGGED_UPN>"
| where OperationName in (
    "Add member to role",
    "Reset user password",
    "Delete user",
    "Update user",
    "Add member to group",
    "Set domain authentication"
)
| project TimeGenerated, OperationName, TargetResources, Result
```

```kql
// Check for new inbox rules (potential email forwarding exfiltration)
// Requires OfficeActivity connector
OfficeActivity
| where TimeGenerated >= ago(24h)
| where UserId == "<FLAGGED_UPN>"
| where Operation in ("New-InboxRule", "Set-InboxRule")
| project TimeGenerated, Operation, Parameters
```

---

### Step 2.4 – Contact the User (Out-of-Band)
Contact the user via a **secondary channel** (phone or in-person — not email, as it may be compromised):
- Confirm whether they initiated the suspicious login
- Ask if they have received any phishing emails or unusual prompts recently
- Do NOT send password reset links via the potentially compromised email account

---

## 3. Containment

### Step 3.1 – Immediate Account Containment

**If user confirms they did NOT initiate the login:**

1. **Revoke all active sessions:**
   - Entra ID Portal → Users → [User] → Revoke Sessions
   - PowerShell: `Revoke-AzureADUserAllRefreshToken -ObjectId <ObjectId>`

2. **Reset the password** (force change at next login)

3. **Temporarily disable the account** if scope is unclear

4. **Review and remove** any suspicious inbox rules, delegated mailbox access, or OAuth app consents

---

### Step 3.2 – Privileged Account Containment (if admin account involved)

```kql
// What did the compromised admin account do?
AuditLogs
| where TimeGenerated >= ago(48h)
| where InitiatedBy has "<FLAGGED_UPN>"
| project TimeGenerated, OperationName, TargetResources, Result
| order by TimeGenerated desc
```

- Remove any role assignments added during the compromise window
- Check for newly created accounts or service principals:
  ```kql
  AuditLogs
  | where TimeGenerated >= ago(24h)
  | where OperationName in ("Add user", "Add service principal")
  | project TimeGenerated, OperationName, TargetResources, InitiatedBy
  ```

---

## 4. Eradication & Recovery

### Step 4.1 – Eradication Checklist
- [ ] Suspicious inbox rules deleted
- [ ] OAuth app consents reviewed and revoked if unauthorized
- [ ] Any newly created accounts/service principals removed
- [ ] Role assignments reviewed — remove unauthorized admin roles
- [ ] MFA re-registered on a known-good device

### Step 4.2 – Recovery
- Re-enable account after password reset and MFA re-registration
- Confirm user can authenticate normally
- Monitor the account closely for 72 hours post-recovery

```kql
// Post-recovery monitoring query — run after re-enabling account
SigninLogs
| where TimeGenerated >= ago(72h)
| where UserPrincipalName == "<FLAGGED_UPN>"
| where ResultType != "0"
| project TimeGenerated, IPAddress, Location, ResultDescription
```

---

## 5. Post-Incident Activity

### Step 5.1 – Documentation
Record in Sentinel incident:
- [ ] How the account was compromised (phishing, credential stuffing, etc.)
- [ ] Anomalous login details (time, location, IP, device)
- [ ] All post-compromise actions taken by the attacker
- [ ] Containment and recovery actions with timestamps
- [ ] Whether data was accessed or exfiltrated

### Step 5.2 – Lessons Learned
- Was MFA enforced? If bypassed, how?
- Were Conditional Access policies sufficient?
- How long between the anomalous login and detection?

### Step 5.3 – Recommended Hardening

| Recommendation | Priority |
|---|---|
| Enforce phishing-resistant MFA (FIDO2 / Certificate-based) | Critical |
| Enable Entra ID Identity Protection risk-based Conditional Access | High |
| Restrict legacy authentication protocols | High |
| Enable Defender for Office 365 anti-phishing policies | High |
| Regular access reviews for privileged roles | Medium |
| User security awareness training | Medium |

---

## References
- [MITRE ATT&CK T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK T1098 – Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [Microsoft: Respond to threats with Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/respond-threats-during-investigation)
- [NIST SP 800-61 – Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
