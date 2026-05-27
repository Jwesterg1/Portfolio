# Threat Hunting Queries

Ad-hoc KQL queries for proactive threat hunting in Microsoft Sentinel. Unlike scheduled analytics rules, these are run manually by an analyst looking for signs of compromise that haven't triggered an alert.

Each query includes the hypothesis it's testing, the data source required, and notes on what to look for in the results.

---

## Hunt 1: Living Off the Land — LOLBins Abuse

**Hypothesis:** An attacker is using built-in Windows binaries to execute malicious code and evade detection.

**Data Source:** SecurityEvent (Event ID 4688), Sysmon Event ID 1

```kql
// Common LOLBins abused for execution, download, or defense evasion
let LOLBins = dynamic([
    "certutil.exe",      // Download files, decode base64
    "mshta.exe",         // Execute HTA files / scripts
    "regsvr32.exe",      // Execute DLLs / bypass AppLocker
    "rundll32.exe",      // Execute DLLs
    "wscript.exe",       // Execute VBScript/JScript
    "cscript.exe",       // Execute VBScript/JScript
    "msiexec.exe",       // Install packages from URL
    "installutil.exe",   // Execute .NET code
    "msbuild.exe",       // Execute .NET code inline
    "wmic.exe",          // WMI execution / lateral movement
    "bitsadmin.exe",     // Download files
    "forfiles.exe",      // Command execution
    "pcalua.exe",        // Execute arbitrary processes
    "bash.exe"           // WSL abuse
]);

SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4688
| where Process has_any (LOLBins)
| project
    TimeGenerated,
    Computer,
    Account,
    ParentProcessName,
    Process,
    CommandLine
| order by TimeGenerated desc
```

**Look for:**
- `certutil.exe -urlcache -split -f http://...` (file download)
- `regsvr32.exe /s /n /u /i:http://...` (Squiblydoo technique)
- `mshta.exe http://...` (remote HTA execution)
- Unusual parent processes (e.g. `outlook.exe` spawning `wscript.exe`)

---

## Hunt 2: Lateral Movement via Pass-the-Hash

**Hypothesis:** An attacker is using stolen NTLM hashes to authenticate to other systems without knowing the plaintext password.

**Data Source:** SecurityEvent

```kql
// Pass-the-Hash indicators:
// - LogonType 3 (Network) with NtLmSsp authentication
// - Source IP is internal (lateral movement, not external)
// - Target account is privileged

SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4624
| where LogonType == 3                           // Network logon
| where AuthenticationPackageName == "NTLM"
| where LogonProcessName == "NtLmSsp"
// Filter to internal source IPs only (adjust range to your network)
| where IpAddress matches regex @"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
// Exclude machine accounts
| where not(TargetUserName endswith "$")
| summarize
    LogonCount   = count(),
    TargetHosts  = make_set(Computer),
    SourceIPs    = make_set(IpAddress)
    by TargetUserName, TargetDomainName
| where LogonCount > 3                           // Multiple hosts = lateral movement
| order by LogonCount desc
```

**Look for:**
- Same account authenticating to many hosts in a short window
- Privileged accounts (admin, svc_) using NTLM where Kerberos is expected
- Source host that is a workstation (not a server/DC) authenticating laterally

---

## Hunt 3: Persistence via Scheduled Tasks

**Hypothesis:** An attacker has created a scheduled task to maintain persistence after a reboot or credential change.

**Data Source:** SecurityEvent (Event ID 4698, 4702)

```kql
// Event 4698 = Scheduled task created
// Event 4702 = Scheduled task updated

SecurityEvent
| where TimeGenerated >= ago(7d)
| where EventID in (4698, 4702)
| extend TaskXML = tostring(EventData)
// Extract task name and action from XML
| extend
    TaskName    = extract(@'<TaskName>([^<]+)</TaskName>', 1, TaskXML),
    TaskCommand = extract(@'<Command>([^<]+)</Command>', 1, TaskXML),
    TaskArgs    = extract(@'<Arguments>([^<]+)</Arguments>', 1, TaskXML),
    RunAs       = extract(@'<UserId>([^<]+)</UserId>', 1, TaskXML)
// Flag suspicious commands
| where TaskCommand has_any (
    "powershell", "cmd", "wscript", "cscript",
    "mshta", "rundll32", "regsvr32", "certutil"
)
| project
    TimeGenerated,
    Computer,
    SubjectUserName,
    TaskName,
    TaskCommand,
    TaskArgs,
    RunAs,
    EventID
| order by TimeGenerated desc
```

**Look for:**
- Tasks running from temp directories (`%APPDATA%`, `%TEMP%`, `C:\Users\Public`)
- Tasks running as SYSTEM with encoded PowerShell commands
- Tasks with random or disguised names mimicking legitimate Windows tasks
- Tasks created outside business hours

---

## Hunt 4: Reconnaissance — Active Directory Enumeration

**Hypothesis:** An attacker with a foothold is enumerating Active Directory to map the environment before lateral movement or privilege escalation.

**Data Source:** SecurityEvent

```kql
// Common AD enumeration Event IDs
// 4661 = Handle to object requested (LDAP queries against AD objects)
// 4662 = Operation performed on object
// Look for high volume of directory queries from a single account

SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4661
| where ObjectType in (
    "SAM_USER",
    "SAM_GROUP",
    "SAM_DOMAIN",
    "%{bf967aba-0de6-11d0-a285-00aa003049e2}",   // User class
    "%{bf967a9c-0de6-11d0-a285-00aa003049e2}"    // Group class
)
| summarize
    QueryCount   = count(),
    ObjectsQueried = make_set(ObjectName, 20)
    by SubjectUserName, Computer, bin(TimeGenerated, 5m)
| where QueryCount > 100                         // High volume = likely automated enum
| order by QueryCount desc
```

**Correlate with common enumeration tools:**
```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4688
| where CommandLine has_any (
    "net user /domain",
    "net group /domain",
    "net localgroup administrators",
    "nltest /domain_trusts",
    "whoami /all",
    "dsquery",
    "Get-ADUser",
    "Get-ADGroup",
    "BloodHound",
    "SharpHound"
)
| project TimeGenerated, Computer, Account, CommandLine
```

---

## Hunt 5: Data Exfiltration — Unusual Outbound Volume

**Hypothesis:** An attacker is staging and exfiltrating data via an unusual protocol or destination.

**Data Source:** AzureNetworkAnalytics_CL, CommonSecurityLog (if firewall logs connected)

```kql
// Detect hosts with unusually high outbound data transfer
// Requires network flow logs (NSG Flow Logs or firewall connector)

AzureNetworkAnalytics_CL
| where TimeGenerated >= ago(1h)
| where FlowDirection_s == "O"                   // Outbound
| where FlowStatus_s == "A"                      // Allowed
// Exclude known cloud provider ranges (adjust as needed)
| where not(DestIP_s has_any ("10.", "172.", "192.168."))
| summarize
    TotalBytesSent = sum(OutboundBytes_d),
    ConnectionCount = count(),
    DestinationIPs = make_set(DestIP_s, 10)
    by SrcIP_s, VM_s, bin(TimeGenerated, 10m)
| extend TotalMB = round(TotalBytesSent / 1048576.0, 2)
| where TotalMB > 100                            // Flag >100MB in 10 min window
| order by TotalMB desc
```

**Look for:**
- Large transfers to unfamiliar cloud storage (non-corporate S3, Dropbox, Mega.nz)
- Outbound traffic on unusual ports (DNS tunneling on 53, ICMP exfil)
- Transfers occurring outside business hours
- Single host responsible for disproportionate outbound volume

---

## Hunt 6: Credential Dumping Indicators

**Hypothesis:** An attacker has attempted to dump credentials from LSASS memory or the SAM database.

**Data Source:** SecurityEvent, Sysmon

```kql
// LSASS access attempts (requires Sysmon Event ID 10 - Process Access)
// Event
// | where TimeGenerated >= ago(24h)
// | where Source == "Microsoft-Windows-Sysmon"
// | where EventID == 10                          // ProcessAccess
// | extend EventData = parse_xml(EventData)
// | extend
//     SourceImage = tostring(EventData.DataItem.EventData.Data[5]["#text"]),
//     TargetImage = tostring(EventData.DataItem.EventData.Data[6]["#text"]),
//     GrantedAccess = tostring(EventData.DataItem.EventData.Data[8]["#text"])
// | where TargetImage has "lsass.exe"
// | where not(SourceImage has_any (
//     "MsMpEng.exe",          // Defender
//     "svchost.exe",
//     "csrss.exe",
//     "wininit.exe"
// ))
// | project TimeGenerated, Computer, SourceImage, TargetImage, GrantedAccess

// Volume Shadow Copy deletion (common ransomware/wiper behavior)
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4688
| where CommandLine has_any (
    "vssadmin delete shadows",
    "vssadmin resize shadowstorage",
    "wmic shadowcopy delete",
    "bcdedit /set recoveryenabled no",
    "bcdedit /set bootstatuspolicy ignoreallfailures",
    "wbadmin delete catalog"
)
| project TimeGenerated, Computer, Account, ParentProcessName, CommandLine
| order by TimeGenerated desc
```

---

*These queries are intended as starting points. Tune thresholds and whitelist legitimate activity for your environment before promoting any hunt to a scheduled analytics rule.*
