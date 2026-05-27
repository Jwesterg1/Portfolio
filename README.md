# Watchlists

Sentinel watchlists allow you to correlate log data against reference lists — in this case, known malicious indicators (IOCs) sourced from threat intelligence feeds.

## ThreatIntelIndicators Watchlist

The file `ThreatIntelIndicators-sample.csv` is a template watchlist populated with sample IOCs for demonstration purposes. **Do not use these IPs/domains/hashes in production without verifying them against current threat intel feeds.**

### Schema

| Column | Description | Example Values |
|---|---|---|
| `IndicatorType` | Type of IOC | `IP`, `Domain`, `FileHash`, `URL` |
| `IndicatorValue` | The actual indicator | `185.220.101.45` |
| `ThreatType` | Category of threat | `C2`, `Malware`, `Phishing`, `Scanner` |
| `Confidence` | Reliability of the indicator | `High`, `Medium`, `Low` |
| `Source` | Where the indicator came from | `abuse.ch`, `AlienVault OTX`, `Internal` |
| `Description` | Human-readable context | Free text |
| `ExpirationDate` | When to retire the IOC | `YYYY-MM-DD` |

---

## How to Load into Microsoft Sentinel

1. In Sentinel, go to **Configuration → Watchlists**
2. Click **+ New**
3. Set:
   - **Name:** `ThreatIntelIndicators`
   - **Alias:** `ThreatIntelIndicators` (must match the name used in KQL)
   - **Source type:** Local file
4. Upload `ThreatIntelIndicators-sample.csv`
5. Set **SearchKey** to `IndicatorValue`
6. Click **Review + Create**

Once loaded, reference it in KQL with:
```kql
_GetWatchlist('ThreatIntelIndicators')
```

---

## Recommended Free Threat Intel Sources

| Source | Type | URL |
|---|---|---|
| abuse.ch Feodo Tracker | C2 IPs | https://feodotracker.abuse.ch/downloads/ipblocklist.txt |
| abuse.ch MalwareBazaar | File Hashes | https://bazaar.abuse.ch/export/ |
| AlienVault OTX | Multi-type | https://otx.alienvault.com/ |
| CISA KEV | Vulnerability IOCs | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| Emerging Threats | Network IOCs | https://rules.emergingthreats.net/ |
| URLhaus | Malicious URLs | https://urlhaus.abuse.ch/ |

---

## Keeping the Watchlist Fresh

For a production environment, automate watchlist updates using a **Logic App** that:
1. Pulls the latest feed from your chosen source (e.g. abuse.ch CSV)
2. Parses and formats to the watchlist schema
3. Calls the Sentinel API to update the watchlist

This is a good next project milestone to add to this repo.
