# Devices Contacting High Number of Distinct Remote IPs – C2 / Scanning Detection

> **Category:** Security Detection  
> **Platform:** Microsoft Defender for Endpoint | Log Analytics  
> **MITRE ATT&CK:** [TA0011 – Command and Control / Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/) | [TA0043 – Reconnaissance / Active Scanning (T1595)](https://attack.mitre.org/techniques/T1595/)  
> **Severity:** High  

---

## Description

This query detects devices making outbound connections to an unusually high number of distinct remote IP addresses within a 2-hour window — a pattern consistent with C2 beaconing to rotating infrastructure, internal or external network scanning, or proxy/tunneling behavior. Browser processes are excluded to reduce noise from normal web browsing. Only devices with 25 or more distinct remote IPs are returned, sorted by distinct IP count.

---

## Query

```kql
DeviceNetworkEvents
| where TimeGenerated > ago(2h)
| where Direction == "Outbound"
| where InitiatingProcessFileName !in ("msedge.exe", "chrome.exe", "firefox.exe")
| summarize
    TotalOutboundConnectionsCount = count(),
    DistinctRemoteIPCount = dcount(RemoteIP),
    DistinctCountriesCount = dcount(RemoteCountry)
    by DeviceName, InitiatingProcessFileName
| where DistinctRemoteIPCount >= 25
| order by DistinctRemoteIPCount desc
```

---

## How It Works

1. **Table** – `DeviceNetworkEvents` captures network connection events from Defender for Endpoint sensors including remote IP, direction, and the process that opened the connection.
2. **Filters** – `TimeGenerated > ago(2h)` uses a 2-hour window to catch persistent scanning or beaconing. `Direction == "Outbound"` focuses on connections leaving the device. `InitiatingProcessFileName !in (...)` excludes common browsers, which legitimately contact many different IPs during normal browsing and would otherwise flood the results.
3. **Aggregation** – Grouped by `DeviceName` and `InitiatingProcessFileName`. `count()` gives total outbound connections. `dcount(RemoteIP)` counts distinct IP destinations. `dcount(RemoteCountry)` counts distinct countries contacted — a non-browser process contacting IPs across many countries is a strong anomaly signal.
4. **Threshold** – `where DistinctRemoteIPCount >= 25` filters to devices with a broad remote IP footprint well above normal single-application behavior.
5. **Ordering** – `order by DistinctRemoteIPCount desc` surfaces the most broadly connecting devices first.

---

## Use Case / Scenario

> *Threat actors frequently use fast-flux DNS, domain generation algorithms (DGA), or pre-provisioned IP lists to have compromised hosts beacon out to a rotating set of C2 addresses. Scanning tools and worms also generate high numbers of distinct destination IPs in a short window. A non-browser process contacting 25+ distinct IPs in 2 hours is a significant anomaly that warrants immediate investigation.*

---

## Investigation Steps

When this query flags a device, an analyst should:

1. Identify `InitiatingProcessFileName` — a system binary like `svchost.exe` or `lsass.exe` making many outbound connections is highly suspicious.
2. Pivot to the remote IPs and check them against threat intelligence — are they known C2 infrastructure, Tor exit nodes, or bulletproof hosting?
3. Check `DistinctCountriesCount` — a non-browser process contacting IPs across many countries in 2 hours is unlikely to be legitimate.
4. Review the process's parent chain: `| where DeviceName == "flagged-device" and InitiatingProcessFileName == "flagged.exe"` and look at `InitiatingProcessParentFileName` for unusual spawn relationships.
5. Correlate with file write activity (Exercise 15) and authentication events to build a broader attack timeline.
6. If C2 behavior is confirmed, isolate the device and begin incident response procedures.

---

## False Positive Considerations

- Software update services may contact many CDN nodes simultaneously (e.g., Windows Update, Steam, antivirus definition updates) — these are typically short bursts, not sustained over 2 hours.
- Network monitoring or asset discovery tools run by IT operations.
- Peer-to-peer applications that open connections to many peers.

**Tuning tip:** Add additional browser and update process exclusions as needed: `| where InitiatingProcessFileName !in ("MsMpEng.exe", "SteamService.exe", "wuauclt.exe")`. For DGA detection specifically, combining this with a DNS query volume query significantly improves confidence.

---

## References

- [MITRE ATT&CK – Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [MITRE ATT&CK – Active Scanning (T1595)](https://attack.mitre.org/techniques/T1595/)
- [MITRE ATT&CK – Dynamic Resolution (T1568)](https://attack.mitre.org/techniques/T1568/)
- [Microsoft Docs – DeviceNetworkEvents Table](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicenetworkevents-table)

---

*Last Updated: 2025-09-03*
