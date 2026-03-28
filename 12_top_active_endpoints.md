# Top 5 Most Active Endpoints by Event Volume (Last 24 Hours)

> **Category:** Log Aggregation / Investigation  
> **Platform:** Microsoft Defender for Endpoint | Log Analytics  
> **MITRE ATT&CK:** [TA0007 – Discovery / Network Service Scanning (T1046)](https://attack.mitre.org/techniques/T1046/) | [TA0040 – Impact / Resource Hijacking (T1496)](https://attack.mitre.org/techniques/T1496/)  
> **Severity:** Low  

---

## Description

This query identifies the top 5 devices generating the highest volume of endpoint events in the last 24 hours. High event volume on an endpoint can indicate a misconfigured application, a noisy security tool, malware generating repeated activity, or a system under active attack. This query is useful for daily endpoint health checks and as a starting point for identifying devices that warrant deeper investigation.

---

## Query

```kql
DeviceEvents
| where TimeGenerated > ago(24h)
| summarize EventCount = count() by DeviceName
| top 5 by EventCount
```

---

## How It Works

1. **Table** – `DeviceEvents` captures a broad range of endpoint activity reported by Microsoft Defender for Endpoint sensors, including process, network, file, and registry events.
2. **Filters** – `TimeGenerated > ago(24h)` scopes to the last 24 hours for daily triage.
3. **Aggregation** – `count()` totals all events grouped `by DeviceName`, producing a per-device activity count.
4. **Ranking** – `top 5 by EventCount` returns the 5 most active devices sorted by total event volume.

---

## Use Case / Scenario

> *An endpoint generating an unusually high number of events compared to the rest of the fleet may be misconfigured, infected with malware that is looping activity (e.g., repeated process creation, registry writes), or actively involved in an attack. This query surfaces those outliers quickly, allowing analysts to triage high-noise devices before reviewing them in detail.*

---

## Investigation Steps

When this query returns unexpectedly active devices, an analyst should:

1. Compare the flagged device's event count against the environment baseline — how much higher is it than a typical device?
2. Break down the event types on the flagged device with `| where DeviceName == "flagged-device" | summarize count() by ActionType` to understand what kind of activity is driving the volume.
3. Check if the device belongs to a known high-activity role (e.g., build server, domain controller) that may legitimately generate more events.
4. Review recent process creations and network connections on the device for suspicious patterns.
5. Check the device's vulnerability and patch status in Defender for Endpoint.

---

## False Positive Considerations

- Build servers, CI/CD agents, and domain controllers naturally generate higher event volumes than standard workstations.
- Security scanning tools running on an endpoint will increase event counts significantly.
- Backup agents or DLP tools performing file scanning can produce large numbers of file events.

**Tuning tip:** Exclude known high-volume infrastructure roles with `| where DeviceName !in ("buildserver01", "dc01", "dc02")` or by filtering on a device tag if your environment uses them.

---

## References

- [MITRE ATT&CK – Resource Hijacking (T1496)](https://attack.mitre.org/techniques/T1496/)
- [MITRE ATT&CK – Network Service Scanning (T1046)](https://attack.mitre.org/techniques/T1046/)
- [Microsoft Docs – DeviceEvents Table](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table)

---

*Last Updated: 2025-09-01*
