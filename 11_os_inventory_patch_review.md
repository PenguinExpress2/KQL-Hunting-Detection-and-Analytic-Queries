# Device OS Inventory – Platform and Version Distribution (Last 7 Days)

> **Category:** Log Aggregation / Investigation  
> **Platform:** Microsoft Defender for Endpoint | Log Analytics  
> **MITRE ATT&CK:** [TA0007 – Discovery / System Information Discovery (T1082)](https://attack.mitre.org/techniques/T1082/)  
> **Severity:** Low  

---

## Description

This query enumerates the operating system platforms and versions seen across all active devices in the environment over the last 7 days. It returns a count of devices per OS platform and version, sorted from highest to lowest. This is primarily used for patch prioritization, OS-specific vulnerability exposure assessment, and baseline reporting — but it also mirrors the reconnaissance technique attackers use to identify unpatched or outdated systems during internal discovery phases.

---

## Query

```kql
DeviceInfo
| where TimeGenerated > ago(7d)
| summarize DeviceCount = count() by OSPlatform, OSVersion
| sort by DeviceCount desc
```

---

## How It Works

1. **Table** – `DeviceInfo` contains hardware and software inventory data for enrolled Defender for Endpoint devices, including OS platform and version.
2. **Filters** – `TimeGenerated > ago(7d)` captures devices that have reported in within the last 7 days, aligning with a typical weekly patch cycle.
3. **Aggregation** – `count()` totals devices grouped by both `OSPlatform` (e.g., Windows, Linux, macOS) and `OSVersion` (e.g., 10.0.19045). This breakdown allows patch teams to see not just how many Windows devices exist, but which specific builds are running.
4. **Ordering** – `sort by DeviceCount desc` surfaces the most common OS/version combinations first, making it easy to prioritize patching for the highest-impact groups.

---

## Use Case / Scenario

> *Security and IT operations teams run this query ahead of monthly patching windows to understand OS distribution across the fleet. OS versions with known critical vulnerabilities (e.g., end-of-life builds, unpatched CVEs) can be identified and prioritized. This also helps assess exposure when a new vulnerability is disclosed — if the vulnerable OS version represents a large percentage of the fleet, the urgency is higher.*

---

## Investigation Steps

When this query is used as part of patch management or incident response:

1. Cross-reference `OSVersion` results against the current Microsoft Patch Tuesday release notes or vendor security advisories.
2. Identify any end-of-life OS versions (e.g., Windows 7, Windows Server 2008) that should no longer exist in the environment.
3. For a specific CVE disclosure, filter the results to the affected OS versions to determine blast radius.
4. Export the device count per version and track changes week-over-week to confirm patching is progressing.
5. Drill into specific OS versions and pivot to `DeviceName` to build a target list for patch deployment.

---

## False Positive Considerations

- Virtual machines or test environments may run intentionally outdated OS versions — these should be documented and excluded from compliance reporting.
- Devices that have not checked in recently may show stale OS version data.

**Tuning tip:** To get unique device counts rather than total event counts, use `summarize DeviceCount = dcount(DeviceId) by OSPlatform, OSVersion` to deduplicate devices that have reported multiple times within the 7-day window.

---

## References

- [MITRE ATT&CK – System Information Discovery (T1082)](https://attack.mitre.org/techniques/T1082/)
- [Microsoft Docs – DeviceInfo Table](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceinfo-table)

---

*Last Updated: 2025-09-01*
