# High File Write Volume – Data Staging Detection Hunt

> **Category:** Threat Hunting  
> **Platform:** Microsoft Defender for Endpoint | Log Analytics  
> **MITRE ATT&CK:** [TA0009 – Collection / Data Staged (T1074)](https://attack.mitre.org/techniques/T1074/) | [TA0009 – Collection / Data from Local System (T1005)](https://attack.mitre.org/techniques/T1005/)  
> **Severity:** High  

---

## Description

This query hunts for devices that wrote or modified an unusually large number of files within any 1-hour window over the last 24 hours. Mass file creation or modification is a common precursor to data exfiltration — attackers often collect and stage files (e.g., compressing documents, copying data to a staging directory) before transferring them externally. The query returns total write event count, distinct file count, and distinct file extension count per device per hour, surfacing only hours with 200 or more write events.

---

## Query

```kql
DeviceFileEvents
| where TimeGenerated > ago(24h)
| where ActionType in ("FileCreated", "FileModified")
| extend FileExtension = tostring(split(FileName, ".", -1))
| summarize
    TotalFileWriteCount = count(),
    DistinctFileCount = dcount(FileName),
    DistinctFileExtensionCount = dcount(FileExtension)
    by bin(TimeGenerated, 1h), DeviceName
| where TotalFileWriteCount >= 200
| order by TotalFileWriteCount desc
```

---

## How It Works

1. **Table** – `DeviceFileEvents` logs file system activity on Defender for Endpoint-enrolled devices, including file creation, modification, deletion, and rename events.
2. **Filters** – `TimeGenerated > ago(24h)` looks at the full past day. `ActionType in ("FileCreated", "FileModified")` focuses on write operations — read-only activity is not relevant to staging detection.
3. **Extension extraction** – `extend FileExtension = tostring(split(FileName, ".", -1))` splits the filename on `.` and extracts the last element as the file extension, then casts it to a string for `dcount()` to work on it.
4. **Aggregation** – Events are binned into 1-hour windows with `bin(TimeGenerated, 1h)` and grouped by device. This means each result row represents one device in one specific hour. `count()` gives the total write events. `dcount(FileName)` counts distinct files written. `dcount(FileExtension)` counts the variety of file types involved.
5. **Threshold** – `where TotalFileWriteCount >= 200` filters to hours with anomalously high write activity. Adjust based on your environment baseline.
6. **Ordering** – `order by TotalFileWriteCount desc` surfaces the busiest device+hour combinations first.

---

## Use Case / Scenario

> *Before exfiltrating data, attackers commonly stage it: copying files from multiple locations into a single directory, archiving documents, or creating bulk copies for transfer. A device writing 200+ files in a single hour — especially across many different file extensions — is a strong indicator of automated collection or staging activity. Defenders can use this query across historical logs to identify when staging may have begun and build a timeline for incident response.*

---

## Investigation Steps

When this query flags a device and time window, an analyst should:

1. Identify the specific files written — pivot to `| where DeviceName == "flagged-device" and TimeGenerated between (start .. end) | where ActionType in ("FileCreated","FileModified") | project FileName, FolderPath, InitiatingProcessFileName`.
2. Look for archive file extensions in `DistinctFileExtensionCount` — a high count of `.zip`, `.rar`, `.7z`, or `.tar` files is a strong indicator of staging.
3. Check the `InitiatingProcessFileName` responsible for the writes — is it a known application or something unexpected?
4. Correlate the time window with outbound network activity to see if the staging was followed by exfiltration (Exercise 14 query can be useful here).
5. Review whether the staging destination path is unusual (e.g., temp directories, removable media mount points, network shares).

---

## False Positive Considerations

- Software installers or update agents that write many files during installation or patching.
- Backup or sync agents (OneDrive, SharePoint sync) that perform bulk file operations during initial sync.
- Developers or data scientists running build pipelines or data processing scripts.

**Tuning tip:** Exclude known sync processes with `| where InitiatingProcessFileName !in ("OneDrive.exe", "MsMpEng.exe", "msiexec.exe")`. Raise the threshold for environments with frequent bulk file operations.

---

## References

- [MITRE ATT&CK – Data Staged (T1074)](https://attack.mitre.org/techniques/T1074/)
- [MITRE ATT&CK – Data from Local System (T1005)](https://attack.mitre.org/techniques/T1005/)
- [MITRE ATT&CK – Archive Collected Data (T1560)](https://attack.mitre.org/techniques/T1560/)
- [Microsoft Docs – DeviceFileEvents Table](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicefileevents-table)

---

*Last Updated: 2025-09-01*
