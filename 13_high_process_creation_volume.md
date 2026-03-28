# Top 5 Devices by Process Creation Volume (Last 24 Hours)

> **Category:** Threat Hunting  
> **Platform:** Microsoft Defender for Endpoint | Log Analytics  
> **MITRE ATT&CK:** [TA0002 – Execution / Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/) | [TA0002 – Execution / Native API (T1106)](https://attack.mitre.org/techniques/T1106/)  
> **Severity:** Medium  

---

## Description

This query identifies the top 5 devices generating the highest number of process creation events in the last 24 hours. An unusually high process creation rate can indicate a looping script, malware spawning child processes repeatedly, a lateral movement tool deploying payloads, or a compromised system running automated tasks. This is a lightweight first-pass hunt to surface devices worth deeper investigation.

---

## Query

```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| summarize ProcessCreationEventCount = count() by DeviceName
| top 5 by ProcessCreationEventCount
```

---

## How It Works

1. **Table** – `DeviceProcessEvents` records process creation and termination events on Defender for Endpoint-enrolled devices, including the process name, command line, and parent process.
2. **Filters** – `TimeGenerated > ago(24h)` scopes to the last 24 hours.
3. **Aggregation** – `count()` totals all process creation events grouped `by DeviceName`.
4. **Ranking** – `top 5 by ProcessCreationEventCount` surfaces the 5 devices with the highest process creation activity.

---

## Use Case / Scenario

> *Malware, scripting frameworks, and lateral movement tools often generate significantly more process creation events than normal user activity. A device spawning hundreds or thousands of processes in a short window — especially if those processes are short-lived or use interpreters like cmd.exe or powershell.exe — is a strong indicator that something automated and potentially malicious is running. This query is a fast way to find those outliers.*

---

## Investigation Steps

When this query flags a high-volume device, an analyst should:

1. Drill into the specific device and examine which processes are being created most frequently: `| where DeviceName == "flagged-device" | summarize count() by FileName | sort by count_ desc`.
2. Review the parent-child process relationships — is a single parent process (e.g., `powershell.exe`, `cmd.exe`, `wscript.exe`) spawning large numbers of children?
3. Inspect `ProcessCommandLine` values for encoded commands, download cradles (`IEX`, `-EncodedCommand`, `DownloadString`), or other suspicious patterns.
4. Check the timing of the activity — did it start at a specific time that correlates with a phishing email, a login event, or a scheduled task?
5. Review the device's recent network connections for C2 communication or data staging behavior.

---

## False Positive Considerations

- Build servers, software packaging systems, and CI/CD agents legitimately spawn large numbers of processes as part of their normal operation.
- Antivirus or EDR products performing on-demand scans may generate elevated process creation counts.
- Software update processes or installer scripts running during patch windows.

**Tuning tip:** To focus on suspicious short-lived processes, add `| where FileName in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")` after the time filter to narrow to scripting interpreter activity specifically.

---

## References

- [MITRE ATT&CK – Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/)
- [MITRE ATT&CK – Native API (T1106)](https://attack.mitre.org/techniques/T1106/)
- [Microsoft Docs – DeviceProcessEvents Table](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table)

---

*Last Updated: 2025-09-01*
