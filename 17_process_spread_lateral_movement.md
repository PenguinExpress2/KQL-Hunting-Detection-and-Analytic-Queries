# Process Execution Spread Across Multiple Devices – Lateral Movement / Payload Deployment Detection

> **Category:** Threat Hunting  
> **Platform:** Microsoft Defender for Endpoint | Log Analytics  
> **MITRE ATT&CK:** [TA0008 – Lateral Movement / Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/) | [TA0002 – Execution / Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/)  
> **Severity:** High  

---

## Description

This query identifies process names that have been executed across an unusually high number of distinct devices within the last 6 hours. When a single process — especially a LOLBin or scripting interpreter — suddenly appears on 10 or more different endpoints, it is a strong signal of lateral movement, automated payload deployment, or a malicious scripting framework spreading across the environment. The query returns total execution count, distinct device count, and distinct user count per process name.

---

## Query

```kql
DeviceProcessEvents
| where TimeGenerated > ago(6h)
| where ActionType == "ProcessCreated"
| summarize
    TotalProcessCreationCount = count(),
    DistinctDeviceCount = dcount(DeviceId),
    DistinctUserCount = dcount(InitiatingProcessAccountUpn)
    by InitiatingProcessFileName
| where DistinctDeviceCount >= 10
| order by DistinctDeviceCount desc
```

---

## How It Works

1. **Table** – `DeviceProcessEvents` records process creation events across all Defender for Endpoint-enrolled devices.
2. **Filters** – `TimeGenerated > ago(6h)` provides a 6-hour hunting window — wide enough to catch attacker campaigns that spread over time, but tight enough to stay relevant. `ActionType == "ProcessCreated"` limits to process creation events only.
3. **Aggregation** – Grouped `by InitiatingProcessFileName` (the parent executable that spawned child processes). `count()` gives total executions. `dcount(DeviceId)` counts distinct devices where the process ran. `dcount(InitiatingProcessAccountUpn)` counts distinct user identities associated with the executions — high user spread alongside high device spread may suggest an automated or domain-wide deployment.
4. **Threshold** – `where DistinctDeviceCount >= 10` flags processes appearing on 10 or more devices in the window, which is an anomalous propagation rate for most non-system processes.
5. **Ordering** – `order by DistinctDeviceCount desc` surfaces the most broadly spread processes first.

---

## Use Case / Scenario

> *After gaining initial access, threat actors often use tools like PsExec, WMI, or scripting frameworks to deploy payloads or run commands across multiple endpoints simultaneously. A process that suddenly appears on dozens of devices within hours — especially one that is not a standard system process — indicates mid-stage attacker behavior consistent with lateral movement or malware propagation.*

---

## Investigation Steps

When this query flags a widely spread process, an analyst should:

1. Determine whether the process is a known legitimate binary — check its hash against threat intelligence.
2. Review the `ProcessCommandLine` values on the flagged devices to see what arguments are being passed.
3. Check the parent process (`InitiatingProcessParentFileName`) — is a known lateral movement tool (e.g., `psexec.exe`, `wmiprvse.exe`, `winrm`) spawning it?
4. Look at the timing spread — did all executions happen simultaneously (automated push) or sequentially (manual lateral movement)?
5. Cross-reference with authentication logs — look for remote logins (`Type 3`) on the affected devices just before the process appeared.
6. If the process is confirmed malicious, isolate affected devices and begin forensic collection.

---

## False Positive Considerations

- Enterprise software deployments (e.g., group policy scripts, SCCM packages) can trigger legitimate broad process spread during patch windows or software rollouts.
- Antivirus or EDR update processes running on all endpoints simultaneously.
- Domain-wide login scripts that execute on user sign-in across the fleet.

**Tuning tip:** Add a baseline exclusion for known enterprise deployment processes: `| where InitiatingProcessFileName !in ("msiexec.exe", "sccm_agent.exe", "MsMpEng.exe")`. For more precision, pair with command line filtering to distinguish legitimate from malicious executions of the same binary.

---

## References

- [MITRE ATT&CK – Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
- [MITRE ATT&CK – Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/)
- [MITRE ATT&CK – Lateral Tool Transfer (T1570)](https://attack.mitre.org/techniques/T1570/)
- [Microsoft Docs – DeviceProcessEvents Table](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table)

---

*Last Updated: 2025-09-05*
