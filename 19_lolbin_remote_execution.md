# Remote Execution via LOLBins Across Multiple Devices – Post-Compromise Detection

> **Category:** Security Detection  
> **Platform:** Microsoft Defender for Endpoint | Log Analytics  
> **MITRE ATT&CK:** [TA0008 – Lateral Movement / Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/) | [TA0002 – Execution / System Binary Proxy Execution (T1218)](https://attack.mitre.org/techniques/T1218/)  
> **Severity:** Critical  

---

## Description

This query detects the execution of native Windows remote-capable utilities — commonly known as Living-off-the-Land Binaries (LOLBins) — across multiple endpoints within a 6-hour window. Tools like `psexec.exe`, `wmic.exe`, `schtasks.exe`, and `winrm.vbs` are frequently abused by attackers after initial access to move laterally, execute commands remotely, and deploy payloads without dropping new binaries. The query surfaces binaries seen on 5 or more distinct devices, includes the actual device and user lists for immediate triage, and excludes admin accounts to reduce noise.

---

## Query

```kql
DeviceProcessEvents
| where TimeGenerated > ago(6h)
| where ActionType == "ProcessCreated"
| where FileName in ("psexec.exe", "wmic.exe", "schtasks.exe", "winrm.vbs")
| where InitiatingProcessAccountUpn !has "admin"
| summarize
    TotalProcessCreationCount = count(),
    DistinctDeviceCount = dcount(DeviceName),
    Devices = make_set(DeviceName),
    DistinctUserCount = dcount(InitiatingProcessAccountUpn),
    Users = make_set(InitiatingProcessAccountUpn)
    by FileName
| where DistinctDeviceCount >= 5
| order by DistinctDeviceCount desc
```

---

## How It Works

1. **Table** – `DeviceProcessEvents` logs all process creation activity on Defender for Endpoint-enrolled devices, including the filename, command line, and account that initiated the process.
2. **Filters** – `TimeGenerated > ago(6h)` scopes to a 6-hour detection window appropriate for catching active lateral movement campaigns. `ActionType == "ProcessCreated"` limits to new process spawns. `FileName in (...)` targets four high-risk remote execution utilities that are rarely needed by standard end users. `InitiatingProcessAccountUpn !has "admin"` excludes accounts with "admin" in the name to reduce IT administration noise — adjust this based on your naming conventions.
3. **Aggregation** – Grouped `by FileName`. `count()` gives total executions. `dcount(DeviceName)` and `make_set(DeviceName)` give both the count and the actual list of affected devices — the set is critical for rapid triage, letting analysts immediately see which machines are involved. Similarly, `dcount(InitiatingProcessAccountUpn)` and `make_set(InitiatingProcessAccountUpn)` give both the spread and the specific accounts involved.
4. **Threshold** – `where DistinctDeviceCount >= 5` catches LOLBins appearing on 5 or more devices — well above normal single-user administrative use.
5. **Ordering** – `order by DistinctDeviceCount desc` surfaces the most broadly spread binary first.

---

## Use Case / Scenario

> *After gaining initial access and escalating privileges, attackers commonly use built-in Windows remote execution tools to move laterally across the network without triggering AV alerts from dropped malware. A tool like `psexec.exe` or `wmic.exe` appearing on 5, 10, or 20 endpoints in a few hours — especially under non-admin user accounts or unusual accounts — is a strong indicator of an active post-compromise lateral movement campaign.*

---

## Investigation Steps

When this query flags a LOLBin with broad device spread, an analyst should:

1. Review the `Devices` set — are the affected machines in the same subnet, OU, or business unit? A geographic or logical cluster of affected devices suggests targeted lateral movement.
2. Review the `Users` set — are these legitimate IT accounts, or do they look like compromised standard user accounts being used to move laterally after privilege escalation?
3. Check the full `ProcessCommandLine` for the flagged binary on each device to understand what remote commands are being run.
4. Review the parent process (`InitiatingProcessFileName`) on each device — legitimate admin use typically comes from `explorer.exe` or an RMM tool; attacker use often comes from `cmd.exe`, `powershell.exe`, or a remote shell.
5. Correlate with authentication logs — look for remote logon events (`Type 3`) on affected devices just before the LOLBin execution.
6. If malicious activity is confirmed, isolate affected devices, revoke sessions for the involved accounts, and begin forensic collection.

---

## False Positive Considerations

- IT administrators legitimately use `psexec.exe`, `wmic.exe`, and `schtasks.exe` for remote management — the admin account exclusion filter helps, but may need to be adjusted if your org uses non-standard admin naming.
- Patch management and configuration management tools (e.g., SCCM, Ansible) may invoke `schtasks.exe` or `wmic.exe` as part of their normal operation.
- Penetration testing or red team exercises.

**Tuning tip:** Build an allowlist of known IT management servers and exclude them by device name: `| where DeviceName !in ("sccm-server01", "rmmtool01")`. Also consider adding `make_set(ProcessCommandLine)` to the summarize to capture the actual commands run for faster triage.

---

## References

- [MITRE ATT&CK – Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)
- [MITRE ATT&CK – Windows Management Instrumentation (T1047)](https://attack.mitre.org/techniques/T1047/)
- [MITRE ATT&CK – Scheduled Task/Job (T1053)](https://attack.mitre.org/techniques/T1053/)
- [MITRE ATT&CK – System Binary Proxy Execution (T1218)](https://attack.mitre.org/techniques/T1218/)
- [LOLBAS Project – Living Off The Land Binaries](https://lolbas-project.github.io/)
- [Microsoft Docs – DeviceProcessEvents Table](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table)

---

*Last Updated: 2025-09-05*
