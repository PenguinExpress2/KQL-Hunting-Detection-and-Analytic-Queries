# Script Interpreter Execution Across Multiple Devices – Living-off-the-Land Detection

> **Category:** Security Detection  
> **Platform:** Microsoft Defender for Endpoint | Log Analytics  
> **MITRE ATT&CK:** [TA0002 – Execution / Command and Scripting Interpreter: PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/) | [TA0008 – Lateral Movement / Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/)  
> **Severity:** High  

---

## Description

This query detects suspicious use of script interpreters — specifically PowerShell, WScript, and CScript — that are being executed across multiple endpoints in a short 4-hour window. It further narrows results to invocations containing known command-line abuse indicators such as encoded commands, download cradles, and web-based execution patterns. Processes appearing on 5 or more distinct devices that match these patterns are surfaced, with total execution count, device count, and user count returned per interpreter.

---

## Query

```kql
DeviceProcessEvents
| where TimeGenerated > ago(4h)
| where ActionType == "ProcessCreated"
| where FileName in ("powershell.exe", "wscript.exe", "cscript.exe")
| where ProcessCommandLine has_any ("-enc", "iex", "downloadstring", "http")
| summarize
    TotalProcessCreationCount = count(),
    DistinctDeviceCount = dcount(DeviceName),
    DistinctUserCount = dcount(InitiatingProcessAccountUpn)
    by FileName
| where DistinctDeviceCount >= 5
| order by DistinctDeviceCount desc
```

---

## How It Works

1. **Table** – `DeviceProcessEvents` logs process creation activity including the full command line used.
2. **Filters** – `TimeGenerated > ago(4h)` provides a 4-hour detection window. `ActionType == "ProcessCreated"` limits to new process spawns. `FileName in (...)` scopes to the three most commonly abused script interpreters. `ProcessCommandLine has_any (...)` further filters to invocations containing known malicious indicators: `-enc` (Base64-encoded PowerShell), `iex` (Invoke-Expression), `downloadstring` (download cradle), and `http` (outbound URL execution).
3. **Aggregation** – Grouped `by FileName`. `count()` totals executions. `dcount(DeviceName)` counts distinct devices where the interpreter was used with suspicious arguments. `dcount(InitiatingProcessAccountUpn)` counts distinct users associated — multiple users triggering the same pattern may indicate a credential-based spread.
4. **Threshold** – `where DistinctDeviceCount >= 5` catches interpreters being used with suspicious patterns across 5 or more devices.
5. **Ordering** – `order by DistinctDeviceCount desc` surfaces the most widely spread interpreter first.

---

## Use Case / Scenario

> *Living-off-the-land (LOtL) attacks abuse built-in Windows scripting tools like PowerShell to avoid dropping new binaries that would trigger AV. An attacker using a remote execution framework or worm-like propagation mechanism will often push a PowerShell one-liner with a download cradle to multiple endpoints at once. The combination of suspicious command-line arguments and broad device spread is a high-confidence indicator of active attacker tooling.*

---

## Investigation Steps

When this query flags an interpreter with broad spread, an analyst should:

1. Review the full `ProcessCommandLine` values for the flagged interpreter on the affected devices — decode any Base64-encoded `-enc` payloads.
2. Identify the parent process (`InitiatingProcessFileName`) — if spawned by `winrm`, `psexec`, or `wmiprvse`, this confirms remote execution.
3. Check whether the command line contains a URL — resolve it and check it against threat intelligence.
4. Review the user accounts associated — are they privileged accounts? Is this coming from a single compromised admin account spreading laterally?
5. Correlate with network events — does the device make outbound connections to external IPs shortly after the script execution?
6. Examine whether additional processes were spawned as children of the flagged interpreter (further payload staging).

---

## False Positive Considerations

- IT administrators running legitimate PowerShell scripts across the fleet via RMM tools or group policy — these often use `-enc` or `iex` for encoding.
- Authorized software deployment or configuration management tools.
- Security scanning tools running PowerShell-based assessment scripts.

**Tuning tip:** Maintain an allowlist of known legitimate encoded commands or script hashes. Add `| where InitiatingProcessAccountUpn !has "admin"` to reduce IT admin activity noise, but be cautious — attackers frequently use admin accounts for lateral movement.

---

## References

- [MITRE ATT&CK – PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK – Windows Command Shell (T1059.003)](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK – Ingress Tool Transfer (T1105)](https://attack.mitre.org/techniques/T1105/)
- [Microsoft Docs – DeviceProcessEvents Table](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table)

---

*Last Updated: 2025-09-05*
