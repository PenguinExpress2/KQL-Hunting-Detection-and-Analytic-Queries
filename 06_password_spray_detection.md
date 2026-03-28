# Single IP Targeting Multiple Accounts – Password Spray Detection

> **Category:** Security Detection  
> **Platform:** Microsoft Sentinel | Azure AD | Log Analytics  
> **MITRE ATT&CK:** [TA0006 – Credential Access / Password Spraying (T1110.003)](https://attack.mitre.org/techniques/T1110/003/)  
> **Severity:** High  

---

## Description

This query detects password spraying behavior by identifying single IP addresses that have attempted sign-ins against more than 5 distinct user accounts within the last hour — regardless of whether those attempts succeeded or failed. Password spraying avoids account lockouts by trying one or a few passwords across many accounts, making the per-user failure count low but the per-IP user count high. This query surfaces that pattern directly.

---

## Query

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| summarize
    UniqueUserCount = dcount(UserPrincipalName),
    TotalSigninAttempts = count(),
    TargetApps = make_set(AppDisplayName),
    TargetUsers = make_set(UserPrincipalName)
    by IPAddress
| where UniqueUserCount > 5
| order by UniqueUserCount desc
```

---

## How It Works

1. **Table** – `SigninLogs` captures all Azure AD authentication events including source IP, user identity, and application.
2. **Filters** – `TimeGenerated > ago(1h)` focuses on the last hour for near-real-time spray detection. No result type filter is applied because password spraying activity includes both failures and any successful attempts.
3. **Aggregation** – Grouped `by IPAddress`. `dcount(UserPrincipalName)` counts distinct accounts targeted from each IP. `count()` gives the total number of sign-in attempts from that IP. `make_set(AppDisplayName)` and `make_set(UserPrincipalName)` capture the exact apps and accounts targeted for analyst triage.
4. **Threshold** – `where UniqueUserCount > 5` filters to IPs that targeted more than 5 distinct accounts — a strong indicator of spraying rather than a single user with multiple failures.
5. **Ordering** – `order by UniqueUserCount desc` surfaces the broadest spray attempts first.

---

## Use Case / Scenario

> *Password spraying is a low-and-slow credential attack where an adversary tries a single common password (e.g., "Winter2024!") across a large number of accounts to avoid per-user lockout policies. Unlike brute force, a single targeted account may only show one or two failures — making per-user detection miss it entirely. This query catches it by looking at the breadth of accounts targeted from a single source IP.*

---

## Investigation Steps

When this query returns results, an analyst should:

1. Check the source IP against threat intelligence — is it a known attacker IP, Tor exit node, or commercial VPN?
2. Review `TargetUsers` to determine if any targeted accounts are privileged (admins, service accounts, executives).
3. Check `TargetApps` — sprays targeting email or VPN portals are especially high priority.
4. Search for successful sign-ins (`ResultType == 0`) from the same IP in the same window.
5. If a successful sign-in is found, treat the account as compromised and initiate response procedures.
6. Consider blocking the source IP at the Conditional Access or firewall level.

---

## False Positive Considerations

- Shared NAT or proxy IPs where many users appear to originate from the same address (common in offices or universities).
- Vulnerability scanners or authorized pen testers.
- Load balancers or authentication proxies that forward requests from many users under a single IP.

**Tuning tip:** Exclude known internal NAT ranges or proxy IPs with `| where IPAddress !in ("203.0.113.10", "198.51.100.5")`. For high-user-count shared IPs, raise the `UniqueUserCount` threshold or add a `TotalSigninAttempts` cross-check.

---

## References

- [MITRE ATT&CK – Password Spraying (T1110.003)](https://attack.mitre.org/techniques/T1110/003/)
- [MITRE ATT&CK – Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)
- [Microsoft Docs – SigninLogs Schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)

---

*Last Updated: 2025-09-03*
