# Top Applications by Successful Sign-Ins (Last 24 Hours)

> **Category:** Log Aggregation / Investigation  
> **Platform:** Microsoft Sentinel | Azure AD | Log Analytics  
> **MITRE ATT&CK:** [TA0001 – Initial Access / Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)  
> **Severity:** Low  

---

## Description

This query identifies the top 10 applications by number of successful sign-ins in the past 24 hours. It surfaces which apps are most actively used in the tenant and how many unique users are accessing each one. This is useful for daily health checks, baseline reporting, and spotting unusual spikes in app usage that may indicate account compromise or misuse.

---

## Query

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| summarize SignInCount = count(), UniqueUsers = dcount(UserPrincipalName) by AppDisplayName
| top 10 by SignInCount desc
```

---

## How It Works

1. **Table** – `SigninLogs` contains Azure AD authentication events including app name, user, IP, and result.
2. **Filters** – `TimeGenerated > ago(24h)` scopes to the last 24 hours. `ResultType == 0` keeps only successful sign-ins.
3. **Aggregation** – `count()` gives the total successful sign-ins per app. `dcount(UserPrincipalName)` counts distinct users accessing each app. Both are grouped `by AppDisplayName`.
4. **Ranking** – `top 10 by SignInCount desc` returns only the 10 most active apps, sorted highest to lowest.

---

## Use Case / Scenario

> *This query is used for daily SOC health checks and usage baseline reporting. A sudden spike in sign-ins for an app like a file storage or email platform could indicate credential stuffing, account takeover, or an automated tool abusing valid credentials.*

---

## Investigation Steps

When this query returns unexpected results, an analyst should:

1. Compare today's results against historical baselines — is any app unusually high?
2. Drill into the specific app with elevated counts and review the individual `UserPrincipalName` values.
3. Check whether the users accessing the app are expected to do so (role-based review).
4. For suspicious apps, pivot to failed sign-ins for the same app to look for brute-force precursors.
5. Correlate with `IPAddress` to identify sign-ins from unexpected geographies or anonymous proxies.

---

## False Positive Considerations

- Automated service accounts or integrations that generate high sign-in volume legitimately (e.g., monitoring tools, sync agents).
- Scheduled tasks or scripts that authenticate on a recurring basis.
- Spike during business hours or after a company-wide announcement (e.g., new tool rollout).

**Tuning tip:** Exclude known service accounts with `| where UserPrincipalName !in ("svc_account@domain.com", "sync_agent@domain.com")`.

---

## References

- [MITRE ATT&CK – Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
- [Microsoft Docs – SigninLogs Schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)

---

*Last Updated: 2025-08-22*
