# User Sign-In Behavior Profile – Top App and Busiest Day (Last 7 Days)

> **Category:** Log Aggregation / Threat Hunting  
> **Platform:** Microsoft Sentinel | Azure AD | Log Analytics  
> **MITRE ATT&CK:** [TA0009 – Collection / Data from Information Repositories (T1213)](https://attack.mitre.org/techniques/T1213/) | [TA0001 – Initial Access / Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)  
> **Severity:** Low  

---

## Description

This query builds a behavioral profile for the top 10 most active users over the last 7 days. For each user it returns the total number of successful sign-ins, the number of distinct applications accessed, the single most-accessed application, and the day with the highest sign-in volume. This profile is useful for establishing baselines, detecting anomalous usage patterns, and identifying accounts that may have been compromised and are accessing an unusually broad set of applications.

---

## Query

```kql
// Step 1: Per-user stats
let UserStats =
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| summarize TotalSignIns = count(),
            NumAppsAccessed = dcount(AppDisplayName)
  by UserPrincipalName;

// Step 2: Per-user + app — find most accessed app
let TopApps =
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| summarize AppSignins = count() by UserPrincipalName, AppDisplayName
| summarize arg_max(AppSignins, AppDisplayName) by UserPrincipalName;

// Step 3: Per-user + day — find busiest day
let TopDays =
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| summarize DailySignins = count() by UserPrincipalName, Day = bin(TimeGenerated, 1d)
| summarize arg_max(DailySignins, Day) by UserPrincipalName;

// Step 4: Combine all results
UserStats
| join kind=inner (TopApps) on UserPrincipalName
| join kind=inner (TopDays) on UserPrincipalName
| top 10 by TotalSignIns desc
| project UserPrincipalName,
          TotalSignIns,
          NumAppsAccessed,
          TopAppAccessed = AppDisplayName,
          BusiestDay = Day
```

---

## How It Works

1. **Table** – `SigninLogs` is queried three times in separate `let` statements to compute different aggregations cleanly without conflating grouping keys.
2. **UserStats** – Computes total successful sign-ins and distinct app count per user over 7 days.
3. **TopApps** – First summarizes sign-in count per user+app pair, then uses `arg_max(AppSignins, AppDisplayName)` to extract the single app with the highest count per user.
4. **TopDays** – Bins sign-ins to 1-day buckets with `bin(TimeGenerated, 1d)`, counts per user+day, then uses `arg_max(DailySignins, Day)` to extract the busiest day per user.
5. **Join & Project** – All three tables are joined on `UserPrincipalName`, trimmed to the top 10 by total sign-ins, and projected to clean column names.

---

## Use Case / Scenario

> *A compromised account often shows a sudden increase in applications accessed or an unusual spike on a specific day (e.g., a Sunday or holiday). This profile query helps analysts identify accounts with abnormal breadth of access or unusual activity days that deviate from the established user baseline — both potential indicators of account takeover.*

---

## Investigation Steps

When this query returns unexpected results, an analyst should:

1. Compare `NumAppsAccessed` against the user's role — does a finance employee need to access 20+ apps?
2. Review `BusiestDay` — sign-in spikes on weekends, holidays, or outside normal business hours warrant closer review.
3. For users with unusually high `TotalSignIns`, check if a scripted process or token-abuse tool is driving the volume.
4. Pivot to the user's full sign-in history and look for new IPs, new devices, or new application access patterns.
5. Cross-reference with HR data — is the user still an active employee?

---

## False Positive Considerations

- Power users, IT admins, and developers legitimately access many applications and may have high sign-in volumes.
- Automated service processes or testing accounts may show large counts across many apps.

**Tuning tip:** Filter out known service accounts with `| where UserPrincipalName !startswith "svc_"` or restrict to a specific user group using `| where UserPrincipalName endswith "@yourdomain.com"`.

---

## References

- [MITRE ATT&CK – Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK – Data from Information Repositories (T1213)](https://attack.mitre.org/techniques/T1213/)
- [Microsoft Docs – SigninLogs Schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [Microsoft Docs – arg_max() Aggregation](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/arg-max-aggregation-function)

---

*Last Updated: 2025-09-05*
