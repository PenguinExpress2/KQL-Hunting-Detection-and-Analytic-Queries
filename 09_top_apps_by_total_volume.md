# Top 5 Applications by Sign-In Volume (Last 24 Hours)

> **Category:** Log Aggregation / Investigation  
> **Platform:** Microsoft Sentinel | Azure AD | Log Analytics  
> **MITRE ATT&CK:** [TA0001 – Initial Access / Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)  
> **Severity:** Low  

---

## Description

This query identifies the top 5 applications by total sign-in activity — both successful and failed — over the last 24 hours. It is a lightweight visibility query used to understand which apps are generating the most authentication traffic in the tenant on any given day. Unexpected entries in this list (e.g., an app not commonly used appearing at the top) can be an early indicator of targeted activity or misconfigured automation.

---

## Query

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| summarize SignInCount = count() by AppDisplayName
| top 5 by SignInCount desc
```

---

## How It Works

1. **Table** – `SigninLogs` captures all Azure AD authentication events including the application name for each attempt.
2. **Filters** – `TimeGenerated > ago(24h)` scopes to the last 24 hours. No result type filter is applied — both successes and failures are included to capture full app traffic volume.
3. **Aggregation** – `count()` totals all sign-in attempts (regardless of outcome) grouped `by AppDisplayName`.
4. **Ranking** – `top 5 by SignInCount desc` returns the 5 most active applications sorted by total volume.

---

## Use Case / Scenario

> *This query serves as a quick daily pulse check on application authentication traffic. An unexpected application appearing in the top 5 — especially one that is not typically used by most employees — may indicate a credential stuffing campaign, an attacker probing a lesser-known app, or an automated tool hitting an API endpoint at scale.*

---

## Investigation Steps

When this query returns unexpected applications, an analyst should:

1. Verify whether the flagged app is expected to have that level of authentication traffic.
2. If the app is unusual, break down its traffic by `UserPrincipalName` and `IPAddress` to identify who is driving the volume.
3. Check the success-to-failure ratio for the flagged app using `countif(ResultType == 0)` and `countif(ResultType != 0)`.
4. Determine if the app uses modern authentication or legacy protocols — legacy protocol apps are common targets.
5. Review the app's registration in Azure AD to confirm it is a sanctioned application.

---

## False Positive Considerations

- Core business applications (Microsoft 365, Outlook, Teams) will naturally dominate this list every day.
- Monitoring or SIEM integration apps may generate high authentication volumes through scheduled polling.

**Tuning tip:** To remove expected core apps from the view and highlight surprises, add `| where AppDisplayName !in ("Microsoft Office 365", "Microsoft Teams", "Azure Portal")` and adjust the exclusion list to match your baseline top apps.

---

## References

- [MITRE ATT&CK – Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
- [Microsoft Docs – SigninLogs Schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)

---

*Last Updated: 2025-09-01*
