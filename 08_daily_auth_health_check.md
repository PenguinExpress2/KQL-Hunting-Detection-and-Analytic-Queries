# Daily Authentication Health Check – Sign-Ins by Result Type

> **Category:** Log Aggregation / Investigation  
> **Platform:** Microsoft Sentinel | Azure AD | Log Analytics  
> **MITRE ATT&CK:** [TA0001 – Initial Access / Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)  
> **Severity:** Low  

---

## Description

This query provides a quick daily health check of authentication activity by aggregating all sign-in events from the last 24 hours and grouping them by result type. It gives the SOC an at-a-glance breakdown of successful vs. failed sign-ins across the tenant — useful as a morning dashboard check, a baseline metric, and an early indicator of abnormal authentication volume.

---

## Query

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| summarize SignInCount = count() by ResultType
```

---

## How It Works

1. **Table** – `SigninLogs` contains all Azure AD authentication events with a `ResultType` field indicating outcome.
2. **Filters** – `TimeGenerated > ago(24h)` scopes the query to the last 24 hours.
3. **Aggregation** – `summarize count() by ResultType` groups all sign-in events by their result code and returns a count for each. `ResultType == 0` represents successful sign-ins; any non-zero code represents a specific failure reason (e.g., `50126` = invalid credentials, `50053` = account locked).

---

## Use Case / Scenario

> *Every morning a SOC analyst checks this query as part of a dashboard routine. A sudden spike in a specific non-zero result code — such as `50053` (account locked out) or `50126` (invalid credentials) — can be an early signal of an active brute-force or password spray campaign underway across the tenant.*

---

## Investigation Steps

When this query returns unexpected result type volumes, an analyst should:

1. Look up any unfamiliar non-zero result codes in the [Microsoft Sign-In Error Codes reference](https://learn.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes).
2. For a spike in `50126` (invalid credentials), pivot to per-user and per-IP failure breakdowns to identify the source.
3. For a spike in `50053` (account locked), identify which accounts are locked and whether lockouts are concentrated on specific users (targeted attack) or spread broadly (spray).
4. Compare today's counts to the rolling 7-day average for the same result codes to determine if a spike is genuinely anomalous.

---

## False Positive Considerations

- Scheduled tasks or service accounts with stale credentials generate persistent non-zero codes that are not attacks.
- End of password expiration cycles can temporarily inflate `50126` failure codes.
- New application integrations or misconfigured clients may produce elevated failure codes during setup.

**Tuning tip:** After identifying the baseline failure volume per result code, set threshold alerts on specific codes that deviate significantly from the daily average.

---

## References

- [MITRE ATT&CK – Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
- [Microsoft Docs – Azure AD Sign-In Error Codes](https://learn.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes)
- [Microsoft Docs – SigninLogs Schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)

---

*Last Updated: 2026-01-04*
