# Sign-In Summary by Application – Success vs. Failure Counts (Last 24 Hours)

> **Category:** Log Aggregation / Investigation  
> **Platform:** Microsoft Sentinel | Azure AD | Log Analytics  
> **MITRE ATT&CK:** [TA0001 – Initial Access / Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/) | [TA0006 – Credential Access / Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)  
> **Severity:** Low  

---

## Description

This query generates a summary of sign-in activity for the past 24 hours, aggregated by application. It returns both the success count and failure count per app, then surfaces the top 5 applications by failed sign-in volume. This helps the SOC quickly identify which apps are being most actively targeted by failed authentication attempts — a useful daily triage view for spotting brute-force activity or misconfigured clients.

---

## Query

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| summarize
    FailCount = countif(ResultType != 0),
    SuccessCount = countif(ResultType == 0)
    by AppDisplayName
| top 5 by FailCount desc
```

---

## How It Works

1. **Table** – `SigninLogs` captures all Azure AD authentication events with result codes and application names.
2. **Filters** – `TimeGenerated > ago(24h)` scopes to the last 24 hours.
3. **Aggregation** – `countif(ResultType != 0)` counts all failed sign-ins per app in a single pass. `countif(ResultType == 0)` counts all successful sign-ins per app. Both are grouped `by AppDisplayName`, giving a side-by-side comparison of success vs failure per application.
4. **Ranking** – `top 5 by FailCount desc` returns the 5 most-targeted applications by failure volume.

---

## Use Case / Scenario

> *During a SOC daily check, an analyst wants a quick view of which applications are generating the most authentication failures. An app with a high failure-to-success ratio may be under a brute-force or credential stuffing attack. Apps with high success counts but unusual spikes may indicate account takeover using valid stolen credentials.*

---

## Investigation Steps

When this query returns unexpected results, an analyst should:

1. Identify apps with disproportionately high failure counts compared to success counts — this ratio is often more telling than raw numbers.
2. Drill into the specific app and pivot to per-user failure counts to identify targeted accounts.
3. Check the source IPs associated with failures on the flagged app.
4. Compare today's numbers against the prior 7-day baseline to identify anomalous spikes.
5. If a productivity app (email, SharePoint) shows high failures, check for credential stuffing toolkits targeting that service.

---

## False Positive Considerations

- Applications with frequent automated token refreshes may generate non-zero result codes that are not true failures.
- Legacy authentication clients (SMTP, IMAP) can generate high failure volumes from misconfigurations.
- Password change cycles that temporarily invalidate cached credentials across many clients.

**Tuning tip:** Exclude legacy authentication noise with `| where ClientAppUsed !in ("SMTP", "IMAP4", "POP3")` if those protocols are expected in your environment but not under active monitoring.

---

## References

- [MITRE ATT&CK – Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK – Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
- [Microsoft Docs – SigninLogs Schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)

---

*Last Updated: 2025-09-01*
