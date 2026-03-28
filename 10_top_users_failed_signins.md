# Top 5 Users by Failed Sign-In Attempts (Last 24 Hours)

> **Category:** Security Detection  
> **Platform:** Microsoft Sentinel | Azure AD | Log Analytics  
> **MITRE ATT&CK:** [TA0006 – Credential Access / Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)  
> **Severity:** Medium  

---

## Description

This query identifies the top 5 user accounts generating the most failed sign-in attempts in the last 24 hours. It is a lightweight triage query used to quickly surface accounts at risk of lockout, accounts being actively targeted by brute-force attempts, or users with persistent authentication issues that may need IT support.

---

## Query

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize FailedSigninCount = count() by UserPrincipalName
| top 5 by FailedSigninCount
```

---

## How It Works

1. **Table** – `SigninLogs` captures all Azure AD authentication events.
2. **Filters** – `TimeGenerated > ago(24h)` scopes to the last 24 hours. `ResultType != 0` keeps only failed sign-in attempts, discarding successful logins to focus exclusively on failure activity.
3. **Aggregation** – `count()` totals all failed attempts grouped `by UserPrincipalName`, producing a per-user failure count.
4. **Ranking** – `top 5 by FailedSigninCount` returns the 5 accounts with the highest failure volumes, sorted descending.

---

## Use Case / Scenario

> *This query is used as a morning triage tool. A user with a high failure count may be experiencing a forgotten password, a misconfigured client, or — more seriously — may be the target of a brute-force or credential stuffing attack. Identifying these accounts early allows the SOC to take pre-emptive action before an account is compromised or locked out.*

---

## Investigation Steps

When this query returns results, an analyst should:

1. Determine whether the user is aware of the failures — a quick check with the user or their manager can rule out a benign cause.
2. Review the source IPs of the failures — are they all from the user's expected location, or from unexpected external addresses?
3. Check whether any successful sign-in (`ResultType == 0`) followed the failures for the same account.
4. Look at the timeline of failures — a burst in a short window suggests an automated attack; spread-out failures over hours may indicate a misconfigured device.
5. If the account is targeted by an external IP, consider enforcing Conditional Access policies or temporarily disabling the account.

---

## False Positive Considerations

- Users who recently changed their password but have cached credentials on old devices generating repeated failures.
- Service accounts or shared mailboxes with expired credentials.
- Users returning from leave who have forgotten their password.

**Tuning tip:** Separate user accounts from service accounts by adding `| where UserPrincipalName !startswith "svc_"` to keep the results focused on human users.

---

## References

- [MITRE ATT&CK – Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK – Credential Stuffing (T1110.004)](https://attack.mitre.org/techniques/T1110/004/)
- [Microsoft Docs – SigninLogs Schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)

---

*Last Updated: 2025-09-01*
