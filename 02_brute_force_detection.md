# Brute Force Password Attack Detection – Repeated Failures per User per IP

> **Category:** Security Detection  
> **Platform:** Microsoft Sentinel | Azure AD | Log Analytics  
> **MITRE ATT&CK:** [TA0006 – Credential Access / Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)  
> **Severity:** High  

---

## Description

This query detects potential brute-force password attacks against Azure AD accounts by identifying cases where a single IP address has generated 5 or more failed sign-in attempts against the same user within the last hour. It surfaces the targeted user, the attacking IP, the total failure count, and the set of applications that were targeted during the burst.

---

## Query

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailedAttempts = count(), AppsTargeted = make_set(AppDisplayName)
    by UserPrincipalName, IPAddress
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

---

## How It Works

1. **Table** – `SigninLogs` captures all Azure AD sign-in attempts including failures, source IP, and application name.
2. **Filters** – `TimeGenerated > ago(1h)` scopes to the last hour for near-real-time detection. `ResultType != 0` keeps only failed attempts, cutting noise from successful logins.
3. **Aggregation** – `count()` totals the failed attempts. `make_set(AppDisplayName)` collects the distinct apps targeted, grouped by `UserPrincipalName` and `IPAddress` together — this ensures we're detecting the same IP hammering the same user, not just a busy IP overall.
4. **Threshold** – `where FailedAttempts >= 5` flags user+IP pairs that exceed the brute-force threshold. Adjust based on your organization's baseline.
5. **Ordering** – `order by FailedAttempts desc` puts the most aggressive attempts at the top.

---

## Use Case / Scenario

> *An attacker performing credential stuffing or password spraying will generate a high number of failed logins from the same IP against a specific account. This query catches that pattern in near-real-time and lists the apps being targeted, helping the SOC prioritize which accounts to lock or investigate first.*

---

## Investigation Steps

When this query returns results, an analyst should:

1. Determine whether the source IP is internal (misconfigured script/service) or external (attacker infrastructure).
2. Check threat intelligence feeds for the flagged IP address.
3. Look for a successful sign-in (`ResultType == 0`) from the same IP or user shortly after the failure burst — this would indicate a successful compromise.
4. Review `AppsTargeted` — if high-value apps (email, VPN, admin portals) are in the set, escalate immediately.
5. Confirm whether the affected user account has MFA enabled.
6. Consider temporarily blocking the source IP at the firewall or Conditional Access level.

---

## False Positive Considerations

- Misconfigured service accounts with expired or incorrect credentials.
- Legitimate users who forgot their password and attempted multiple times from the same network.
- Automated vulnerability scanners or pen test tools.

**Tuning tip:** Exclude known scanner IPs or service accounts with `| where IPAddress !in ("10.0.0.5") and UserPrincipalName !startswith "svc_"`.

---

## References

- [MITRE ATT&CK – Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK – Credential Stuffing (T1110.004)](https://attack.mitre.org/techniques/T1110/004/)
- [Microsoft Docs – SigninLogs Schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)

---

*Last Updated: 2025-08-23*
