# Top Users by High-Risk Sign-Ins (Last 7 Days)

> **Category:** Log Aggregation / Investigation  
> **Platform:** Microsoft Sentinel | Azure AD Identity Protection | Log Analytics  
> **MITRE ATT&CK:** [TA0001 – Initial Access / Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/) | [TA0006 – Credential Access / Steal or Forge Authentication Tokens (T1528)](https://attack.mitre.org/techniques/T1528/)  
> **Severity:** High  

---

## Description

This query surfaces the top 10 users with the highest number of high-risk sign-ins over the last 7 days, as classified by Azure AD Identity Protection's `RiskLevelDuringSignIn` field. For each user it returns the total count of risky sign-ins, the number of distinct IP addresses used, and the most recent risky sign-in timestamp — giving the SOC a prioritized list for investigation and potential account remediation.

---

## Query

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelDuringSignIn == "high"
| summarize RiskySigninCount = count(), DistinctIPs = dcount(IPAddress), LatestRiskySignin = max(TimeGenerated) by UserPrincipalName
| top 10 by RiskySigninCount
```

---

## How It Works

1. **Table** – `SigninLogs` includes Azure AD Identity Protection risk signals alongside standard sign-in metadata.
2. **Filters** – `TimeGenerated > ago(7d)` scopes to the last 7 days for a weekly risk summary. `RiskLevelDuringSignIn == "high"` isolates only the sign-ins flagged at the highest risk level by Identity Protection.
3. **Aggregation** – `count()` totals all high-risk sign-ins per user. `dcount(IPAddress)` counts distinct source IPs, which can indicate sign-ins from multiple locations or infrastructure. `max(TimeGenerated)` captures the most recent risky sign-in so analysts can prioritize recently active accounts.
4. **Ranking** – `top 10 by RiskySigninCount` returns only the 10 most at-risk users, sorted by descending risk volume.

---

## Use Case / Scenario

> *Azure AD Identity Protection flags sign-ins as high-risk based on signals such as anonymous IPs, atypical travel, malware-linked IPs, and leaked credentials. This query aggregates those signals over a week to identify which users are persistently triggering high-risk events — a pattern that may indicate an ongoing account compromise, credential exposure, or targeted attack campaign.*

---

## Investigation Steps

When this query returns results, an analyst should:

1. Review the `LatestRiskySignin` — accounts with very recent risky sign-ins should be prioritized.
2. Check `DistinctIPs` — a high number of distinct IPs may indicate impossible travel or use of proxy/VPN infrastructure.
3. Open the user's Identity Protection risk profile in Azure AD for the full risk event history.
4. Determine whether any of the risky sign-ins resulted in a successful authentication (`ResultType == 0`).
5. Check if the user has recently accessed sensitive applications or performed privileged actions.
6. Consider forcing a password reset and re-registering MFA for the highest-risk accounts.

---

## False Positive Considerations

- Users who frequently travel internationally and sign in from different countries (atypical travel risk signal).
- Users who legitimately use VPNs or privacy tools that trigger anonymous IP detections.
- Shared accounts accessed from multiple locations.

**Tuning tip:** Correlate with `ConditionalAccessStatus` to check if risk-based Conditional Access policies already remediated the session (e.g., forced MFA challenge or blocked access).

---

## References

- [MITRE ATT&CK – Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK – Steal or Forge Authentication Tokens (T1528)](https://attack.mitre.org/techniques/T1528/)
- [Microsoft Docs – Azure AD Identity Protection Risk Levels](https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks)
- [Microsoft Docs – SigninLogs Schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)

---

*Last Updated: 2025-08-28*
