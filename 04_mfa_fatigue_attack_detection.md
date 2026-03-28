# MFA Fatigue Attack Detection – Burst Failures Followed by MFA Success

> **Category:** Security Detection  
> **Platform:** Microsoft Sentinel | Azure AD | Log Analytics  
> **MITRE ATT&CK:** [TA0006 – Credential Access / Multi-Factor Authentication Request Generation (T1621)](https://attack.mitre.org/techniques/T1621/)  
> **Severity:** Critical  

---

## Description

This query detects MFA fatigue attacks — a social engineering technique where an attacker repeatedly triggers MFA push notifications for a valid account until an exhausted user approves one. The query identifies users who experienced 10 or more failed MFA attempts within any 15-minute window, followed by a successful MFA sign-in within 5 minutes of the last failure. It also flags whether the successful sign-in came from an IP that was part of the attack burst, which can indicate attacker-controlled infrastructure.

---

## Query

```kql
// Step 1: Build failure bursts (15-minute windows) for MFA-required failures
let Failures = SigninLogs
| where TimeGenerated > ago(24h)
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ResultType != 0
| extend EventTime = TimeGenerated
| summarize
    FailedMFAAttempts = count(),
    AttackWindowStart = min(EventTime),
    AttackWindowEnd = max(EventTime),
    AppsTargeted = make_set(AppDisplayName),
    FailureIPs = make_set(IPAddress)
  by UserPrincipalName, WindowStart = bin(EventTime, 15m)
| where FailedMFAAttempts >= 10;

// Step 2: Successful MFA events (to join against)
let Successes = SigninLogs
| where TimeGenerated > ago(24h)
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ResultType == 0
| project UserPrincipalName, SuccessTime = TimeGenerated, SuccessIP = IPAddress, SuccessApp = AppDisplayName;

// Step 3: Join failures to successes where success occurs within 5 minutes after the attack window
Failures
| join kind=inner (
    Successes
) on UserPrincipalName
| where SuccessTime between (AttackWindowEnd .. AttackWindowEnd + 5m)
| extend SuccessIPMatchesFailureIPs = iff(SuccessIP in (FailureIPs), true, false)
| project
    UserPrincipalName,
    AttackWindowStart,
    AttackWindowEnd,
    FailedMFAAttempts,
    AppsTargeted,
    FailureIPs,
    SuccessTime,
    SuccessIP,
    SuccessIPMatchesFailureIPs
| order by FailedMFAAttempts desc, AttackWindowEnd desc
```

---

## How It Works

1. **Table** – `SigninLogs` captures MFA-related authentication events including result, app, and IP.
2. **Failures table** – Filters to MFA-required failed sign-ins (`ResultType != 0`, `AuthenticationRequirement == "multiFactorAuthentication"`). Events are binned into 15-minute windows per user with `bin(EventTime, 15m)`. For each window, it computes the failure count, start/end timestamps, distinct apps targeted, and distinct IPs used. Only windows with 10 or more failures are kept.
3. **Successes table** – Separately captures MFA-required successful sign-ins (`ResultType == 0`) with timestamp, IP, and app.
4. **Join** – The two tables are joined on `UserPrincipalName`. The `where SuccessTime between (AttackWindowEnd .. AttackWindowEnd + 5m)` clause confirms the success occurred within 5 minutes after the failure burst ended — the hallmark of a fatigue approval.
5. **IP correlation** – `SuccessIPMatchesFailureIPs` checks whether the approving device shared an IP with the attack burst, which would suggest attacker-controlled infrastructure performed the approval.

---

## Use Case / Scenario

> *MFA fatigue (also called MFA push bombing) is a technique where an attacker who already has a user's password bombards them with MFA push notifications until the user approves one to stop the noise. This technique was used in high-profile breaches including the 2022 Uber and Okta incidents. This query catches the pattern: a burst of MFA failures for a user followed very quickly by an approval.*

---

## Investigation Steps

When this query returns results, an analyst should:

1. Immediately contact the affected user to confirm whether they intentionally approved an MFA prompt.
2. If the approval was accidental or unknown, treat the account as compromised — revoke all active sessions and reset credentials.
3. Review `SuccessIPMatchesFailureIPs` — a `true` value means the attacker's IP performed the approval, indicating the account is likely fully compromised.
4. Check `AppsTargeted` to determine what resources the attacker was attempting to access.
5. Review post-authentication activity for the user: email forwarding rules, file downloads, admin actions.
6. Determine if the attacker moved laterally from the compromised account.

---

## False Positive Considerations

- Legitimate users who struggled with an MFA app and eventually succeeded (typically much lower failure counts — tune the threshold accordingly).
- Shared accounts where multiple users trigger MFA prompts simultaneously.

**Tuning tip:** Increase the `FailedMFAAttempts >= 10` threshold if your environment sees frequent legitimate MFA failures, or add `| where SuccessIPMatchesFailureIPs == true` to narrow to confirmed high-confidence cases.

---

## References

- [MITRE ATT&CK – MFA Request Generation (T1621)](https://attack.mitre.org/techniques/T1621/)
- [MITRE ATT&CK – Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
- [Microsoft Docs – SigninLogs Schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [Uber Breach – MFA Fatigue Example (2022)](https://www.uber.com/newsroom/security-update/)

---

*Last Updated: 2025-08-29*
