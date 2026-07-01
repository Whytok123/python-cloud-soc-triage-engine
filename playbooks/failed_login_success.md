# Playbook: Multiple Failed Logins Followed by Success

## Alert Name
Multiple failed logins followed by success

## Severity
High

## Why This Matters
Multiple failed logins followed by a successful login may indicate brute force, password guessing, password spraying, or a compromised account.

## Detection Logic
This alert is generated when the same user and source IP have three or more failed console logins followed by a successful login.

## Evidence to Review
- user_name
- source_ip
- event_time
- aws_region
- failed login count
- successful login event

## Triage Steps
1. Confirm whether the login was performed by the real user.
2. Review login activity before and after the successful login.
3. Check whether the source IP is expected.
4. Check if MFA was used.
5. Review any IAM changes after the login.
6. Escalate if the user does not recognize the activity.

## Containment Actions
- Reset the user password.
- Enforce MFA.
- Disable suspicious access keys.
- Review IAM permissions.
- Monitor for additional activity.

## Closure Criteria
Close the case only after the login is confirmed as legitimate or the account has been secured.
