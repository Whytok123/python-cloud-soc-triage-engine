# Cloud SOC Incident Report

## Incident ID
INC-0001

## Alert Title
Multiple failed logins followed by success

## Severity
High

## Detection Rule
AWS-AUTH-001

## Date/Time Detected
2026-06-29 14:03 UTC

## Affected User
student-user

## Source IP
8.8.8.8

## AWS Region
us-east-1

## Summary
Three failed AWS console login attempts were followed by a successful login from the same source IP.

## Evidence
- Event source: signin.amazonaws.com
- Event name: ConsoleLogin
- Failed attempts: 3
- Successful login time: 2026-06-29T14:03:00Z
- User: student-user
- Source IP: 8.8.8.8
- Region: us-east-1

## Analyst Assessment
This activity may indicate brute force activity, password spraying, or compromised credentials. Because the login eventually succeeded, the account should be reviewed for unauthorized activity.

## Recommended Actions
1. Verify with the user whether the login was legitimate.
2. Review recent account activity.
3. Reset the password if unauthorized.
4. Enforce MFA.
5. Check for new access keys or IAM permission changes.
6. Continue monitoring the account.

## Status
Open

## Lessons Learned
Improve login monitoring, enforce MFA, and review IAM activity after suspicious authentication events.
