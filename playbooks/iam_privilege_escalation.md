# Playbook: Possible IAM Privilege Escalation

## Alert Name
Possible IAM privilege escalation

## Severity
High

## Why This Matters
IAM permission changes can allow a user or role to gain additional access. Attackers often modify IAM permissions to increase control over an AWS account.

## Detection Logic
This alert is generated when risky IAM events are detected, such as:

- AttachUserPolicy
- AttachRolePolicy
- PutUserPolicy
- PutRolePolicy
- AddUserToGroup
- CreatePolicyVersion
- SetDefaultPolicyVersion

## Evidence to Review
- eventName
- userIdentity
- sourceIPAddress
- awsRegion
- requestParameters
- affected user, group, role, or policy

## Triage Steps
1. Confirm whether the IAM change was approved.
2. Identify who made the change.
3. Identify what permission was added or modified.
4. Check whether the permission grants admin or sensitive access.
5. Review activity from the same user before and after the change.
6. Escalate if the change was unauthorized.

## Containment Actions
- Remove unauthorized IAM permissions.
- Disable suspicious credentials.
- Rotate access keys if needed.
- Review other IAM changes from the same actor.
- Preserve evidence.

## Closure Criteria
Close the case only after the IAM change is confirmed as authorized or unauthorized permissions have been removed.
