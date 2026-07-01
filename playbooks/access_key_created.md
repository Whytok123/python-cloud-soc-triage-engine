# Playbook: New IAM Access Key Created

## Alert Name
New IAM access key created

## Severity
Medium

## Why This Matters
IAM access keys are long-term credentials. If an attacker creates an access key, they may keep access to the AWS account even after the console session ends.

## Detection Logic
This alert is generated when a CreateAccessKey event is detected.

## Evidence to Review
- eventTime
- userIdentity
- sourceIPAddress
- awsRegion
- requestParameters
- affected IAM user

## Triage Steps
1. Confirm whether the access key creation was approved.
2. Identify the user who created the key.
3. Check whether the key belongs to the same user or another user.
4. Review activity from the same source IP.
5. Check if the key was used after creation.
6. Escalate if the key was unauthorized.

## Containment Actions
- Disable the suspicious access key.
- Rotate credentials.
- Review IAM permissions.
- Require MFA.
- Monitor for additional API activity.

## Closure Criteria
Close the case only after the access key is confirmed as authorized or has been disabled and documented.
