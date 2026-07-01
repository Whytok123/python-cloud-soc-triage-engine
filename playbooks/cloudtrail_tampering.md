# Playbook: CloudTrail Logging Modified or Disabled

## Alert Name
CloudTrail logging modified or disabled

## Severity
Critical

## Why This Matters
CloudTrail records AWS account activity. If logging is stopped, deleted, or modified, an attacker may be trying to hide their actions.

## Detection Logic
This alert is generated when one of these events is detected:

- StopLogging
- DeleteTrail
- UpdateTrail
- PutEventSelectors

## Evidence to Review
- eventTime
- eventName
- userIdentity
- sourceIPAddress
- awsRegion
- requestParameters

## Triage Steps
1. Confirm whether the CloudTrail change was approved.
2. Identify the IAM user or role that performed the action.
3. Review recent activity from the same user.
4. Check whether the source IP is expected.
5. Verify whether CloudTrail is still enabled.
6. Re-enable logging if needed.
7. Escalate if unauthorized.

## Containment Actions
- Re-enable CloudTrail logging.
- Disable suspicious access keys.
- Remove unauthorized IAM permissions.
- Rotate affected credentials.
- Preserve logs for investigation.

## Closure Criteria
Close the case only after the action is confirmed as authorized or the unauthorized activity has been contained and documented.
