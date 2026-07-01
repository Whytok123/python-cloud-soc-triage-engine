from collections import defaultdict


def detect_failed_logins_followed_by_success(events: list[dict]) -> list[dict]:
    alerts = []
    login_events = []

    for event in events:
        if event["event_name"] == "ConsoleLogin":
            result = event["raw_event"].get("responseElements", {}).get("ConsoleLogin")

            login_events.append({
                **event,
                "login_result": result
            })

    grouped_events = defaultdict(list)

    for event in login_events:
        key = (event["user_name"], event["source_ip"])
        grouped_events[key].append(event)

    for (user_name, source_ip), user_events in grouped_events.items():
        user_events.sort(key=lambda x: x["event_time"])

        failed_count = 0

        for event in user_events:
            if event["login_result"] == "Failure":
                failed_count += 1

            if event["login_result"] == "Success" and failed_count >= 3:
                alerts.append({
                    "rule_id": "AWS-AUTH-001",
                    "title": "Multiple failed logins followed by success",
                    "severity": "High",
                    "description": "Three or more failed console logins were followed by a successful login.",
                    "user_name": user_name,
                    "source_ip": source_ip,
                    "event_time": event["event_time"],
                    "aws_region": event["aws_region"],
                    "evidence": f"{failed_count} failed logins followed by success"
                })

    return alerts


def detect_access_key_created(events: list[dict]) -> list[dict]:
    alerts = []

    for event in events:
        if event["event_name"] == "CreateAccessKey":
            alerts.append({
                "rule_id": "AWS-IAM-001",
                "title": "New IAM access key created",
                "severity": "Medium",
                "description": "A new long-term IAM access key was created.",
                "user_name": event["user_name"],
                "source_ip": event["source_ip"],
                "event_time": event["event_time"],
                "aws_region": event["aws_region"],
                "evidence": "CreateAccessKey event detected"
            })

    return alerts


def detect_privilege_escalation(events: list[dict]) -> list[dict]:
    risky_events = {
        "AttachUserPolicy",
        "AttachRolePolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "AddUserToGroup",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion"
    }

    alerts = []

    for event in events:
        if event["event_name"] in risky_events:
            alerts.append({
                "rule_id": "AWS-IAM-002",
                "title": "Possible IAM privilege escalation",
                "severity": "High",
                "description": f"Risky IAM permission change detected: {event['event_name']}",
                "user_name": event["user_name"],
                "source_ip": event["source_ip"],
                "event_time": event["event_time"],
                "aws_region": event["aws_region"],
                "evidence": event["event_name"]
            })

    return alerts


def detect_cloudtrail_tampering(events: list[dict]) -> list[dict]:
    risky_events = {
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        "PutEventSelectors"
    }

    alerts = []

    for event in events:
        if event["event_name"] in risky_events:
            alerts.append({
                "rule_id": "AWS-LOG-001",
                "title": "CloudTrail logging modified or disabled",
                "severity": "Critical",
                "description": f"CloudTrail logging change detected: {event['event_name']}",
                "user_name": event["user_name"],
                "source_ip": event["source_ip"],
                "event_time": event["event_time"],
                "aws_region": event["aws_region"],
                "evidence": event["event_name"]
            })

    return alerts


def run_all_detections(events: list[dict]) -> list[dict]:
    alerts = []

    alerts.extend(detect_failed_logins_followed_by_success(events))
    alerts.extend(detect_access_key_created(events))
    alerts.extend(detect_privilege_escalation(events))
    alerts.extend(detect_cloudtrail_tampering(events))

    return alerts
