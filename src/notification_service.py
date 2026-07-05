import json
import os
from datetime import datetime, timezone


NOTIFICATION_DIR = "data/notifications"
JSON_OUTBOX = os.path.join(NOTIFICATION_DIR, "notification_outbox.json")
TEXT_OUTBOX = os.path.join(NOTIFICATION_DIR, "email_outbox.txt")

NOTIFICATION_PRIORITIES = {
    "Critical": {
        "priority": "P1",
        "urgency": "immediate",
        "delivery_timing": "send_immediately",
    },
    "High": {
        "priority": "P2",
        "urgency": "normal",
        "delivery_timing": "send_during_triage_queue",
    },
}


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def should_notify(alert):
    return alert.get("severity") in NOTIFICATION_PRIORITIES


def get_notification_priority(alert):
    severity = alert.get("severity", "Unknown")

    return NOTIFICATION_PRIORITIES.get(
        severity,
        {
            "priority": "P3",
            "urgency": "none",
            "delivery_timing": "do_not_notify",
        },
    )


def build_notification(alert, notification_id):
    severity = alert.get("severity", "Unknown")
    title = alert.get("title", "Unknown alert")
    rule_id = alert.get("rule_id", "Unknown rule")
    risk_score = alert.get("risk_score", "Unknown")
    user_name = alert.get("user_name", "unknown")
    source_ip = alert.get("source_ip", "unknown")
    mitre_technique_id = alert.get("mitre_technique_id", "unknown")
    mitre_technique_name = alert.get("mitre_technique_name", "unknown")
    recommended_action = alert.get(
        "recommended_action",
        "Review the alert evidence and validate whether the activity was authorized."
    )
    analyst_summary = alert.get("analyst_summary", "No analyst summary available.")

    priority_info = get_notification_priority(alert)
    priority = priority_info["priority"]
    urgency = priority_info["urgency"]
    delivery_timing = priority_info["delivery_timing"]

    subject = f"[{priority}][{severity}] Cloud SOC Alert - {title}"

    body = (
        f"{severity.upper()} CLOUD SOC ALERT\n\n"
        f"Notification ID: {notification_id}\n"
        f"Priority: {priority}\n"
        f"Urgency: {urgency}\n"
        f"Delivery Timing: {delivery_timing}\n"
        f"Rule ID: {rule_id}\n"
        f"Title: {title}\n"
        f"Risk Score: {risk_score}\n"
        f"User: {user_name}\n"
        f"Source IP: {source_ip}\n"
        f"MITRE Technique: {mitre_technique_id} {mitre_technique_name}\n\n"
        f"Analyst Summary:\n{analyst_summary}\n\n"
        f"Recommended Action:\n{recommended_action}\n"
    )

    return {
        "notification_id": notification_id,
        "created_at": utc_now_iso(),
        "channel": "local_email_outbox",
        "delivery_status": "simulated",
        "priority": priority,
        "urgency": urgency,
        "delivery_timing": delivery_timing,
        "subject": subject,
        "severity": severity,
        "rule_id": rule_id,
        "title": title,
        "risk_score": risk_score,
        "user_name": user_name,
        "source_ip": source_ip,
        "mitre_technique_id": mitre_technique_id,
        "mitre_technique_name": mitre_technique_name,
        "recommended_action": recommended_action,
        "analyst_summary": analyst_summary,
        "body": body,
    }


def generate_notifications(alerts):
    os.makedirs(NOTIFICATION_DIR, exist_ok=True)

    notifications = []

    for alert in alerts:
        if should_notify(alert):
            notification_id = f"NTF-{len(notifications) + 1:04d}"
            notifications.append(build_notification(alert, notification_id))

    outbox = {
        "generated_at": utc_now_iso(),
        "channel": "local_email_outbox",
        "delivery_mode": "simulation",
        "notification_count": len(notifications),
        "notifications": notifications,
    }

    with open(JSON_OUTBOX, "w", encoding="utf-8") as file:
        json.dump(outbox, file, indent=2)

    with open(TEXT_OUTBOX, "w", encoding="utf-8") as file:
        if not notifications:
            file.write("No High or Critical alerts generated notifications.\n")
        else:
            for notification in notifications:
                file.write("=" * 80 + "\n")
                file.write(notification["subject"] + "\n")
                file.write("=" * 80 + "\n")
                file.write(notification["body"] + "\n\n")

    return outbox
