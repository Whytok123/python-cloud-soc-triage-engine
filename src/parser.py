import json
from pathlib import Path


def load_cloudtrail_file(file_path: str) -> list[dict]:
    path = Path(file_path)

    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)

    return data.get("Records", [])


def normalize_event(event: dict) -> dict:
    user_identity = event.get("userIdentity", {})

    return {
        "event_time": event.get("eventTime"),
        "event_source": event.get("eventSource"),
        "event_name": event.get("eventName"),
        "aws_region": event.get("awsRegion"),
        "source_ip": event.get("sourceIPAddress"),
        "user_type": user_identity.get("type"),
        "user_name": user_identity.get("userName") or user_identity.get("arn"),
        "user_arn": user_identity.get("arn"),
        "raw_event": event
    }
