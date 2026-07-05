import csv
from pathlib import Path


def write_alerts_to_csv(alerts: list[dict], output_file: str) -> None:
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "rule_id",
        "title",
        "severity",
        "risk_score",
        "user_name",
        "user_role",
        "department",
        "source_ip",
        "aws_region",
        "event_time",
        "description",
        "evidence",
        "recommended_action",
        "analyst_summary",
        "status"
    ]

    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for alert in alerts:
            row = {field: alert.get(field, "") for field in fields}
            row["status"] = "Open"
            writer.writerow(row)
