BASE_SCORE = {
    "Low": 25,
    "Medium": 50,
    "High": 75,
    "Critical": 95
}


def add_severity_score(alert: dict) -> dict:
    severity = alert.get("severity", "Low")
    score = BASE_SCORE.get(severity, 25)

    if alert.get("user_role") == "Unknown":
        score += 5

    if alert.get("rule_id") == "AWS-LOG-001":
        score = 100

    alert["risk_score"] = min(score, 100)

    return alert
