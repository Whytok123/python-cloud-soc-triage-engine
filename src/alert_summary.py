def safe_value(value, default="unknown"):
    if value is None:
        return default

    value = str(value).strip()

    if not value:
        return default

    return value


def build_analyst_summary(alert):
    severity = safe_value(alert.get("severity"), "Unknown severity")
    title = safe_value(alert.get("title"), "security alert")
    user_name = safe_value(alert.get("user_name"))
    source_ip = safe_value(alert.get("source_ip"))
    ip_reputation = safe_value(alert.get("ip_reputation"))
    user_risk = safe_value(alert.get("user_risk"))
    mitre_tactic = safe_value(alert.get("mitre_tactic"))
    mitre_technique_id = safe_value(alert.get("mitre_technique_id"))
    mitre_technique_name = safe_value(alert.get("mitre_technique_name"))
    recommended_action = safe_value(alert.get("recommended_action"), "Review the alert evidence and validate whether the activity was authorized.")

    summary = (
        f"{severity} alert detected: {title}. "
        f"The activity involves user {user_name} from source IP {source_ip}. "
        f"IP reputation is {ip_reputation}, and user risk is {user_risk}. "
        f"This alert maps to MITRE ATT&CK tactic {mitre_tactic} using technique "
        f"{mitre_technique_id} {mitre_technique_name}. "
        f"Recommended analyst action: {recommended_action}"
    )

    return summary


def add_analyst_summary(alert):
    alert["analyst_summary"] = build_analyst_summary(alert)
    return alert
