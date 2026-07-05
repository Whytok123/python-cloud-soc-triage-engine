import os
from parser import load_cloudtrail_file, normalize_event
from detections import run_all_detections
from correlation import run_correlation_detections
from enrichment import enrich_alert
from severity import add_severity_score
from mitre_mapping import add_mitre_mapping
from local_enrichment import enrich_with_local_context
from incident_queue import write_alerts_to_csv
from database import save_alerts_to_database


def main():
    input_file = os.getenv("SOC_INPUT_FILE", "data/raw/sample_cloudtrail.json")
    raw_events = load_cloudtrail_file(input_file)

    normalized_events = []
    for event in raw_events:
        normalized_events.append(normalize_event(event))

    rule_alerts = run_all_detections(normalized_events)
    correlation_alerts = run_correlation_detections(normalized_events)

    alerts = rule_alerts + correlation_alerts

    final_alerts = []
    for alert in alerts:
        alert = enrich_alert(alert)
        alert = add_severity_score(alert)
        alert = add_mitre_mapping(alert)
        alert = enrich_with_local_context(alert)
        alert["status"] = "Open"
        final_alerts.append(alert)

    write_alerts_to_csv(final_alerts, "data/alerts/alerts.csv")
    save_alerts_to_database(final_alerts)

    print(f"Processed events: {len(normalized_events)}")
    print(f"Generated rule alerts: {len(rule_alerts)}")
    print(f"Generated correlation alerts: {len(correlation_alerts)}")
    print(f"Generated total alerts: {len(final_alerts)}")
    print("Alert queue created: data/alerts/alerts.csv")
    print("Incident database updated: data/incidents/incidents.db")


if __name__ == "__main__":
    main()
