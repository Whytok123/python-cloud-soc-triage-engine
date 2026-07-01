from parser import load_cloudtrail_file, normalize_event
from detections import run_all_detections
from enrichment import enrich_alert
from severity import add_severity_score
from incident_queue import write_alerts_to_csv


def main():
    raw_events = load_cloudtrail_file("data/raw/sample_cloudtrail.json")

    normalized_events = []
    for event in raw_events:
        normalized_events.append(normalize_event(event))

    alerts = run_all_detections(normalized_events)

    final_alerts = []
    for alert in alerts:
        alert = enrich_alert(alert)
        alert = add_severity_score(alert)
        final_alerts.append(alert)

    write_alerts_to_csv(final_alerts, "data/alerts/alerts.csv")

    print(f"Processed events: {len(normalized_events)}")
    print(f"Generated alerts: {len(final_alerts)}")
    print("Alert queue created: data/alerts/alerts.csv")


if __name__ == "__main__":
    main()
