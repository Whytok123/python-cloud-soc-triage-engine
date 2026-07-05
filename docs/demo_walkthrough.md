# Demo Walkthrough

This walkthrough explains how to demonstrate the Python Cloud SOC Triage Engine in under two minutes.

## 1. Run the detection engine

Command:

    python src/main.py

Expected output:

    Processed events: 10
    Generated rule alerts: 7
    Generated correlation alerts: 1
    Generated total alerts: 8
    Alert queue created: data/alerts/alerts.csv
    Incident database updated: data/incidents/incidents.db
    Ingestion status updated: data/ingestion/ingestion_status.json
    Notifications generated: 7

## 2. Start the dashboard

Command:

    streamlit run dashboard/app.py

If running inside Kali VM and opening from Windows, use the Kali VM IP:

    http://<KALI_VM_IP>:8501

Example:

    http://192.168.119.128:8501

## 3. Show ingestion status

At the top of the dashboard, show:

- Ingestion mode
- Source name
- Input file
- Events processed
- Alerts generated
- Last ingested time

## 4. Show notification status

Show the notification widget:

- P1 Critical alerts
- P2 High alerts
- Local email outbox simulation

Real SMTP email is intentionally not enabled by default to avoid storing passwords or API keys.

## 5. Open a high-risk incident

Open a Critical or High incident and show:

- Case summary
- Entity context
- Local enrichment
- MITRE ATT&CK mapping
- Analyst summary
- Evidence
- Recommended analyst action
- Case update workflow

## 6. Show generated reports

Open:

    reports/generated/

Each incident has a markdown report with investigation details and closure guidance.

## 7. Explain the value

This project demonstrates an end-to-end SOC workflow:

Cloud logs -> detection -> enrichment -> correlation -> prioritization -> dashboard triage -> reports -> notifications.
