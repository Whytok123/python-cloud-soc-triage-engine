import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"

if str(SRC_PATH) not in sys.path:
    sys.path.append(str(SRC_PATH))

from database import get_all_incidents, get_incident_by_id, update_incident



def load_ingestion_status(status_file="data/ingestion/ingestion_status.json"):
    status_path = Path(status_file)

    if not status_path.exists():
        return None

    try:
        with status_path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        return None


def render_ingestion_status():
    status = load_ingestion_status()

    st.subheader("Ingestion Status")

    if not status:
        st.info("No ingestion status found yet. Run `python src/main.py` to generate ingestion status.")
        return

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Mode", status.get("mode", "unknown"))
    col2.metric("Events Processed", status.get("processed_events", 0))
    col3.metric("Rule Alerts", status.get("rule_alerts", 0))
    col4.metric("Total Alerts", status.get("total_alerts", 0))

    st.caption(
        f"Source: {status.get('source_name', 'unknown')} | "
        f"Environment: {status.get('environment', 'unknown')} | "
        f"Cloud Provider: {status.get('cloud_provider', 'unknown')} | "
        f"Input File: {status.get('input_file', 'unknown')} | "
        f"Last Ingested: {status.get('ingested_at', 'unknown')}"
    )


st.set_page_config(
    page_title="Cloud SOC Triage Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Cloud SOC Triage Dashboard")
st.caption("Offline AWS CloudTrail detection, MITRE mapping, local enrichment, and case management lab")

render_ingestion_status()
st.divider()

incidents = get_all_incidents()

if not incidents:
    st.warning("No incidents found. Run the detection engine first: python src/main.py")
    st.stop()

df = pd.DataFrame(incidents)

total_alerts = len(df)
critical_alerts = len(df[df["severity"] == "Critical"])
high_alerts = len(df[df["severity"] == "High"])
open_cases = len(df[df["status"] != "Closed"])
suspicious_ip_alerts = len(df[df["ip_reputation"] == "Suspicious"])

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Alerts", total_alerts)
col2.metric("Critical Alerts", critical_alerts)
col3.metric("High Alerts", high_alerts)
col4.metric("Open Cases", open_cases)
col5.metric("Suspicious IP Alerts", suspicious_ip_alerts)

st.divider()

st.subheader("SOC Case Filters")

filter_col1, filter_col2, filter_col3, filter_col4 = st.columns(4)

with filter_col1:
    severity_filter = st.multiselect(
        "Filter by severity",
        options=sorted(df["severity"].unique()),
        default=list(sorted(df["severity"].unique()))
    )

with filter_col2:
    status_filter = st.multiselect(
        "Filter by status",
        options=sorted(df["status"].unique()),
        default=list(sorted(df["status"].unique()))
    )

with filter_col3:
    user_filter = st.multiselect(
        "Filter by user",
        options=sorted(df["user_name"].unique()),
        default=list(sorted(df["user_name"].unique()))
    )

with filter_col4:
    ip_rep_filter = st.multiselect(
        "Filter by IP reputation",
        options=sorted(df["ip_reputation"].unique()),
        default=list(sorted(df["ip_reputation"].unique()))
    )

filtered_df = df[
    df["severity"].isin(severity_filter)
    & df["status"].isin(status_filter)
    & df["user_name"].isin(user_filter)
    & df["ip_reputation"].isin(ip_rep_filter)
]

st.subheader("Incident Queue")

display_columns = [
    "incident_id",
    "rule_id",
    "title",
    "severity",
    "risk_score",
    "mitre_technique_id",
    "ip_reputation",
    "user_risk",
    "user_name",
    "source_ip",
    "status",
    "event_time"
]

st.dataframe(
    filtered_df[display_columns],
    use_container_width=True,
    hide_index=True
)

st.divider()

st.subheader("Incident Details and Analyst Update")

incident_ids = filtered_df["incident_id"].tolist()

if not incident_ids:
    st.warning("No incidents match the selected filters.")
    st.stop()

selected_incident_id = st.selectbox(
    "Select an incident to investigate",
    options=incident_ids
)

incident = get_incident_by_id(selected_incident_id)

if incident:
    detail_col1, detail_col2, detail_col3 = st.columns(3)

    with detail_col1:
        st.markdown("### Case Summary")
        st.write(f"**Incident ID:** {incident['incident_id']}")
        st.write(f"**Rule ID:** {incident['rule_id']}")
        st.write(f"**Title:** {incident['title']}")
        st.write(f"**Severity:** {incident['severity']}")
        st.write(f"**Risk Score:** {incident['risk_score']}")
        st.write(f"**Status:** {incident['status']}")

    with detail_col2:
        st.markdown("### Entity Context")
        st.write(f"**User:** {incident['user_name']}")
        st.write(f"**Role:** {incident['user_role']}")
        st.write(f"**Department:** {incident['department']}")
        st.write(f"**User Risk:** {incident['user_risk']}")
        st.write(f"**Source IP:** {incident['source_ip']}")
        st.write(f"**AWS Region:** {incident['aws_region']}")

    with detail_col3:
        st.markdown("### Local Enrichment")
        st.write(f"**IP Type:** {incident['ip_type']}")
        st.write(f"**IP Label:** {incident['ip_label']}")
        st.write(f"**IP Reputation:** {incident['ip_reputation']}")
        st.write(f"**Business Hours:** {incident['business_hours']}")
        st.write(f"**Normal Region:** {incident['normal_region']}")
        st.write(f"**Unusual Region:** {incident['unusual_region']}")

    st.markdown("### MITRE ATT&CK Mapping")
    mitre_col1, mitre_col2, mitre_col3 = st.columns(3)

    mitre_col1.info(f"**Tactic:** {incident['mitre_tactic']}")
    mitre_col2.info(f"**Technique ID:** {incident['mitre_technique_id']}")
    mitre_col3.info(f"**Technique:** {incident['mitre_technique_name']}")

    st.markdown("### Local Risk Notes")
    st.warning(incident["local_risk_notes"])

    st.markdown("### Analyst Summary")
    st.info(incident.get("analyst_summary", "No analyst summary available."))

    st.markdown("### Description")
    st.write(incident["description"])

    st.markdown("### Evidence")
    st.code(incident["evidence"])

    st.markdown("### Recommended Analyst Action")
    st.write(incident["recommended_action"])

    st.markdown("### Update Case")

    status_options = [
        "Open",
        "Investigating",
        "Escalated",
        "Closed",
        "False Positive"
    ]

    current_status = incident["status"]
    if current_status not in status_options:
        current_status = "Open"

    new_status = st.selectbox(
        "Case status",
        options=status_options,
        index=status_options.index(current_status)
    )

    new_notes = st.text_area(
        "Analyst notes",
        value=incident.get("analyst_notes", ""),
        height=150,
        placeholder="Add investigation notes, containment actions, or closure reason..."
    )

    if st.button("Save Case Update"):
        update_incident(selected_incident_id, new_status, new_notes)
        st.success(f"Updated {selected_incident_id}. Refreshing dashboard...")
        st.rerun()

st.divider()

st.subheader("Dashboard Summary")

summary_text = f"""
This dashboard contains {total_alerts} cloud security alerts.
There are {critical_alerts} critical alerts, {high_alerts} high alerts, and {suspicious_ip_alerts} alerts involving suspicious IP context.
{open_cases} cases are currently not closed.

The highest-risk incidents should be investigated first, especially alerts involving CloudTrail tampering,
root account usage, IAM privilege changes, suspicious IPs, critical users, public S3 exposure,
and security groups opened to the internet.
"""

st.info(summary_text)
