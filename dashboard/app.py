import streamlit as st
import pandas as pd
from pathlib import Path

ALERT_FILE = Path("data/alerts/alerts.csv")

st.set_page_config(page_title="Cloud SOC Triage Dashboard", layout="wide")

st.title("Cloud SOC Triage Dashboard")

if not ALERT_FILE.exists():
    st.warning("No alerts found. Run python src/main.py first.")
else:
    df = pd.read_csv(ALERT_FILE)

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Alerts", len(df))
    col2.metric("Critical Alerts", len(df[df["severity"] == "Critical"]))
    col3.metric("High Alerts", len(df[df["severity"] == "High"]))
    col4.metric("Open Cases", len(df[df["status"] == "Open"]))

    st.subheader("Incident Queue")

    severity_filter = st.multiselect(
        "Filter by severity",
        options=df["severity"].unique(),
        default=list(df["severity"].unique())
    )

    filtered_df = df[df["severity"].isin(severity_filter)]

    st.dataframe(filtered_df, use_container_width=True)

    st.subheader("Analyst Summary")

    selected_index = st.selectbox(
        "Select an alert to investigate",
        options=filtered_df.index
    )

    alert = filtered_df.loc[selected_index]

    st.write(f"**Rule ID:** {alert['rule_id']}")
    st.write(f"**Title:** {alert['title']}")
    st.write(f"**Severity:** {alert['severity']}")
    st.write(f"**Risk Score:** {alert['risk_score']}")
    st.write(f"**User:** {alert['user_name']}")
    st.write(f"**User Role:** {alert['user_role']}")
    st.write(f"**Department:** {alert['department']}")
    st.write(f"**Source IP:** {alert['source_ip']}")
    st.write(f"**AWS Region:** {alert['aws_region']}")
    st.write(f"**Event Time:** {alert['event_time']}")
    st.write(f"**Description:** {alert['description']}")
    st.write(f"**Evidence:** {alert['evidence']}")
    st.write(f"**Recommended Action:** {alert['recommended_action']}")
    st.write(f"**Status:** {alert['status']}")
