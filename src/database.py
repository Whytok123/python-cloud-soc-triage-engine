import sqlite3
from pathlib import Path
from datetime import datetime


DB_PATH = "data/incidents/incidents.db"


def get_connection():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            rule_id TEXT,
            title TEXT,
            severity TEXT,
            risk_score INTEGER,
            user_name TEXT,
            user_role TEXT,
            department TEXT,
            source_ip TEXT,
            aws_region TEXT,
            event_time TEXT,
            description TEXT,
            evidence TEXT,
            recommended_action TEXT,
            analyst_summary TEXT,
            mitre_tactic TEXT,
            mitre_technique_id TEXT,
            mitre_technique_name TEXT,
            ip_type TEXT,
            ip_label TEXT,
            ip_reputation TEXT,
            business_hours TEXT,
            normal_region TEXT,
            unusual_region TEXT,
            user_risk TEXT,
            local_risk_notes TEXT,
            status TEXT,
            analyst_notes TEXT,
            created_at TEXT,
            updated_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def generate_incident_id(number: int) -> str:
    return f"INC-{number:04d}"



def ensure_database_schema(db_path="data/incidents/incidents.db"):
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        existing_columns = [
            row[1]
            for row in cursor.execute("PRAGMA table_info(incidents)").fetchall()
        ]

        if "analyst_summary" not in existing_columns:
            cursor.execute("ALTER TABLE incidents ADD COLUMN analyst_summary TEXT")

        conn.commit()


def save_alerts_to_database(alerts: list[dict]) -> None:
    initialize_database()
    ensure_database_schema()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM incidents")

    now = datetime.utcnow().isoformat() + "Z"

    for index, alert in enumerate(alerts, start=1):
        incident_id = generate_incident_id(index)

        cursor.execute("""
            INSERT INTO incidents (
                incident_id,
                rule_id,
                title,
                severity,
                risk_score,
                user_name,
                user_role,
                department,
                source_ip,
                aws_region,
                event_time,
                description,
                evidence,
                recommended_action,
                analyst_summary,
                mitre_tactic,
                mitre_technique_id,
                mitre_technique_name,
                ip_type,
                ip_label,
                ip_reputation,
                business_hours,
                normal_region,
                unusual_region,
                user_risk,
                local_risk_notes,
                status,
                analyst_notes,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident_id,
            alert.get("rule_id", ""),
            alert.get("title", ""),
            alert.get("severity", ""),
            alert.get("risk_score", 0),
            alert.get("user_name", ""),
            alert.get("user_role", ""),
            alert.get("department", ""),
            alert.get("source_ip", ""),
            alert.get("aws_region", ""),
            alert.get("event_time", ""),
            alert.get("description", ""),
            alert.get("evidence", ""),
            alert.get("recommended_action", ""),
            alert.get("analyst_summary", ""),
            alert.get("mitre_tactic", ""),
            alert.get("mitre_technique_id", ""),
            alert.get("mitre_technique_name", ""),
            alert.get("ip_type", ""),
            alert.get("ip_label", ""),
            alert.get("ip_reputation", ""),
            alert.get("business_hours", ""),
            alert.get("normal_region", ""),
            alert.get("unusual_region", ""),
            alert.get("user_risk", ""),
            alert.get("local_risk_notes", ""),
            alert.get("status", "Open"),
            "",
            now,
            now
        ))

    conn.commit()
    conn.close()


def get_all_incidents() -> list[dict]:
    initialize_database()

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        ORDER BY risk_score DESC, event_time DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def get_incident_by_id(incident_id: str) -> dict | None:
    initialize_database()

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
    row = cursor.fetchone()

    conn.close()

    if row is None:
        return None

    return dict(row)


def update_incident(incident_id: str, status: str, analyst_notes: str) -> None:
    initialize_database()

    conn = get_connection()
    cursor = conn.cursor()

    now = datetime.utcnow().isoformat() + "Z"

    cursor.execute("""
        UPDATE incidents
        SET status = ?, analyst_notes = ?, updated_at = ?
        WHERE incident_id = ?
    """, (status, analyst_notes, now, incident_id))

    conn.commit()
    conn.close()
