from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_DATABASE = PROJECT_DIR.parent / "SSHoneypot" / "attacks.db"
SAMPLE_DATASET = PROJECT_DIR / "sample_data" / "honeypot_logs.csv"
REQUIRED_COLUMNS = [
    "timestamp", "src_ip", "username", "password", "command", "event_type"
]


def load_events(input_path: Path) -> pd.DataFrame:
    """Load either the SSHoneypot SQLite database or a CSV export."""
    if input_path.suffix.lower() == ".csv":
        frame = pd.read_csv(input_path)
        # SSHoneypot exports use the SQLite column name; analytics uses the shorter `src_ip` name used throughout the report.
        if "src_ip" not in frame.columns and "source_ip" in frame.columns:
            frame = frame.rename(columns={"source_ip": "src_ip"})
        session_metadata = pd.DataFrame()
    else:
        with sqlite3.connect(input_path) as connection:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(events)")
            }
            session_column = ", session_id" if "session_id" in columns else ""
            frame = pd.read_sql_query(
                f"""SELECT timestamp, source_ip AS src_ip, username, password,
                           command, event_type{session_column}
                    FROM events""",
                connection,
            )
            if "sessions" in {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }:
                session_metadata = pd.read_sql_query(
                    "SELECT * FROM sessions", connection
                )

    missing = set(REQUIRED_COLUMNS) - set(frame.columns)
    if missing:
        raise ValueError(f"Dataset is missing columns: {', '.join(sorted(missing))}")

    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    frame = frame.dropna(subset=["timestamp", "src_ip"]).copy()
    frame["src_ip"] = frame["src_ip"].astype(str)
    if "session_id" not in frame.columns:
        frame["session_id"] = pd.NA
    frame["session_id"] = frame["session_id"].where(
        frame["session_id"].notna()
        & frame["session_id"].astype("string").str.strip().ne(""),
        pd.NA,
    )
    frame["_event_order"] = range(len(frame))
    frame["hour"] = frame["timestamp"].dt.hour
    frame["event_date"] = frame["timestamp"].dt.date
    frame.attrs["session_metadata"] = session_metadata
    return frame


def analyze(frame: pd.DataFrame) -> dict[str, pd.DataFrame]:
    """Return sorted rankings and grouped results used by the CLI and tests."""
    login_attempts = frame[frame["event_type"].eq("LOGIN_FAKE")].copy()
    rejected_auth = frame[frame["event_type"].eq("LOGIN_FAIL")].copy()

    # SORT: rank the most active source IPs and most-tried passwords.
    top_ips = (
        frame.groupby("src_ip").size().reset_index(name="attempts")
        .sort_values(["attempts", "src_ip"], ascending=[False, True])
        .head(10)
    )
    password_rows = frame.loc[
        frame["event_type"].isin(["LOGIN_FAKE", "LOGIN_FAIL"]), "password"
    ].dropna()
    password_rows = password_rows[password_rows.astype(str).str.strip().ne("")]
    top_passwords = (
        password_rows.astype(str).value_counts().rename_axis("password")
        .reset_index(name="attempts").head(10)
    )

    # AGGREGATION: count all logged events by hour of day.
    attacks_by_hour = (
        frame.groupby("hour").size().reindex(range(24), fill_value=0)
        .rename("attempts").reset_index()
    )
    attacks_by_day = (
        frame.groupby("event_date").size().rename("attempts").reset_index()
    )
    sessions = classify_sessions(frame)
    reconnaissance_signals = (
        frame[frame["event_type"].isin(["SSH_PROBE", "TIMEOUT", "INVALID_REQUEST"])]
        .groupby("event_type")
        .size()
        .reindex(["SSH_PROBE", "TIMEOUT", "INVALID_REQUEST"], fill_value=0)
        .rename("signals")
        .reset_index()
    )
    return {
        "failed_logins": rejected_auth,
        "login_attempts": login_attempts,
        "rejected_auth": rejected_auth,
        "top_ips": top_ips,
        "top_passwords": top_passwords,
        "attacks_by_hour": attacks_by_hour,
        "attacks_by_day": attacks_by_day,
        "sessions": sessions,
        "reconnaissance_signals": reconnaissance_signals,
    }


def classify_sessions(frame: pd.DataFrame) -> pd.DataFrame:
    """Classify sessions by ID, with an IP/row-order fallback for legacy data."""
    sessions = []
    open_sessions: dict[str, list[dict]] = {}
    ordered = frame.sort_values(["timestamp", "_event_order"])

    def new_session(row, session_id=None):
        session = {
            "session_id": session_id,
            "src_ip": row["src_ip"],
            "started_at": row["timestamp"],
            "ended_at": pd.NaT,
            "duration_seconds": None,
            "disconnect_reason": None,
            "events": [],
        }
        sessions.append(session)
        return session

    for _, row in ordered.iterrows():
        source_ip = row["src_ip"]
        event_type = row.get("event_type")
        session_id = row.get("session_id")
        if pd.notna(session_id):
            key = str(session_id)
            session = open_sessions.setdefault(key, [None])[-1]
            if session is None:
                session = new_session(row, key)
                open_sessions[key][-1] = session
            if event_type == "CONNECT":
                session["started_at"] = row["timestamp"]
            elif event_type == "DISCONNECT":
                session["ended_at"] = row["timestamp"]
            else:
                session["events"].append(event_type)
            continue

        if event_type == "CONNECT":
            session = new_session(row)
            open_sessions.setdefault(source_ip, []).append(session)
        elif event_type == "DISCONNECT":
            active = open_sessions.get(source_ip, [])
            if active:
                active.pop()["ended_at"] = row["timestamp"]
        else:
            active = open_sessions.get(source_ip, [])
            if active:
                active[-1]["events"].append(event_type)

    metadata = frame.attrs.get("session_metadata", pd.DataFrame())
    metadata_by_id = (
        metadata.set_index("session_id").to_dict("index")
        if not metadata.empty and "session_id" in metadata.columns
        else {}
    )

    records = []
    for number, session in enumerate(sessions, start=1):
        details = metadata_by_id.get(session["session_id"], {})
        for key in ("started_at", "ended_at", "duration_seconds", "disconnect_reason"):
            if details.get(key) is not None:
                session[key] = details[key]
        event_types = set(session["events"])
        if "CMD" in event_types:
            category = "command_activity"
        elif any(event.startswith("LOGIN") for event in event_types):
            category = "credential_activity"
        else:
            category = "reconnaissance_only"
        records.append({
            "session": number,
            "session_id": session["session_id"],
            "src_ip": session["src_ip"],
            "started_at": session["started_at"],
            "ended_at": session["ended_at"],
            "duration_seconds": session["duration_seconds"],
            "disconnect_reason": session["disconnect_reason"],
            "category": category,
        })
    return pd.DataFrame(records)


def create_charts(frame: pd.DataFrame, results: dict[str, pd.DataFrame], output_dir: Path) -> None:
    """Write a timeline and top-password bar chart for the demo."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    output_dir.mkdir(parents=True, exist_ok=True)

    hourly_timeline = frame.set_index("timestamp").resample("h").size()
    fig, axis = plt.subplots(figsize=(10, 4.5))
    axis.plot(hourly_timeline.index, hourly_timeline.values, marker="o", linewidth=1.5)
    axis.set_title("HoneyBadger Attack Timeline")
    axis.set_xlabel("UTC timestamp")
    axis.set_ylabel("Logged events")
    axis.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig(output_dir / "attack_timeline.png", dpi=150)
    plt.close(fig)

    fig, axis = plt.subplots(figsize=(8, 4.5))
    passwords = results["top_passwords"].copy()
    if passwords.empty:
        axis.text(0.5, 0.5, "No password values available\n(passwords may be redacted)",
                  ha="center", va="center")
        axis.set_axis_off()
    else:
        passwords = passwords.sort_values("attempts")
        axis.barh(passwords["password"], passwords["attempts"], color="#d99a29")
        axis.set_title("Top Failed-Login Passwords")
        axis.set_xlabel("Attempts")
    fig.tight_layout()
    fig.savefig(output_dir / "top_passwords.png", dpi=150)
    plt.close(fig)


def print_report(results: dict[str, pd.DataFrame]) -> None:
    """Print concise answers for the demonstration video."""
    top_ips = results["top_ips"]
    by_hour = results["attacks_by_hour"]
    peak = by_hour.loc[by_hour["attempts"].idxmax()]
    print(
        f"Login attempts: {len(results['login_attempts'])} | "
        f"Rejected auth: {len(results['rejected_auth'])}"
    )
    print("\nWhich source IPs attack most:")
    print(top_ips.to_string(index=False) if not top_ips.empty else "No events found.")
    print(f"\nWhat time of day do attacks peak:\n"
          f"Peak hour: {int(peak['hour']):02d}:00 UTC ({int(peak['attempts'])} event(s))")
    print("\nHourly aggregation:")
    print(by_hour[by_hour["attempts"].gt(0)].to_string(index=False))
    if results["top_passwords"].empty:
        print("\nPassword ranking: no values available; all recorded passwords are redacted.")
    else:
        print("\nTop passwords from login attempts and rejected auth:")
        print(results["top_passwords"].to_string(index=False))

    print("\nReconnaissance signals:")
    print(results["reconnaissance_signals"].to_string(index=False))

    sessions = results["sessions"]
    print("\nWhat percentage of connections are reconnaissance-only "
          "versus credential or command activity:")
    if sessions.empty:
        print("No CONNECT/DISCONNECT session events were found.")
    else:
        summary = (sessions["category"].value_counts()
                   .rename_axis("category").reset_index(name="connections"))
        summary["percent"] = (summary["connections"] / len(sessions) * 100).round(1)
        print(f"Connections analyzed: {len(sessions)}")
        print(summary.to_string(index=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze HoneyBadger honeypot logs")
    parser.add_argument("--input", type=Path, help="SQLite database or CSV dataset")
    parser.add_argument("--output-dir", type=Path, default=PROJECT_DIR / "charts")
    args = parser.parse_args()

    input_path = args.input or DEFAULT_DATABASE
    using_sample = not input_path.exists()
    if using_sample:
        input_path = SAMPLE_DATASET
        print(f"Live database not found; using demo dataset: {input_path}")
    frame = load_events(input_path)
    results = analyze(frame)
    print_report(results)
    create_charts(frame, results, args.output_dir)
    print(f"\nCharts saved to: {args.output_dir}")


if __name__ == "__main__":
    main()
