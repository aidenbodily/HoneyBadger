from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_DATABASE = PROJECT_DIR.parent / "SSHoneypot" / "attacks.db"
SAMPLE_DATASET = PROJECT_DIR / "sample_data" / "honeypot_logs.csv"
REQUIRED_COLUMNS = ["timestamp", "src_ip", "username", "password", "command"]


def load_events(input_path: Path) -> pd.DataFrame:
    """Load either the SSHoneypot SQLite database or a CSV export."""
    if input_path.suffix.lower() == ".csv":
        frame = pd.read_csv(input_path)
        # SSHoneypot exports use the SQLite column name; analytics uses the shorter `src_ip` name used throughout the report.
        if "src_ip" not in frame.columns and "source_ip" in frame.columns:
            frame = frame.rename(columns={"source_ip": "src_ip"})
    else:
        query = """
            SELECT timestamp, source_ip AS src_ip, username, password,
                   command, event_type
            FROM events
        """
        with sqlite3.connect(input_path) as connection:
            frame = pd.read_sql_query(query, connection)

    missing = set(REQUIRED_COLUMNS) - set(frame.columns)
    if missing:
        raise ValueError(f"Dataset is missing columns: {', '.join(sorted(missing))}")

    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    frame = frame.dropna(subset=["timestamp", "src_ip"]).copy()
    frame["src_ip"] = frame["src_ip"].astype(str)
    frame["_event_order"] = range(len(frame))
    frame["hour"] = frame["timestamp"].dt.hour
    frame["event_date"] = frame["timestamp"].dt.date
    return frame


def analyze(frame: pd.DataFrame) -> dict[str, pd.DataFrame]:
    """Return sorted rankings and grouped results used by the CLI and tests."""
    # FILTER: focus credential analysis on failed login attempts.
    failed_logins = frame[frame["event_type"].eq("LOGIN_FAIL")].copy()

    # SORT: rank the most active source IPs and most-tried passwords.
    top_ips = (
        frame.groupby("src_ip").size().reset_index(name="attempts")
        .sort_values(["attempts", "src_ip"], ascending=[False, True])
        .head(10)
    )
    password_rows = failed_logins["password"].dropna()
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
    return {
        "failed_logins": failed_logins,
        "top_ips": top_ips,
        "top_passwords": top_passwords,
        "attacks_by_hour": attacks_by_hour,
        "attacks_by_day": attacks_by_day,
        "sessions": sessions,
    }


def classify_sessions(frame: pd.DataFrame) -> pd.DataFrame:
    """Classify CONNECT/DISCONNECT sessions by the activity they contain."""
    sessions = []
    open_sessions: dict[str, list[dict]] = {}
    ordered = frame.sort_values(["timestamp", "_event_order"])

    for _, row in ordered.iterrows():
        source_ip = row["src_ip"]
        event_type = row.get("event_type")
        if event_type == "CONNECT":
            session = {
                "src_ip": source_ip,
                "started_at": row["timestamp"],
                "ended_at": pd.NaT,
                "events": [],
            }
            sessions.append(session)
            open_sessions.setdefault(source_ip, []).append(session)
        elif event_type == "DISCONNECT":
            active = open_sessions.get(source_ip, [])
            if active:
                active.pop()["ended_at"] = row["timestamp"]
        else:
            active = open_sessions.get(source_ip, [])
            if active:
                active[-1]["events"].append(event_type)

    if not sessions:
        return pd.DataFrame(columns=["src_ip", "started_at", "ended_at", "category"])

    records = []
    for number, session in enumerate(sessions, start=1):
        event_types = set(session["events"])
        if "CMD" in event_types:
            category = "command_activity"
        elif any(event.startswith("LOGIN") for event in event_types):
            category = "credential_activity"
        else:
            category = "reconnaissance_only"
        records.append({
            "session": number,
            "src_ip": session["src_ip"],
            "started_at": session["started_at"],
            "ended_at": session["ended_at"],
            "category": category,
        })
    return pd.DataFrame(records)


def create_charts(frame: pd.DataFrame, results: dict[str, pd.DataFrame], output_dir: Path) -> None:
    """Write a timeline and top-password bar chart for the demo."""
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
    print(f"Failed-login filter: {len(results['failed_logins'])} failed login(s)")
    print("\nWhich source IPs attack most:")
    print(top_ips.to_string(index=False) if not top_ips.empty else "No events found.")
    print(f"\nWhat time of day do attacks peak:\n"
          f"Peak hour: {int(peak['hour']):02d}:00 UTC ({int(peak['attempts'])} event(s))")
    print("\nHourly aggregation:")
    print(by_hour[by_hour["attempts"].gt(0)].to_string(index=False))
    if results["top_passwords"].empty:
        print("\nPassword ranking: no values available; SSHoneypot redacts passwords by default.")
    else:
        print("\nTop failed-login passwords:")
        print(results["top_passwords"].to_string(index=False))

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
