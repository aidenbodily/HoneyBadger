# HoneyBadger — Honeypot Log Analytics

HoneyBadger is the Sprint 2 data analytics module for the SSH honeypot. It
uses Pandas to turn Sprint 1 SQLite events into SOC-style answers and uses
Matplotlib to create charts.

## Requirements

```bash
python3 -m pip install -r requirements.txt
```

## Run the demo

From this folder:

```bash
python3 analyze_logs.py
```

If `../SSHoneypot/attacks.db` exists, the script analyzes it. Otherwise, it
uses `sample_data/honeypot_logs.csv` so the project can be demonstrated without
waiting for live honeypot traffic.

To analyze a specific database or CSV export:

```bash
python3 analyze_logs.py --input ../SSHoneypot/attacks.db
python3 analyze_logs.py --input sample_data/honeypot_logs.csv
```

The script answers:

1. Which source IPs generate the most logged events?
2. What hour of the day has the most activity?

It also demonstrates the required operations:

- **Filter:** keep only `LOGIN_FAIL` events for credential analysis.
- **Sort:** rank the top 10 source IPs and failed-login passwords by count.
- **Aggregation:** group all events by hour of day with `groupby("hour")`.
- **Stretch:** save `charts/attack_timeline.png` and
  `charts/top_passwords.png` with Matplotlib.

The Sprint 1 server redacts passwords unless it is deliberately started with
`--store-passwords`. When passwords are redacted, HoneyBadger still analyzes
IP, time, username, command, and event-type patterns and explains why the
password chart has no values.

Run tests with:

```bash
python3 -m unittest -v test_analyze_logs.py
```
