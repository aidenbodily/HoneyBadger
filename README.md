# HoneyBadger

HoneyBadger is a Python data analytics program that analyzes SSH honeypot logs
with Pandas and Matplotlib. It identifies common attack patterns and presents
the results as printed reports and charts for basic SOC analysis.

## Instructions for Build and Use

Steps to build and/or run the software:

1. Install Python 3.11 or newer.
2. Open a terminal in this folder.
3. Install the required libraries:

   ```bash
   python3 -m pip install -r requirements.txt
   ```

4. Run the analyzer:

   ```bash
   python3 analyze_logs.py
   ```

Instructions for using the software:

1. Place a honeypot CSV export in `data/events.csv`, or provide a SQLite
   database with the `--input` option.
2. Run the analyzer with the selected dataset:

   ```bash
   python3 analyze_logs.py --input data/events.csv
   ```

3. Review the printed results and the charts saved in the `charts` folder.

If no live database is available, the program uses the included demo dataset
at `sample_data/honeypot_logs.csv`.

HoneyBadger answers these questions:

1. Which source IPs generate the most logged events?
2. What hour of the day has the most activity?
3. What percentage of connections are reconnaissance-only versus credential or
   command activity?
4. How many accepted fake-shell login attempts and rejected authentication
   attempts occurred?
5. Which passwords were submitted across both accepted and rejected attempts?
6. How many SSH probes, timeouts, and invalid requests indicate reconnaissance?

The analysis demonstrates the following operations:

* Separate accepted fake-shell logins (`LOGIN_FAKE`) from rejected auth
  (`LOGIN_FAIL`) and rank passwords from both event types when present.
* Sort source IPs and passwords by attempt count.
* Aggregate events by hour with Pandas `groupby()`.
* Group modern events by `session_id`, while pairing legacy/CSV events by IP
  and row order when session IDs are unavailable.
* Read duration and disconnect reason from the SQLite `sessions` table when it
  exists, and count SSH probes, timeouts, and invalid requests as signals.
* Graph the attack timeline and password rankings with Matplotlib.

Run the automated tests with:

```bash
python3 -m unittest -v test_analyze_logs.py
```

## Development Environment

To recreate the development environment, you need the following software
and/or libraries with the specified versions:

* Python 3.11 or newer
* Pandas 2.0 or newer
* Matplotlib 3.7 or newer
* Paramiko 5.0.0 for the end-to-end SSH integration test
* Any text editor or IDE, such as Visual Studio Code
* A CSV honeypot export or SQLite honeypot database

## Useful Websites to Learn More

I found these websites useful in developing this software:

* [Python Official Documentation](https://docs.python.org/3/)
* [Pandas Documentation](https://pandas.pydata.org/docs/)
* [Pandas GroupBy Documentation](https://pandas.pydata.org/docs/reference/groupby.html)
* [Matplotlib Documentation](https://matplotlib.org/stable/contents.html)
* [Python SQLite Documentation](https://docs.python.org/3/library/sqlite3.html)

## Future Work

The following items I plan to fix, improve, and/or add to this project in the future:

* [x] Add explicit session IDs to the honeypot event records.
* [x] Analyze session duration and disconnect reasons.
* [ ] Add source IP enrichment such as network ownership or geolocation.
* [x] Add reconnaissance-signal counts and an end-to-end SSH integration test.
* [ ] Add additional charts for daily activity and repeated scanners.
* [ ] Compare attempted credentials against a safe, approved wordlist.
