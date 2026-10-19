import unittest

import pandas as pd

from analyze_logs import analyze, classify_sessions, load_events, SAMPLE_DATASET


class AnalyticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frame = load_events(SAMPLE_DATASET)
        cls.results = analyze(cls.frame)

    def test_failed_login_filter(self):
        self.assertTrue(self.results["failed_logins"]["event_type"].eq("LOGIN_FAIL").all())
        self.assertEqual(len(self.results["failed_logins"]), 2)

    def test_login_categories_and_passwords(self):
        self.assertEqual(len(self.results["login_attempts"]), 6)
        self.assertEqual(len(self.results["rejected_auth"]), 2)
        self.assertEqual(self.results["top_passwords"].iloc[0]["password"], "123456")

    def test_top_ip_sort(self):
        self.assertEqual(self.results["top_ips"].iloc[0]["src_ip"], "192.0.2.77")
        self.assertTrue(self.results["top_ips"]["attempts"].is_monotonic_decreasing)

    def test_hour_aggregation(self):
        hourly = self.results["attacks_by_hour"].set_index("hour")["attempts"]
        self.assertEqual(int(hourly.loc[9]), 14)
        self.assertEqual(int(hourly.loc[18]), 7)
        self.assertEqual(set(range(24)), set(hourly.index))

    def test_password_sort(self):
        passwords = self.results["top_passwords"]
        self.assertEqual(passwords.iloc[0]["password"], "123456")
        self.assertTrue(passwords["attempts"].is_monotonic_decreasing)

    def test_reconnaissance_signals(self):
        signals = self.results["reconnaissance_signals"].set_index("event_type")
        self.assertEqual(int(signals.loc["SSH_PROBE", "signals"]), 1)
        self.assertEqual(int(signals.loc["TIMEOUT", "signals"]), 1)
        self.assertEqual(int(signals.loc["INVALID_REQUEST", "signals"]), 1)

    def test_session_ids_are_used(self):
        sessions = self.results["sessions"]
        self.assertEqual(set(sessions["session_id"]), {f"s-{number:03d}" for number in range(1, 7)})
        self.assertEqual(len(sessions), 6)

    def test_session_classification(self):
        frame = pd.DataFrame([
            {"timestamp": "2026-10-12T00:00:00Z", "src_ip": "1.1.1.1", "event_type": "CONNECT"},
            {"timestamp": "2026-10-12T00:00:01Z", "src_ip": "1.1.1.1", "event_type": "DISCONNECT"},
            {"timestamp": "2026-10-12T00:01:00Z", "src_ip": "2.2.2.2", "event_type": "CONNECT"},
            {"timestamp": "2026-10-12T00:01:01Z", "src_ip": "2.2.2.2", "event_type": "LOGIN_FAKE"},
            {"timestamp": "2026-10-12T00:01:02Z", "src_ip": "2.2.2.2", "event_type": "DISCONNECT"},
            {"timestamp": "2026-10-12T00:02:00Z", "src_ip": "3.3.3.3", "event_type": "CONNECT"},
            {"timestamp": "2026-10-12T00:02:01Z", "src_ip": "3.3.3.3", "event_type": "CMD"},
            {"timestamp": "2026-10-12T00:02:02Z", "src_ip": "3.3.3.3", "event_type": "DISCONNECT"},
        ])
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
        frame["_event_order"] = range(len(frame))
        categories = set(classify_sessions(frame)["category"])
        self.assertEqual(categories, {
            "reconnaissance_only", "credential_activity", "command_activity"
        })


if __name__ == "__main__":
    unittest.main()
