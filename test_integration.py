import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

try:
    import paramiko
except ModuleNotFoundError:  # The integration test runs when SSHoneypot deps exist.
    paramiko = None

from analyze_logs import analyze, load_events


PROJECT_DIR = Path(__file__).resolve().parent
SERVER = PROJECT_DIR.parent / "SSHoneypot" / "server.py"


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@unittest.skipIf(paramiko is None, "Paramiko is not installed")
class HoneyBadgerSSHIntegrationTest(unittest.TestCase):
    def test_real_ssh_passwords_are_ranked(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            database = directory / "attacks.db"
            port = unused_port()
            process = subprocess.Popen(
                [
                    sys.executable, "-u", str(SERVER),
                    "--host", "127.0.0.1", "--port", str(port),
                    "--database", str(database),
                    "--host-key", str(directory / "host-key"),
                    "--store-passwords", "--idle-timeout", "1",
                ],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            try:
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        self.fail(process.communicate()[0])
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.03)
                else:
                    self.fail("SSHoneypot did not begin listening")

                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    "127.0.0.1", port=port, username="root", password="hunter2",
                    allow_agent=False, look_for_keys=False, timeout=2,
                    banner_timeout=2, auth_timeout=2,
                )
                client.close()

                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    with sqlite3.connect(database) as connection:
                        stored = connection.execute(
                            "SELECT COUNT(*) FROM events WHERE event_type = 'LOGIN_FAKE'"
                        ).fetchone()[0]
                    if stored:
                        break
                    time.sleep(0.03)
                result = analyze(load_events(database))
                self.assertEqual(result["login_attempts"].shape[0], 1)
                self.assertEqual(result["top_passwords"].iloc[0]["password"], "hunter2")
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.communicate(timeout=4)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate()


if __name__ == "__main__":
    unittest.main()
