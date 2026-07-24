import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from marketplace.db import (
    INITIAL_BALANCE,
    allow_action,
    connect,
    ensure_admin,
    init_database,
    seed_demo,
)


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary_directory.name) / "test.db"
        self.previous_db = os.environ.get("MARKET_DB_PATH")
        self.previous_admin_password = os.environ.get("ADMIN_PASSWORD")
        os.environ["MARKET_DB_PATH"] = str(self.path)
        os.environ["ADMIN_PASSWORD"] = "SecureRoot2026!"
        init_database()

    def tearDown(self):
        if self.previous_db is None:
            os.environ.pop("MARKET_DB_PATH", None)
        else:
            os.environ["MARKET_DB_PATH"] = self.previous_db
        if self.previous_admin_password is None:
            os.environ.pop("ADMIN_PASSWORD", None)
        else:
            os.environ["ADMIN_PASSWORD"] = self.previous_admin_password
        self.temporary_directory.cleanup()

    def test_schema_and_admin_creation_are_idempotent(self):
        credentials = ensure_admin()
        self.assertEqual(credentials, ("admin", "SecureRoot2026!"))
        self.assertIsNone(ensure_admin())
        connection = connect()
        try:
            user = connection.execute(
                "SELECT role, balance FROM users WHERE username = 'admin'"
            ).fetchone()
            self.assertEqual(user["role"], "admin")
            self.assertEqual(user["balance"], INITIAL_BALANCE)
            transfer_columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(transfers)"
                ).fetchall()
            }
            self.assertIn("request_token_hash", transfer_columns)
        finally:
            connection.close()
        self.assertEqual(self.path.stat().st_mode & 0o077, 0)

    def test_demo_seed_is_idempotent(self):
        ensure_admin()
        seed_demo()
        seed_demo()
        connection = connect()
        try:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM users").fetchone()[0], 3
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM products").fetchone()[0], 3
            )
        finally:
            connection.close()

    def test_database_constraints_reject_negative_balance(self):
        ensure_admin()
        connection = connect()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE users SET balance = -1 WHERE username = 'admin'"
                )
        finally:
            connection.close()

    def test_persistent_action_limit(self):
        self.assertTrue(allow_action("signup_ip", "127.0.0.1", 2, 3600))
        self.assertTrue(allow_action("signup_ip", "127.0.0.1", 2, 3600))
        self.assertFalse(allow_action("signup_ip", "127.0.0.1", 2, 3600))


if __name__ == "__main__":
    unittest.main()
