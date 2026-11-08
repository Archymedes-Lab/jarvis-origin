import os
import sqlite3
import tempfile
import unittest

from jarvis_origin import inputwatch
from jarvis_origin.store import Store
from jarvis_origin.util import now


class TypingWindowTests(unittest.TestCase):
    def test_punctuation_concentration_is_detected_without_key_content(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, "jarvis_origin.db"))
            try:
                store.db.execute(
                    "INSERT INTO input_typing_windows "
                    "(ts,real_keys,real_key_gaps,equals_keys) VALUES(?,?,?,?)",
                    (now(), 40, 39, 22),
                )
                findings = inputwatch._typing_findings(store, None)
                finding = next(f for f in findings if "equals/plus" in f["title"])
                self.assertEqual(finding["severity"], "low")
                columns = {row[1] for row in store.db.execute(
                    "PRAGMA table_info(input_typing_windows)")}
                self.assertNotIn("key", columns)
                self.assertNotIn("text", columns)
                self.assertNotIn("character", columns)
            finally:
                store.close()

    def test_existing_typing_table_gets_new_punctuation_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "old.db")
            db = sqlite3.connect(path)
            db.execute(
                "CREATE TABLE input_typing_windows ("
                "ts INTEGER PRIMARY KEY, real_keys INTEGER NOT NULL DEFAULT 0, "
                "injected_keys INTEGER NOT NULL DEFAULT 0, "
                "real_key_gaps INTEGER NOT NULL DEFAULT 0, "
                "real_key_sub20 INTEGER NOT NULL DEFAULT 0, "
                "real_key_sub8 INTEGER NOT NULL DEFAULT 0, "
                "cad_run_max INTEGER NOT NULL DEFAULT 0)"
            )
            db.commit()
            db.close()

            store = Store(path)
            try:
                columns = {row[1] for row in store.db.execute(
                    "PRAGMA table_info(input_typing_windows)")}
                self.assertTrue({"equals_keys", "slash_keys", "period_keys"} <= columns)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
