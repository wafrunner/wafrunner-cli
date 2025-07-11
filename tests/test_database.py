import unittest
import sqlite3

from wafrunner_cli.core.database import Database


class TestDatabase(unittest.TestCase):

    def setUp(self):
        # Use an in-memory database for testing
        self.db = Database()
        self.db.conn = sqlite3.connect(":memory:")
        self.db.cursor = self.db.conn.cursor()
        self.db._create_table()

    def tearDown(self):
        self.db.close()

    def test_create_table(self):
        # Check if the table was created
        self.db.cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='cve_lookup'"
        )
        self.assertIsNotNone(self.db.cursor.fetchone())

    def test_insert_and_clear_cve_data(self):
        # Test inserting data
        sample_data = [
            {
                "cve_id": "CVE-2024-0001",
                "vuln_id": "vuln-0001",
                "last_modified": "2024-01-01",
            },
            {
                "cve_id": "CVE-2024-0002",
                "vuln_id": "vuln-0002",
                "last_modified": "2024-01-02",
            },
        ]
        self.db.insert_cve_data(sample_data)

        # Verify data is inserted
        self.db.cursor.execute("SELECT * FROM cve_lookup")
        rows = self.db.cursor.fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], "CVE-2024-0001")

        # Test clearing data
        self.db.clear_cve_lookup()
        self.db.cursor.execute("SELECT * FROM cve_lookup")
        self.assertEqual(len(self.db.cursor.fetchall()), 0)


if __name__ == "__main__":
    unittest.main()
