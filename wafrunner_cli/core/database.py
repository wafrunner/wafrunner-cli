
import sqlite3
from pathlib import Path
from wafrunner_cli.core.config_manager import ConfigManager

class Database:
    """Handles all SQLite database operations."""

    def __init__(self):
        """Initializes the database connection."""
        config_manager = ConfigManager()
        db_path = config_manager.get_data_dir() / "wafrunner.db"
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self._create_table()

    def _create_table(self):
        """Creates the cve_lookup table if it doesn't exist."""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_lookup (
                cve_id TEXT PRIMARY KEY,
                vuln_id TEXT NOT NULL,
                last_modified TEXT
            )
        ''')
        self.conn.commit()

    def clear_cve_lookup(self):
        """Clears the cve_lookup table."""
        self.cursor.execute("DELETE FROM cve_lookup")
        self.conn.commit()

    def insert_cve_data(self, data: list[dict]):
        """
        Inserts a batch of CVE data into the cve_lookup table.

        Args:
            data: A list of dictionaries, where each dictionary has
                  'cve_id', 'vuln_id', and 'last_modified' keys.
        """
        self.cursor.executemany(
            "INSERT OR REPLACE INTO cve_lookup (cve_id, vuln_id, last_modified) VALUES (:cve_id, :vuln_id, :last_modified)",
            data
        )
        self.conn.commit()

    def close(self):
        """Closes the database connection."""
        self.conn.close()
