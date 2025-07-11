import unittest
from unittest.mock import patch

from wafrunner_cli.core import lookup_service


class TestLookupService(unittest.TestCase):

    @patch("wafrunner_cli.core.lookup_service.Database")
    def test_get_vuln_id(self, MockDatabase):
        # Setup mock database
        mock_db_instance = MockDatabase.return_value
        mock_cursor = mock_db_instance.cursor
        mock_cursor.fetchone.return_value = ("a1ddadd4-1b9d-4fab-90fe-64c1c763cd58",)

        # Call the function with a valid CVE ID
        vuln_id = lookup_service.get_vuln_id("CVE-2024-1234")
        self.assertEqual(vuln_id, "a1ddadd4-1b9d-4fab-90fe-64c1c763cd58")

        # Call with an invalid CVE ID
        vuln_id_invalid = lookup_service.get_vuln_id("invalid-cve")
        self.assertIsNone(vuln_id_invalid)

    @patch("wafrunner_cli.core.lookup_service.Database")
    def test_get_cve_id(self, MockDatabase):
        # Setup mock database
        mock_db_instance = MockDatabase.return_value
        mock_cursor = mock_db_instance.cursor
        mock_cursor.fetchone.return_value = ("CVE-2024-5678",)

        # Call the function with a valid vuln ID
        cve_id = lookup_service.get_cve_id("a1ddadd4-1b9d-4fab-90fe-64c1c763cd58")
        self.assertEqual(cve_id, "CVE-2024-5678")

        # Call with an invalid vuln ID
        cve_id_invalid = lookup_service.get_cve_id("invalid-vuln-id")
        self.assertIsNone(cve_id_invalid)

    @patch("wafrunner_cli.core.lookup_service.get_vuln_id")
    def test_lookup_ids_with_cve(self, mock_get_vuln_id):
        mock_get_vuln_id.return_value = "vuln-from-cve"

        result = lookup_service.lookup_ids("CVE-2024-1111")
        self.assertEqual(
            result, {"cve_id": "CVE-2024-1111", "vuln_id": "vuln-from-cve"}
        )

    @patch("wafrunner_cli.core.lookup_service.get_cve_id")
    def test_lookup_ids_with_vuln_id(self, mock_get_cve_id):
        mock_get_cve_id.return_value = "cve-from-vuln"

        result = lookup_service.lookup_ids("a1ddadd4-1b9d-4fab-90fe-64c1c763cd58")
        self.assertEqual(
            result,
            {
                "cve_id": "cve-from-vuln",
                "vuln_id": "a1ddadd4-1b9d-4fab-90fe-64c1c763cd58",
            },
        )

    def test_lookup_ids_not_found(self):
        with patch("wafrunner_cli.core.lookup_service.get_vuln_id", return_value=None):
            result = lookup_service.lookup_ids("CVE-2024-4040")
            self.assertIsNone(result)

    def test_lookup_ids_invalid_format(self):
        result = lookup_service.lookup_ids("invalid-format")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
