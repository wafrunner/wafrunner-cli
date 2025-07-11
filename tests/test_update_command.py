import unittest
from unittest.mock import patch, MagicMock, mock_open
from typer.testing import CliRunner
import json

from wafrunner_cli.main import app


class TestUpdateCommand(unittest.TestCase):
    runner = CliRunner()

    @patch("wafrunner_cli.commands.update.ApiClient")
    @patch("wafrunner_cli.commands.update.Database")
    @patch("httpx.get")
    def test_update_success_no_new_cves(
        self, mock_httpx_get, MockDatabase, MockApiClient
    ):
        mock_api_instance = MockApiClient.return_value
        mock_api_instance.get_cve_lookup_download_url.return_value.json.return_value = {
            "downloadUrl": "http://fake-url.com/cve.json"
        }
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "CVE-2024-0001": {"vulnID": "vuln-0001", "lastModified": "2024-01-01"}
        }
        mock_httpx_get.return_value = mock_response
        mock_db_instance = MockDatabase.return_value
        mock_cursor = mock_db_instance.cursor
        mock_cursor.fetchall.return_value = [("CVE-2024-0001",)]
        mock_cursor.fetchone.side_effect = [(1,), (1,)]

        result = self.runner.invoke(app, ["update"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Added 0 new vulnerabilities", result.stdout)

    @patch("wafrunner_cli.commands.update.ApiClient")
    @patch("wafrunner_cli.commands.update.Database")
    @patch("httpx.get")
    def test_update_success_with_new_cves_verbose(
        self, mock_httpx_get, MockDatabase, MockApiClient
    ):
        mock_api_instance = MockApiClient.return_value
        mock_api_instance.get_cve_lookup_download_url.return_value.json.return_value = {
            "downloadUrl": "http://fake-url.com/cve.json"
        }
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "CVE-2024-0001": {"vulnID": "vuln-0001", "lastModified": "2024-01-01"},
            "CVE-2024-0002": {"vulnID": "vuln-0002", "lastModified": "2024-01-02"},
        }
        mock_httpx_get.return_value = mock_response
        mock_db_instance = MockDatabase.return_value
        mock_cursor = mock_db_instance.cursor
        mock_cursor.fetchall.return_value = [("CVE-2024-0001",)]
        mock_cursor.fetchone.return_value = (2,)

        result = self.runner.invoke(app, ["update", "--verbose"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Added 1 new vulnerabilities", result.stdout)
        self.assertIn("New CVEs:", result.stdout)
        self.assertIn("CVE-2024-0002", result.stdout)

    @patch("wafrunner_cli.commands.update.ApiClient")
    @patch("wafrunner_cli.commands.update.Database")
    @patch("httpx.get")
    @patch("builtins.open", new_callable=mock_open)
    @patch("wafrunner_cli.commands.update.Path.exists")
    def test_update_and_save_to_collection_named(
        self, mock_exists, mock_open_file, mock_httpx_get, MockDatabase, MockApiClient
    ):
        mock_exists.return_value = False
        mock_api_instance = MockApiClient.return_value
        mock_api_instance.get_cve_lookup_download_url.return_value.json.return_value = {
            "downloadUrl": "http://fake-url.com/cve.json"
        }
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "CVE-2024-0003": {"vulnID": "vuln-0003", "lastModified": "2024-01-03"}
        }
        mock_httpx_get.return_value = mock_response
        mock_db_instance = MockDatabase.return_value
        mock_cursor = mock_db_instance.cursor
        mock_cursor.fetchall.return_value = []
        mock_cursor.fetchone.side_effect = [(0,), (1,)]

        result = self.runner.invoke(
            app, ["update", "--save-to-collection", "--name", "my_new_cves"]
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Collection 'my_new_cves' created", result.stdout)
        mock_open_file.assert_called_once()
        handle = mock_open_file()
        written_data = "".join(call[0][0] for call in handle.write.call_args_list)
        saved_collection = json.loads(written_data)
        self.assertEqual(saved_collection["name"], "my_new_cves")
        self.assertEqual(len(saved_collection["vulnerabilities"]), 1)
        self.assertEqual(
            saved_collection["vulnerabilities"][0]["cve_id"], "CVE-2024-0003"
        )

    @patch("wafrunner_cli.commands.update.ApiClient")
    @patch("wafrunner_cli.commands.update.Database")
    @patch("httpx.get")
    @patch("builtins.open", new_callable=mock_open)
    @patch("wafrunner_cli.commands.update.Path.exists")
    @patch("wafrunner_cli.commands.update.datetime")
    def test_update_and_save_to_collection_default_name(
        self,
        mock_datetime,
        mock_exists,
        mock_open_file,
        mock_httpx_get,
        MockDatabase,
        MockApiClient,
    ):
        mock_exists.return_value = False
        mock_dt = MagicMock()
        mock_dt.now.return_value.strftime.return_value = "20250711_120000"
        mock_datetime.now.return_value.isoformat.return_value = (
            "2025-07-11T12:00:00+00:00"
        )
        mock_datetime.now.return_value.strftime = mock_dt.now.return_value.strftime

        mock_api_instance = MockApiClient.return_value
        mock_api_instance.get_cve_lookup_download_url.return_value.json.return_value = {
            "downloadUrl": "http://fake-url.com/cve.json"
        }
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "CVE-2024-0004": {"vulnID": "vuln-0004", "lastModified": "2024-01-04"}
        }
        mock_httpx_get.return_value = mock_response
        mock_db_instance = MockDatabase.return_value
        mock_cursor = mock_db_instance.cursor
        mock_cursor.fetchall.return_value = []
        mock_cursor.fetchone.side_effect = [(0,), (1,)]

        result = self.runner.invoke(app, ["update", "--save-to-collection"])

        self.assertEqual(result.exit_code, 0)
        expected_name = "new_cves_20250711_120000"
        self.assertIn(f"Collection '{expected_name}' created", result.stdout)
        mock_open_file.assert_called_once()
        handle = mock_open_file()
        written_data = "".join(call[0][0] for call in handle.write.call_args_list)
        saved_collection = json.loads(written_data)
        self.assertEqual(saved_collection["name"], expected_name)

    def test_name_without_save_option_fails(self):
        result = self.runner.invoke(app, ["update", "--name", "should_fail"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn(
            "--name can only be used with --save-to-collection", result.stdout
        )


if __name__ == "__main__":
    unittest.main()
