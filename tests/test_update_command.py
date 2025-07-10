import unittest
from unittest.mock import patch, MagicMock

from typer.testing import CliRunner

from wafrunner_cli.main import app

class TestUpdateCommand(unittest.TestCase):

    runner = CliRunner()

    @patch('wafrunner_cli.commands.update.ApiClient')
    @patch('wafrunner_cli.commands.update.Database')
    @patch('httpx.get')
    def test_update_success(self, mock_httpx_get, MockDatabase, MockApiClient):
        # Mock API client for download URL
        mock_api_instance = MockApiClient.return_value
        mock_api_instance.get_cve_lookup_download_url.return_value.status_code = 200
        mock_api_instance.get_cve_lookup_download_url.return_value.json.return_value = {
            "downloadUrl": "http://fake-url.com/cve.json"
        }

        # Mock httpx.get to return a fake response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "CVE-2024-0001": {"vulnID": "vuln-0001", "lastModified": "2024-01-01"}
        }
        mock_httpx_get.return_value = mock_response

        # Mock Database
        mock_db_instance = MockDatabase.return_value

        # Run the command
        result = self.runner.invoke(app, ["update"])

        # Assertions
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Successfully updated the CVE lookup data.", result.stdout)
        mock_db_instance.clear_cve_lookup.assert_called_once()
        mock_db_instance.insert_cve_data.assert_called_once()
        mock_db_instance.close.assert_called_once()

if __name__ == '__main__':
    unittest.main()