
import unittest
from unittest.mock import patch, MagicMock

from typer.testing import CliRunner

from wafrunner_cli.main import app

class TestResearchCommands(unittest.TestCase):

    runner = CliRunner()

    @patch('wafrunner_cli.commands.research.lookup_ids')
    @patch('wafrunner_cli.commands.research.ApiClient')
    def test_github_with_id(self, MockApiClient, mock_lookup_ids):
        # Mock the lookup service to return a valid response
        mock_lookup_ids.return_value = {'cve_id': 'CVE-2024-1234', 'vuln_id': 'vuln-1234'}

        # Mock the API client to avoid actual API calls
        mock_api_instance = MockApiClient.return_value
        mock_api_instance.get.return_value.status_code = 200
        mock_api_instance.get.return_value.json.return_value = {"github_searches": []}
        mock_api_instance.post.return_value.status_code = 200

        # Run the command with a CVE ID
        result = self.runner.invoke(app, ["research", "github", "--id", "CVE-2024-1234"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Found 1 vulnerability ID(s) to process.", result.stdout)

        # Run the command with a vuln ID
        result = self.runner.invoke(app, ["research", "github", "--id", "vuln-1234"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Found 1 vulnerability ID(s) to process.", result.stdout)

    @patch('wafrunner_cli.commands.research.lookup_ids')
    def test_github_with_invalid_id(self, mock_lookup_ids):
        # Mock the lookup service to return None
        mock_lookup_ids.return_value = None

        # Run the command with an invalid ID
        result = self.runner.invoke(app, ["research", "github", "--id", "invalid-id"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Could not resolve identifier: invalid-id", result.stdout)

if __name__ == '__main__':
    unittest.main()
