import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from wafrunner_cli.main import app


class TestResearchCommands(unittest.TestCase):

    runner = CliRunner()

    @patch("wafrunner_cli.commands.research.lookup_ids")
    @patch("wafrunner_cli.commands.research.ApiClient")
    def test_github_with_id(self, MockApiClient, mock_lookup_ids):
        # Mock the lookup service to return a valid response
        mock_lookup_ids.return_value = {
            "cve_id": "CVE-2024-1234",
            "vuln_id": "vuln-1234",
        }

        # Mock the API client to avoid actual API calls
        mock_api_instance = MockApiClient.return_value
        mock_api_instance.get.return_value.status_code = 200
        json_return_value = {"github_searches": []}
        mock_api_instance.get.return_value.json.return_value = json_return_value
        mock_api_instance.post.return_value.status_code = 200

        # Run the command with a CVE ID
        result = self.runner.invoke(
            app,
            ["research", "github", "--id", "CVE-2024-1234"],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn(
            "Found 1 vulnerability ID(s) to process.",
            result.stdout,
        )

        # Run the command with a vuln ID
        result = self.runner.invoke(
            app,
            ["research", "github", "--id", "vuln-1234"],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn(
            "Found 1 vulnerability ID(s) to process.",
            result.stdout,
        )

    @patch("wafrunner_cli.commands.research.lookup_ids")
    @patch("wafrunner_cli.commands.research.ApiClient")
    def test_github_with_invalid_id(self, MockApiClient, mock_lookup_ids):
        # Mock the lookup service to return None
        mock_lookup_ids.return_value = None

        # Run the command with an invalid ID
        result = self.runner.invoke(
            app,
            ["research", "github", "--id", "invalid-id"],
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn(
            "Could not resolve identifier: invalid-id",
            result.stdout,
        )

    @patch("wafrunner_cli.commands.research.lookup_ids")
    @patch("wafrunner_cli.commands.research.ApiClient")
    def test_refine_graph_with_id_success(self, MockApiClient, mock_lookup_ids):
        # Mock the lookup service to return a valid response
        mock_lookup_ids.return_value = {
            "cve_id": "CVE-2024-5678",
            "vuln_id": "vuln-5678",
        }

        # Mock the API client to avoid actual API calls
        mock_api_instance = MockApiClient.return_value
        # The command checks for 2xx status codes
        mock_api_instance.post.return_value.status_code = 202

        # Run the command with a CVE ID
        result = self.runner.invoke(
            app,
            ["research", "refine-graph", "--id", "CVE-2024-5678"],
        )
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn(
            "Found 1 vulnerability IDs to process.",
            result.stdout,
        )
        self.assertIn("Successful Triggers: 1", result.stdout)
        mock_api_instance.post.assert_called_once_with(
            "/vulnerability_records/vuln-5678/actions/refine-exploit-graph",
            json={},
        )

    @patch("wafrunner_cli.commands.research.lookup_ids")
    @patch("wafrunner_cli.commands.research.ApiClient")
    def test_refine_graph_with_id_failure(self, MockApiClient, mock_lookup_ids):
        # Mock the lookup service to return a valid response
        mock_lookup_ids.return_value = {
            "cve_id": "CVE-2024-5678",
            "vuln_id": "vuln-5678",
        }

        # Mock the API client to return a failure
        mock_api_instance = MockApiClient.return_value
        mock_api_instance.post.return_value.status_code = 500
        mock_api_instance.post.return_value.text = "Server Error"

        # Run the command with a CVE ID
        result = self.runner.invoke(
            app,
            [
                "research",
                "refine-graph",
                "--id",
                "CVE-2024-5678",
                "--verbose",
            ],
        )
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn(
            "Found 1 vulnerability IDs to process.",
            result.stdout,
        )
        self.assertIn("Failed Triggers:     1", result.stdout)
        self.assertIn(
            "Failed to trigger exploit graph refinement for vuln-5678",
            result.stdout,
        )
        mock_api_instance.post.assert_called_once_with(
            "/vulnerability_records/vuln-5678/actions/refine-exploit-graph",
            json={},
        )

    @patch("wafrunner_cli.commands.research.lookup_ids")
    @patch("wafrunner_cli.commands.research.ApiClient")
    def test_init_scdef_with_id_and_graph_success(self, MockApiClient, mock_lookup_ids):
        # Mock the lookup service to return a valid response
        mock_lookup_ids.return_value = {
            "cve_id": "CVE-2024-9999",
            "vuln_id": "vuln-9999",
        }

        # Mock the API client to avoid actual API calls
        mock_api_instance = MockApiClient.return_value
        # The command checks for 2xx status codes
        mock_api_instance.post.return_value.status_code = 202

        # Run the command with a CVE ID and graph
        result = self.runner.invoke(
            app,
            [
                "research",
                "init-scdef",
                "--id",
                "CVE-2024-9999",
                "--graph",
                "test-graph",
            ],
        )
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn(
            "Found 1 vulnerability IDs to process.",
            result.stdout,
        )
        self.assertIn("Successful Triggers: 1", result.stdout)
        mock_api_instance.post.assert_called_once_with(
            "/vulnerability_records/vuln-9999/actions/initialise-scdef",
            json={"graphID": "test-graph"},
        )

    @patch("wafrunner_cli.commands.research.lookup_ids")
    @patch("wafrunner_cli.commands.research.ApiClient")
    def test_init_scdef_with_id_no_graph_success(self, MockApiClient, mock_lookup_ids):
        # Mock the lookup service to return a valid response
        mock_lookup_ids.return_value = {
            "cve_id": "CVE-2024-9998",
            "vuln_id": "vuln-9998",
        }

        # Mock the API client to avoid actual API calls
        mock_api_instance = MockApiClient.return_value
        # The command checks for 2xx status codes
        mock_api_instance.post.return_value.status_code = 202

        # Run the command with a CVE ID but no graph
        result = self.runner.invoke(
            app,
            ["research", "init-scdef", "--id", "CVE-2024-9998"],
        )
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn(
            "Found 1 vulnerability IDs to process.",
            result.stdout,
        )
        self.assertIn("Successful Triggers: 1", result.stdout)
        mock_api_instance.post.assert_called_once_with(
            "/vulnerability_records/vuln-9998/actions/initialise-scdef",
            json={},
        )

    @patch("wafrunner_cli.commands.research.lookup_ids")
    @patch("wafrunner_cli.commands.research.ApiClient")
    def test_init_scdef_with_id_failure(self, MockApiClient, mock_lookup_ids):
        # Mock the lookup service to return a valid response
        mock_lookup_ids.return_value = {
            "cve_id": "CVE-2024-9997",
            "vuln_id": "vuln-9997",
        }

        # Mock the API client to return a failure
        mock_api_instance = MockApiClient.return_value
        mock_api_instance.post.return_value.status_code = 500
        mock_api_instance.post.return_value.text = "Server Error"

        # Run the command with a CVE ID
        result = self.runner.invoke(
            app,
            [
                "research",
                "init-scdef",
                "--id",
                "CVE-2024-9997",
                "--verbose",
            ],
        )
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn(
            "Found 1 vulnerability IDs to process.",
            result.stdout,
        )
        self.assertIn("Failed Triggers:     1", result.stdout)
        self.assertIn(
            "Failed to trigger SCDEF initialization for vuln-9997",
            result.stdout,
        )
        mock_api_instance.post.assert_called_once_with(
            "/vulnerability_records/vuln-9997/actions/initialise-scdef",
            json={},
        )

    @patch("wafrunner_cli.commands.research.lookup_ids")
    def test_init_scdef_with_invalid_id(self, mock_lookup_ids):
        # Mock the lookup service to return None
        mock_lookup_ids.return_value = None

        # Run the command with an invalid ID
        result = self.runner.invoke(
            app,
            ["research", "init-scdef", "--id", "invalid-id"],
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn(
            "Could not resolve identifier: invalid-id",
            result.stdout,
        )

    @patch("wafrunner_cli.commands.research.lookup_ids")
    @patch("wafrunner_cli.commands.research.ApiClient")
    def test_update_source_with_cve_id_success(self, MockApiClient, mock_lookup_ids):
        # Mock the lookup service to return a valid response
        mock_lookup_ids.return_value = {
            "cve_id": "CVE-2024-1234",
            "vuln_id": "vuln-1234",
        }

        # Mock the API client to return success
        mock_api_instance = MockApiClient.return_value
        mock_api_instance.post.return_value.status_code = 202

        # Run the command with a CVE ID
        result = self.runner.invoke(
            app,
            ["research", "update-source", "--id", "CVE-2024-1234"],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Found 1 vulnerability IDs to process.", result.stdout)
        self.assertIn("Successful Updates: 1", result.stdout)
        mock_api_instance.post.assert_called_once_with(
            "/vulnerability_records/vuln-1234/actions/update-from-source",
            json={},
        )

    @patch("wafrunner_cli.commands.research.lookup_ids")
    @patch("wafrunner_cli.commands.research.ApiClient")
    def test_update_source_with_vuln_id_success(self, MockApiClient, mock_lookup_ids):
        # Mock the lookup service to return a valid response for vulnID
        mock_lookup_ids.return_value = {
            "vuln_id": "1d4f8624-8acf-4c57-ab06-2b7bdf93ca36",
        }

        # Mock the API client to return success
        mock_api_instance = MockApiClient.return_value
        mock_api_instance.post.return_value.status_code = 202

        # Run the command with a vulnID
        result = self.runner.invoke(
            app,
            [
                "research",
                "update-source",
                "--id",
                "1d4f8624-8acf-4c57-ab06-2b7bdf93ca36",
            ],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Found 1 vulnerability IDs to process.", result.stdout)
        self.assertIn("Successful Updates: 1", result.stdout)
        mock_api_instance.post.assert_called_once_with(
            "/vulnerability_records/1d4f8624-8acf-4c57-ab06-2b7bdf93ca36/actions/"
            "update-from-source",
            json={},
        )

    @patch("wafrunner_cli.commands.research.lookup_ids")
    @patch("wafrunner_cli.commands.research.ApiClient")
    def test_update_source_with_cve_id_failure(self, MockApiClient, mock_lookup_ids):
        # Mock the lookup service to return a valid response
        mock_lookup_ids.return_value = {
            "cve_id": "CVE-2024-1234",
            "vuln_id": "vuln-1234",
        }

        # Mock the API client to return a failure
        mock_api_instance = MockApiClient.return_value
        mock_api_instance.post.return_value.status_code = 400
        mock_api_instance.post.return_value.text = "Bad Request"

        # Run the command with a CVE ID
        result = self.runner.invoke(
            app,
            ["research", "update-source", "--id", "CVE-2024-1234", "--verbose"],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Found 1 vulnerability IDs to process.", result.stdout)
        self.assertIn("Failed Updates:     1", result.stdout)

    @patch("wafrunner_cli.commands.research.lookup_ids")
    @patch("wafrunner_cli.commands.research.ApiClient")
    def test_update_source_with_invalid_id(self, MockApiClient, mock_lookup_ids):
        # Mock the lookup service to return None for invalid ID
        mock_lookup_ids.return_value = None

        # Run the command with an invalid ID
        result = self.runner.invoke(
            app,
            ["research", "update-source", "--id", "invalid-id"],
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn(
            "Could not resolve identifier: invalid-id",
            result.stdout,
        )

    @patch("wafrunner_cli.commands.research.lookup_ids")
    @patch("wafrunner_cli.commands.research.ApiClient")
    def test_update_source_server_error(self, MockApiClient, mock_lookup_ids):
        # Mock the lookup service to return a valid response
        mock_lookup_ids.return_value = {
            "cve_id": "CVE-2024-1234",
            "vuln_id": "vuln-1234",
        }

        # Mock the API client to return server error
        mock_api_instance = MockApiClient.return_value
        mock_api_instance.post.return_value.status_code = 500
        mock_api_instance.post.return_value.text = "Internal Server Error"

        # Run the command with a CVE ID
        result = self.runner.invoke(
            app,
            ["research", "update-source", "--id", "CVE-2024-1234", "--verbose"],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Found 1 vulnerability IDs to process.", result.stdout)
        self.assertIn("Failed Updates:     1", result.stdout)


if __name__ == "__main__":
    unittest.main()
