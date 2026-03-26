import json
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

from typer.testing import CliRunner

from wafrunner_cli.main import app
from wafrunner_cli.commands.data import app as data_app


class TestDataCommandsPresent(unittest.TestCase):
    """Verify all required data commands exist."""

    def test_all_required_commands_present(self):
        all_commands = []
        for cmd in data_app.registered_commands:
            if cmd.name:
                all_commands.append(cmd.name)
            elif hasattr(cmd, "callback") and hasattr(cmd.callback, "__name__"):
                all_commands.append(cmd.callback.__name__)

        commands = set(all_commands)
        required = {"get-graph", "get-controls"}
        missing = required - commands
        self.assertFalse(missing, f"Missing required data commands: {missing}")


class TestGetGraph(unittest.TestCase):

    runner = CliRunner()

    def test_requires_collection_or_id(self):
        result = self.runner.invoke(app, ["data", "get-graph"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Please provide either", result.stdout)

    def test_collection_and_id_mutually_exclusive(self):
        result = self.runner.invoke(
            app, ["data", "get-graph", "-c", "test", "-i", "CVE-2024-1234"]
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn("mutually exclusive", result.stdout)

    @patch("wafrunner_cli.commands.data.lookup_ids")
    def test_invalid_id(self, mock_lookup_ids):
        mock_lookup_ids.return_value = None
        result = self.runner.invoke(
            app, ["data", "get-graph", "-i", "invalid-id"]
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Could not resolve identifier", result.stdout)

    @patch("wafrunner_cli.commands.data.retry_with_backoff")
    @patch("wafrunner_cli.commands.data.lookup_ids")
    @patch("wafrunner_cli.commands.data.ApiClient")
    def test_get_graph_single_success(
        self, MockApiClient, mock_lookup_ids, mock_retry
    ):
        mock_lookup_ids.return_value = {
            "cve_id": "CVE-2024-1234",
            "vuln_id": "vuln-1234",
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "exploitGraphInstanceID": "graph-123",
            "exploitGraph": [{"vector": "test"}],
        }
        mock_retry.return_value = mock_response

        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
                app, ["data", "get-graph", "-i", "CVE-2024-1234"]
            )
            self.assertEqual(result.exit_code, 0, result.stdout)
            self.assertIn("Downloaded:          1", result.stdout)

            # Verify file was created
            graph_file = Path("exploit-graphs/CVE-2024-1234.json")
            self.assertTrue(graph_file.exists())
            data = json.loads(graph_file.read_text())
            self.assertEqual(data["exploitGraphInstanceID"], "graph-123")

    @patch("wafrunner_cli.commands.data.retry_with_backoff")
    @patch("wafrunner_cli.commands.data.lookup_ids")
    @patch("wafrunner_cli.commands.data.ApiClient")
    def test_get_graph_skips_existing(
        self, MockApiClient, mock_lookup_ids, mock_retry
    ):
        mock_lookup_ids.return_value = {
            "cve_id": "CVE-2024-1234",
            "vuln_id": "vuln-1234",
        }

        with self.runner.isolated_filesystem():
            # Pre-create the file
            Path("exploit-graphs").mkdir()
            Path("exploit-graphs/CVE-2024-1234.json").write_text("{}")

            result = self.runner.invoke(
                app, ["data", "get-graph", "-i", "CVE-2024-1234"]
            )
            self.assertEqual(result.exit_code, 0, result.stdout)
            self.assertIn("Skipped (exists):    1", result.stdout)
            # retry_with_backoff should not have been called (no API request)
            mock_retry.assert_not_called()

    @patch("wafrunner_cli.commands.data.retry_with_backoff")
    @patch("wafrunner_cli.commands.data.lookup_ids")
    @patch("wafrunner_cli.commands.data.ApiClient")
    def test_get_graph_force_overwrites(
        self, MockApiClient, mock_lookup_ids, mock_retry
    ):
        mock_lookup_ids.return_value = {
            "cve_id": "CVE-2024-1234",
            "vuln_id": "vuln-1234",
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "exploitGraphInstanceID": "graph-new",
            "exploitGraph": [{"vector": "updated"}],
        }
        mock_retry.return_value = mock_response

        with self.runner.isolated_filesystem():
            Path("exploit-graphs").mkdir()
            Path("exploit-graphs/CVE-2024-1234.json").write_text('{"old": true}')

            result = self.runner.invoke(
                app, ["data", "get-graph", "-i", "CVE-2024-1234", "--force"]
            )
            self.assertEqual(result.exit_code, 0, result.stdout)
            self.assertIn("Downloaded:          1", result.stdout)

            data = json.loads(
                Path("exploit-graphs/CVE-2024-1234.json").read_text()
            )
            self.assertEqual(data["exploitGraphInstanceID"], "graph-new")

    @patch("wafrunner_cli.commands.data.retry_with_backoff")
    @patch("wafrunner_cli.commands.data.lookup_ids")
    @patch("wafrunner_cli.commands.data.ApiClient")
    def test_get_graph_no_graph_available(
        self, MockApiClient, mock_lookup_ids, mock_retry
    ):
        mock_lookup_ids.return_value = {
            "cve_id": "CVE-2024-1234",
            "vuln_id": "vuln-1234",
        }

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_retry.return_value = mock_response

        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
                app, ["data", "get-graph", "-i", "CVE-2024-1234"]
            )
            self.assertEqual(result.exit_code, 0, result.stdout)
            self.assertIn("No graph available:  1", result.stdout)

    @patch("wafrunner_cli.commands.data.retry_with_backoff")
    @patch("wafrunner_cli.commands.data.lookup_ids")
    @patch("wafrunner_cli.commands.data.ApiClient")
    def test_get_graph_uuid_filename(
        self, MockApiClient, mock_lookup_ids, mock_retry
    ):
        mock_lookup_ids.return_value = {
            "cve_id": "CVE-2024-1234",
            "vuln_id": "a1ddadd4-1b9d-4fab-90fe-64c1c763cd58",
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "exploitGraphInstanceID": "graph-123",
            "exploitGraph": [{"vector": "test"}],
        }
        mock_retry.return_value = mock_response

        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
                app,
                ["data", "get-graph", "-i", "CVE-2024-1234", "--uuid"],
            )
            self.assertEqual(result.exit_code, 0, result.stdout)
            self.assertIn("Downloaded:          1", result.stdout)

            graph_file = Path(
                "exploit-graphs/a1ddadd4-1b9d-4fab-90fe-64c1c763cd58.json"
            )
            self.assertTrue(graph_file.exists())

    @patch("wafrunner_cli.commands.data.retry_with_backoff")
    @patch("wafrunner_cli.commands.data.lookup_ids")
    @patch("wafrunner_cli.commands.data.ApiClient")
    def test_get_graph_empty_exploit_graph(
        self, MockApiClient, mock_lookup_ids, mock_retry
    ):
        mock_lookup_ids.return_value = {
            "cve_id": "CVE-2024-1234",
            "vuln_id": "vuln-1234",
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "exploitGraphInstanceID": "graph-123",
            "exploitGraph": [],
        }
        mock_retry.return_value = mock_response

        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
                app, ["data", "get-graph", "-i", "CVE-2024-1234"]
            )
            self.assertEqual(result.exit_code, 0, result.stdout)
            self.assertIn("No graph available:  1", result.stdout)

    @patch("wafrunner_cli.commands.data.retry_with_backoff")
    @patch("wafrunner_cli.commands.data.lookup_ids")
    @patch("wafrunner_cli.commands.data.ApiClient")
    def test_get_graph_custom_output_dir(
        self, MockApiClient, mock_lookup_ids, mock_retry
    ):
        mock_lookup_ids.return_value = {
            "cve_id": "CVE-2024-1234",
            "vuln_id": "vuln-1234",
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "exploitGraphInstanceID": "graph-123",
            "exploitGraph": [{"vector": "test"}],
        }
        mock_retry.return_value = mock_response

        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
                app,
                ["data", "get-graph", "-i", "CVE-2024-1234", "-o", "./my-graphs"],
            )
            self.assertEqual(result.exit_code, 0, result.stdout)
            self.assertTrue(Path("my-graphs/CVE-2024-1234.json").exists())


if __name__ == "__main__":
    unittest.main()
