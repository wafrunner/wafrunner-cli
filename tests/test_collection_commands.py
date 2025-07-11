import unittest
from unittest.mock import patch
from typer.testing import CliRunner
from pathlib import Path
import json

from wafrunner_cli.main import app


class TestCollectionCommands(unittest.TestCase):

    runner = CliRunner()

    def test_create_collection_with_id(self):
        with self.runner.isolated_filesystem() as temp_dir:
            with patch(
                "wafrunner_cli.commands.collection.COLLECTIONS_DIR", Path(temp_dir)
            ):
                with patch(
                    "wafrunner_cli.commands.collection.lookup_ids"
                ) as mock_lookup_ids:
                    mock_lookup_ids.return_value = {
                        "cve_id": "CVE-2024-1234",
                        "vuln_id": "vuln-1234",
                    }

                    # Run the command
                    result = self.runner.invoke(
                        app,
                        [
                            "collection",
                            "create",
                            "my-collection",
                            "--id",
                            "CVE-2024-1234",
                        ],
                    )

                    # Assertions
                    self.assertEqual(result.exit_code, 0, result.stdout)
                    self.assertIn(
                        "Collection 'my-collection' created successfully", result.stdout
                    )

                    # Verify the created file
                    collection_file = Path(temp_dir) / "my-collection.json"
                    self.assertTrue(collection_file.exists())
                    with open(collection_file, "r") as f:
                        data = json.load(f)
                    self.assertEqual(data["name"], "my-collection")
                    self.assertEqual(len(data["vulnerabilities"]), 1)
                    self.assertEqual(
                        data["vulnerabilities"][0]["cve_id"], "CVE-2024-1234"
                    )

    def test_create_collection_with_file(self):
        with self.runner.isolated_filesystem() as temp_dir:
            with patch(
                "wafrunner_cli.commands.collection.COLLECTIONS_DIR", Path(temp_dir)
            ):
                with patch(
                    "wafrunner_cli.commands.collection.lookup_ids"
                ) as mock_lookup_ids:
                    # Set the side_effect to return different values for each call
                    mock_lookup_ids.side_effect = [
                        {"cve_id": "CVE-2024-5678", "vuln_id": "vuln-5678"},
                        {"cve_id": "CVE-2024-1111", "vuln_id": "vuln-1111"},
                    ]

                    # Create a test file
                    with open("test_ids.txt", "w") as f:
                        f.write("CVE-2024-5678\n")
                        f.write("vuln-1111\n")

                    # Run the command
                    result = self.runner.invoke(
                        app,
                        [
                            "collection",
                            "create",
                            "my-collection-from-file",
                            "--file",
                            "test_ids.txt",
                        ],
                    )

                    # Assertions
                    self.assertEqual(result.exit_code, 0, result.stdout)
                    self.assertIn(
                        "Collection 'my-collection-from-file' created successfully",
                        result.stdout,
                    )

                    # Verify the created file
                    collection_file = Path(temp_dir) / "my-collection-from-file.json"
                    self.assertTrue(collection_file.exists())
                    with open(collection_file, "r") as f:
                        data = json.load(f)
                    self.assertEqual(data["name"], "my-collection-from-file")
                    self.assertEqual(len(data["vulnerabilities"]), 2)


if __name__ == "__main__":
    unittest.main()
