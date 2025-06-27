import pytest
from typer.testing import CliRunner
from pathlib import Path
from unittest.mock import MagicMock

# The application object from the script being tested.
from wafrunner_cli.commands.research import app as research_app

runner = CliRunner()

@pytest.fixture
def mock_api_client(mocker):
    """Mocks the ApiClient to control API responses during tests."""
    mock_client = MagicMock()
    mocker.patch("wafrunner_cli.commands.research.ApiClient", return_value=mock_client)
    # Mock the get_vulnerability_record to return a dummy record
    mock_client.get_vulnerability_record.return_value = {"vulnID": "VULN-123", "github_searches": []}
    mock_client.trigger_github_search.return_value = True
    return mock_client

@pytest.fixture
def mock_config_manager(mocker, tmp_path):
    """Mocks the ConfigManager and its methods."""
    mock_cm_instance = MagicMock()
    # Have get_data_dir return a temporary directory
    mock_cm_instance.get_data_dir.return_value = tmp_path
    mocker.patch("wafrunner_cli.commands.research.ConfigManager", return_value=mock_cm_instance)
    return mock_cm_instance

def test_github_command_no_identifier_fails():
    """Test that the command exits with an error if no identifier is provided."""
    result = runner.invoke(research_app, ["github"])
    assert result.exit_code == 1
    assert "Error: Please provide either a --collection or a --vulnid." in result.stderr

def test_github_command_both_identifiers_fail():
    """Test that the command exits with an error if both identifiers are provided."""
    result = runner.invoke(research_app, ["github", "--collection", "my-coll", "--vulnid", "VULN-123"])
    assert result.exit_code == 1
    assert "Error: Options --collection and --vulnid are mutually exclusive." in result.stderr

def test_github_command_with_vulnid_succeeds(mock_api_client, mock_config_manager):
    """Test a successful run with a single vulnID."""
    result = runner.invoke(research_app, ["github", "--vulnid", "VULN-123"])
    assert result.exit_code == 0
    assert "Found 1 vulnerability ID(s) to process." in result.stderr
    assert "Triggering GitHub search for VULN-123..." in result.stderr
    mock_api_client.get_vulnerability_record.assert_called_once_with("VULN-123")
    mock_api_client.trigger_github_search.assert_called_once_with("VULN-123")

def test_github_command_with_collection_succeeds(mock_api_client, mock_config_manager, tmp_path):
    """Test a successful run with a collection file."""
    # Create a mock collection file
    collection_file = tmp_path / "my-collection.txt"
    collection_file.write_text("VULN-001\nVULN-002")

    result = runner.invoke(research_app, ["github", "--collection", "my-collection.txt"])
    
    assert result.exit_code == 0
    assert "Found 2 vulnerability ID(s) to process." in result.stderr
    assert "Triggering GitHub search for VULN-001..." in result.stderr
    assert "Triggering GitHub search for VULN-002..." in result.stderr
    assert mock_api_client.trigger_github_search.call_count == 2

def test_github_command_collection_not_found(mock_config_manager):
    """Test that the command exits if the collection file is not found."""
    result = runner.invoke(research_app, ["github", "--collection", "non-existent-collection"])
    assert result.exit_code == 1
    assert "Error: Collection 'non-existent-collection' not found" in result.stderr