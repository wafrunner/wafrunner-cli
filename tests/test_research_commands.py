import pytest
from typer.testing import CliRunner
from pathlib import Path
from unittest.mock import MagicMock, call
import httpx

# The application object from the script being tested.
# Assuming the project is installed in editable mode or path is configured.
from wafrunner_cli.commands.research import app as research_app
from wafrunner_cli.core.exceptions import AuthenticationError

# pytest-mock is a dependency for the 'mocker' fixture.

runner = CliRunner() # mix_stderr=False is not supported in all versions

@pytest.fixture
def mock_api_client(mocker):
    """Mocks the ApiClient to control API responses during tests."""
    # Use patch with autospec to ensure the mock has the same interface as the real class
    mock_client_instance = mocker.patch(
        "wafrunner_cli.commands.research.ApiClient",
        autospec=True
    ).return_value

    # Default success returns for all methods
    mock_client_instance.get_vulnerability_record.return_value = {"github_searches": []}
    mock_client_instance.trigger_github_search.return_value = True
    mock_client_instance.get_data_sources.return_value = []
    mock_client_instance.trigger_scrape.return_value = True
    
    return mock_client_instance

@pytest.fixture
def mock_config_manager(mocker, tmp_path):
    """Mocks the ConfigManager and its methods."""
    mock_cm_instance = mocker.patch(
        "wafrunner_cli.commands.research.ConfigManager",
        autospec=True
    ).return_value
    # Have get_data_dir return a temporary directory for test isolation
    mock_cm_instance.get_data_dir.return_value = tmp_path
    return mock_cm_instance

# --- Tests for the 'github' command ---

def test_github_command_no_identifier_fails():
    """Test that 'github' exits with an error if no identifier is provided."""
    result = runner.invoke(research_app, ["github"])
    assert result.exit_code == 1
    assert "Error: Please provide either a --collection or a --vulnid." in result.stdout

def test_github_command_both_identifiers_fail():
    """Test that 'github' exits with an error if both identifiers are provided."""
    result = runner.invoke(research_app, ["github", "--collection", "my-coll", "--vulnid", "VULN-123"])
    assert result.exit_code == 1
    assert "Error: Options --collection and --vulnid are mutually exclusive." in result.stdout

def test_github_command_with_vulnid_succeeds(mock_api_client, mock_config_manager):
    """Test a successful 'github' run with a single vulnID."""
    result = runner.invoke(research_app, ["github", "--vulnid", "VULN-123"])
    assert result.exit_code == 0
    assert "Found 1 vulnerability ID(s) to process." in result.stdout
    assert "Triggering GitHub search for VULN-123..." in result.stdout
    mock_api_client.get_vulnerability_record.assert_called_once_with("VULN-123")
    mock_api_client.trigger_github_search.assert_called_once_with("VULN-123")

def test_github_command_with_collection_succeeds(mock_api_client, mock_config_manager, tmp_path):
    """Test a successful 'github' run with a collection file."""
    collection_file = tmp_path / "my-collection.txt"
    collection_file.write_text("VULN-001\nVULN-002")

    result = runner.invoke(research_app, ["github", "--collection", "my-collection.txt"])
    
    assert result.exit_code == 0
    assert "Found 2 vulnerability ID(s) to process." in result.stdout
    assert mock_api_client.trigger_github_search.call_count == 2
    mock_api_client.trigger_github_search.assert_has_calls([call("VULN-001"), call("VULN-002")])

def test_github_command_skips_completed_searches(mock_api_client, mock_config_manager):
    """Test that 'github' skips vulnIDs with already completed searches."""
    # Configure mock to return different records based on vulnID
    def get_record_side_effect(vuln_id):
        if vuln_id == "VULN-COMPLETED":
            return {"github_searches": [{"status": "complete"}]}
        return {"github_searches": []}
    
    mock_api_client.get_vulnerability_record.side_effect = get_record_side_effect
    
    result = runner.invoke(research_app, ["github", "--vulnid", "VULN-COMPLETED"])
    assert result.exit_code == 0
    assert "Skipping VULN-COMPLETED: Found existing completed search." in result.stdout
    mock_api_client.trigger_github_search.assert_not_called()

def test_github_command_force_option_overrides_skip(mock_api_client, mock_config_manager):
    """Test that the --force flag triggers a search even if one is complete."""
    mock_api_client.get_vulnerability_record.return_value = {"github_searches": [{"status": "complete"}]}
    
    result = runner.invoke(research_app, ["github", "--vulnid", "VULN-COMPLETED", "--force"])
    assert result.exit_code == 0
    assert "Running in force mode" in result.stdout
    assert "Skipping" not in result.stdout # Ensure the skip message is not printed
    mock_api_client.trigger_github_search.assert_called_once_with("VULN-COMPLETED")

def test_github_command_collection_not_found(mock_config_manager):
    """Test that 'github' exits if the collection file is not found."""
    result = runner.invoke(research_app, ["github", "--collection", "non-existent-collection"])
    assert result.exit_code == 1
    assert "Error: Collection 'non-existent-collection' not found" in result.stdout

def test_github_auth_error_handling(mock_api_client, mock_config_manager):
    """Test graceful failure on AuthenticationError."""
    mock_api_client.get_vulnerability_record.side_effect = AuthenticationError("Invalid API Key")
    result = runner.invoke(research_app, ["github", "--vulnid", "VULN-123"])
    assert result.exit_code == 1
    assert "API Error: Invalid API Key" in result.stdout

# --- Tests for the 'scrape' command ---

def test_scrape_command_no_identifier_fails():
    """Test that 'scrape' exits with an error if no identifier is provided."""
    result = runner.invoke(research_app, ["scrape"])
    assert result.exit_code == 1
    assert "Error: Please provide either a --collection or a --vulnid." in result.stdout

def test_scrape_command_with_vulnid_succeeds(mock_api_client, mock_config_manager):
    """Test a successful 'scrape' run with a single vulnID."""
    mock_api_client.get_data_sources.return_value = [
        {"linkID": "link-1", "scrapedStatus": "new"},
        {"linkID": "link-2", "scrapedStatus": "pending"},
    ]
    result = runner.invoke(research_app, ["scrape", "--vulnid", "VULN-123"])
    
    assert result.exit_code == 0
    assert "Found 1 vulnerability ID(s) to process for scraping." in result.stdout
    assert "Triggering scrape for VULN-123, linkID: link-1" in result.stdout
    assert "Triggering scrape for VULN-123, linkID: link-2" in result.stdout
    assert mock_api_client.trigger_scrape.call_count == 2

def test_scrape_command_skips_completed_and_error_statuses(mock_api_client, mock_config_manager):
    """Test that 'scrape' correctly skips records with 'complete' or 'error' status."""
    mock_api_client.get_data_sources.return_value = [
        {"linkID": "link-1", "scrapedStatus": "new"},
        {"linkID": "link-2", "scrapedStatus": "complete"},
        {"linkID": "link-3", "scrapedStatus": "error"},
        {"linkID": "link-4", "scrapedStatus": "pending"},
    ]
    result = runner.invoke(research_app, ["scrape", "--vulnid", "VULN-123"])

    assert result.exit_code == 0
    # Should only be called for link-1 and link-4
    assert mock_api_client.trigger_scrape.call_count == 2
    mock_api_client.trigger_scrape.assert_has_calls([call("VULN-123", "link-1"), call("VULN-123", "link-4")])
    assert "Summary for VULN-123: Triggered 2 scrapes, skipped 2 data sources." in result.stdout

def test_scrape_command_handles_no_data_sources(mock_api_client, mock_config_manager):
    """Test 'scrape' behavior when get_data_sources returns an empty list."""
    mock_api_client.get_data_sources.return_value = []
    result = runner.invoke(research_app, ["scrape", "--vulnid", "VULN-123"])
    
    assert result.exit_code == 0
    assert "Summary for VULN-123: Triggered 0 scrapes, skipped 0 data sources." in result.stdout
    mock_api_client.trigger_scrape.assert_not_called()

def test_scrape_command_handles_record_not_found(mock_api_client, mock_config_manager):
    """Test 'scrape' behavior when get_data_sources returns None (e.g., 404)."""
    mock_api_client.get_data_sources.return_value = None
    result = runner.invoke(research_app, ["scrape", "--vulnid", "VULN-NOT-FOUND"])
    
    assert result.exit_code == 0
    assert "Info: No data sources found for VULN-NOT-FOUND" in result.stdout
    mock_api_client.trigger_scrape.assert_not_called()

def test_scrape_command_handles_record_missing_linkid(mock_api_client, mock_config_manager):
    """Test 'scrape' skips records that are missing a linkID."""
    mock_api_client.get_data_sources.return_value = [{"scrapedStatus": "new"}] # No linkID
    result = runner.invoke(research_app, ["scrape", "--vulnid", "VULN-123"])

    assert result.exit_code == 0
    assert "Warning: Skipping record for VULN-123 due to missing linkID." in result.stdout
    mock_api_client.trigger_scrape.assert_not_called()
    assert "Summary for VULN-123: Triggered 0 scrapes, skipped 1 data sources." in result.stdout

def test_scrape_command_handles_trigger_failure(mock_api_client, mock_config_manager):
    """Test 'scrape' logs a message if the API call to trigger a scrape fails."""
    mock_api_client.get_data_sources.return_value = [{"linkID": "link-1", "scrapedStatus": "new"}]
    mock_api_client.trigger_scrape.return_value = False # Simulate failure
    result = runner.invoke(research_app, ["scrape", "--vulnid", "VULN-123"])

    assert result.exit_code == 0
    assert "Failed to trigger scrape for linkID: link-1" in result.stdout
    # The summary should still reflect the attempt
    assert "Summary for VULN-123: Triggered 0 scrapes, skipped 0 data sources." in result.stdout

def test_scrape_auth_error_handling(mock_api_client, mock_config_manager):
    """Test graceful failure on AuthenticationError during 'scrape'."""
    mock_api_client.get_data_sources.side_effect = AuthenticationError("Invalid API Key")
    result = runner.invoke(research_app, ["scrape", "--vulnid", "VULN-123"])
    assert result.exit_code == 1
    assert "API Error: Invalid API Key" in result.stdout
