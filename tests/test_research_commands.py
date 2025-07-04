import pytest
from typer.testing import CliRunner
from pathlib import Path
from unittest.mock import MagicMock, call
import httpx

from wafrunner_cli.commands.research import app as research_app
from wafrunner_cli.core.exceptions import AuthenticationError

import re

runner = CliRunner()

def strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)


@pytest.fixture
def mock_api_client(mocker):
    """Mocks the ApiClient, focusing on get/post methods to reflect current implementation."""
    mock_client_instance = mocker.patch(
        "wafrunner_cli.commands.research.ApiClient",
        autospec=True,
    ).return_value

    # Mock generic methods that return a mock response object
    mock_get_response = MagicMock(spec=httpx.Response)
    mock_get_response.status_code = 200
    # Default JSON for GET requests, can be overridden in tests
    mock_get_response.json.return_value = {"github_searches": [], "exploit_graph_initializations": []}
    mock_client_instance.get.return_value = mock_get_response

    mock_post_response = MagicMock(spec=httpx.Response)
    mock_post_response.status_code = 200
    mock_client_instance.post.return_value = mock_post_response

    return mock_client_instance

@pytest.fixture
def mock_config_manager(mocker, tmp_path):
    """Mocks the ConfigManager and its methods."""
    mock_cm_instance = mocker.patch(
        "wafrunner_cli.commands.research.ConfigManager",
        autospec=True
    ).return_value
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
    assert "Triggered: 1" in result.stdout
    mock_api_client.get.assert_called_once_with("/vulnerability_records/VULN-123")
    mock_api_client.post.assert_called_once_with(
        "/vulnerability_records/VULN-123/actions/search",
        json={"searchType": "github"}
    )

def test_github_command_with_collection_succeeds(mock_api_client, mock_config_manager, tmp_path):
    """Test a successful 'github' run with a collection file."""
    collection_file = tmp_path / "my-collection.txt"
    collection_file.write_text("VULN-001\nVULN-002")

    result = runner.invoke(research_app, ["github", "--collection", "my-collection.txt"])
    
    assert result.exit_code == 0
    assert "Found 2 vulnerability ID(s) to process." in result.stdout
    assert "Triggered: 2" in result.stdout
    
    mock_api_client.get.assert_has_calls([
        call("/vulnerability_records/VULN-001"),
        call("/vulnerability_records/VULN-002")
    ], any_order=True)
    
    mock_api_client.post.assert_has_calls([
        call("/vulnerability_records/VULN-001/actions/search", json={"searchType": "github"}),
        call("/vulnerability_records/VULN-002/actions/search", json={"searchType": "github"})
    ], any_order=True)

def test_github_command_with_json_collection_succeeds(mock_api_client, mock_config_manager, tmp_path):
    """Test a successful 'github' run with a JSON collection file."""
    collection_dir = tmp_path / "collections"
    collection_dir.mkdir()
    collection_file = collection_dir / "my-collection.json"
    collection_file.write_text("""
    {
        "vulnerabilities": [
            {"cve_id": "CVE-2021-44228", "vuln_id": "VULN-001"},
            {"cve_id": "CVE-2021-44229", "vuln_id": "VULN-002"}
        ]
    }
    """)

    result = runner.invoke(research_app, ["github", "--collection", "my-collection"])
    
    assert result.exit_code == 0
    assert "Found 2 vulnerability ID(s) to process." in result.stdout
    assert "Triggered: 2" in result.stdout
    
    mock_api_client.get.assert_has_calls([
        call("/vulnerability_records/VULN-001"),
        call("/vulnerability_records/VULN-002")
    ], any_order=True)
    
    mock_api_client.post.assert_has_calls([
        call("/vulnerability_records/VULN-001/actions/search", json={"searchType": "github"}),
        call("/vulnerability_records/VULN-002/actions/search", json={"searchType": "github"})
    ], any_order=True)

def test_github_command_skips_completed_searches(mock_api_client, mock_config_manager):
    """Test that 'github' skips vulnIDs with already completed searches."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {"github_searches": [{"status": "complete"}]}
    mock_api_client.get.return_value = mock_response
    
    result = runner.invoke(research_app, ["github", "--vulnid", "VULN-COMPLETED"])
    assert result.exit_code == 0
    assert "Skipped: 1" in result.stdout
    assert "Triggered: 0" in result.stdout
    mock_api_client.get.assert_called_once_with("/vulnerability_records/VULN-COMPLETED")
    mock_api_client.post.assert_not_called()

def test_github_command_force_option_overrides_skip(mock_api_client, mock_config_manager):
    """Test that the --force flag triggers a search even if one is complete."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {"github_searches": [{"status": "complete"}]}
    mock_api_client.get.return_value = mock_response
    
    result = runner.invoke(research_app, ["github", "--vulnid", "VULN-COMPLETED", "--force"])
    assert result.exit_code == 0
    assert "Running in force mode" in result.stdout
    assert "Skipped: 0" in result.stdout
    assert "Triggered: 1" in result.stdout
    mock_api_client.get.assert_called_once_with("/vulnerability_records/VULN-COMPLETED")
    mock_api_client.post.assert_called_once_with(
        "/vulnerability_records/VULN-COMPLETED/actions/search",
        json={"searchType": "github"}
    )

def test_github_command_collection_not_found(mock_config_manager):
    """Test that 'github' exits if the collection file is not found."""
    result = runner.invoke(research_app, ["github", "--collection", "non-existent-collection"])
    assert result.exit_code == 1
    assert "Error: Collection 'non-existent-collection' not found" in result.stdout

def test_github_auth_error_handling(mock_api_client, mock_config_manager):
    """Test graceful failure on AuthenticationError."""
    mock_api_client.get.side_effect = AuthenticationError("Invalid API Key")
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
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {"linkID": "link-1", "scrapedStatus": "new"},
        {"linkID": "link-2", "scrapedStatus": "pending"},
    ]
    mock_api_client.get.return_value = mock_response
    
    result = runner.invoke(research_app, ["scrape", "--vulnid", "VULN-123"])
    
    assert result.exit_code == 0
    assert "Summary for VULN-123: Triggered 2 scrapes, skipped 0 data sources." in result.stdout
    mock_api_client.get.assert_called_once_with("/vulnerability_records/VULN-123/data_sources")
    assert mock_api_client.post.call_count == 2

def test_scrape_command_skips_completed_and_error_statuses(mock_api_client, mock_config_manager):
    """Test that 'scrape' correctly skips records with 'complete' or 'error' status."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {"linkID": "link-1", "scrapedStatus": "new"},
        {"linkID": "link-2", "scrapedStatus": "complete"},
        {"linkID": "link-3", "scrapedStatus": "error"},
        {"linkID": "link-4", "scrapedStatus": "pending"},
    ]
    mock_api_client.get.return_value = mock_response

    result = runner.invoke(research_app, ["scrape", "--vulnid", "VULN-123"])

    assert result.exit_code == 0
    assert "Summary for VULN-123: Triggered 2 scrapes, skipped 2 data sources." in result.stdout
    assert mock_api_client.post.call_count == 2
    mock_api_client.post.assert_has_calls([
        call("/vulnerability_records/VULN-123/data_sources/link-1/actions/scrape", json={}),
        call("/vulnerability_records/VULN-123/data_sources/link-4/actions/scrape", json={})
    ], any_order=True)

def test_scrape_command_handles_no_data_sources(mock_api_client, mock_config_manager):
    """Test 'scrape' behavior when get_data_sources returns an empty list."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = []
    mock_api_client.get.return_value = mock_response
    
    result = runner.invoke(research_app, ["scrape", "--vulnid", "VULN-123"])
    
    assert result.exit_code == 0
    assert "Summary for VULN-123: Triggered 0 scrapes, skipped 0 data sources." in result.stdout
    mock_api_client.post.assert_not_called()

def test_scrape_command_handles_record_not_found(mock_api_client, mock_config_manager):
    """Test 'scrape' behavior when the API returns a 404 for data sources."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 404
    mock_api_client.get.return_value = mock_response
    
    result = runner.invoke(research_app, ["scrape", "--vulnid", "VULN-NOT-FOUND"])
    
    assert result.exit_code == 0
    assert "Info: No data sources found for VULN-NOT-FOUND (or record not found)." in result.stdout
    mock_api_client.post.assert_not_called()

def test_scrape_command_handles_record_missing_linkid(mock_api_client, mock_config_manager):
    """Test 'scrape' skips records that are missing a linkID."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = [{"scrapedStatus": "new"}] # No linkID
    mock_api_client.get.return_value = mock_response

    result = runner.invoke(research_app, ["scrape", "--vulnid", "VULN-123"])

    assert result.exit_code == 0
    assert "Warning: Skipping record for VULN-123 due to missing linkID." in result.stdout
    assert "Summary for VULN-123: Triggered 0 scrapes, skipped 1 data sources." in result.stdout
    mock_api_client.post.assert_not_called()

def test_scrape_command_handles_trigger_failure(mock_api_client, mock_config_manager):
    """Test 'scrape' logs a message if the API call to trigger a scrape fails."""
    mock_get_response = MagicMock(spec=httpx.Response)
    mock_get_response.status_code = 200
    mock_get_response.json.return_value = [{"linkID": "link-1", "scrapedStatus": "new"}]
    mock_api_client.get.return_value = mock_get_response

    mock_post_response = MagicMock(spec=httpx.Response)
    mock_post_response.status_code = 500
    mock_api_client.post.return_value = mock_post_response

    result = runner.invoke(research_app, ["scrape", "--vulnid", "VULN-123"])

    assert result.exit_code == 0
    assert "Failed to trigger scrape for linkID: link-1 (Status: 500)" in result.stdout
    assert "Summary for VULN-123: Triggered 0 scrapes, skipped 0 data sources." in result.stdout

def test_scrape_auth_error_handling(mock_api_client, mock_config_manager):
    """Test graceful failure on AuthenticationError during 'scrape'."""
    mock_api_client.get.side_effect = AuthenticationError("Invalid API Key")
    result = runner.invoke(research_app, ["scrape", "--vulnid", "VULN-123"])
    assert result.exit_code == 1
    assert "API Error: Invalid API Key" in result.stdout

# --- Tests for the 'init-graph' command ---

def test_init_graph_command_no_identifier_fails():
    """Test that 'init-graph' exits with an error if no identifier is provided."""
    result = runner.invoke(research_app, ["init-graph"])
    assert result.exit_code == 1
    assert "Error: Please provide either a --collection or a --vulnid." in result.stdout

def test_init_graph_command_both_identifiers_fail():
    """Test that 'init-graph' exits with an error if both identifiers are provided."""
    result = runner.invoke(research_app, ["init-graph", "--collection", "my-coll", "--vulnid", "VULN-123"])
    assert result.exit_code == 1
    assert "Error: Options --collection and --vulnid are mutually exclusive." in result.stdout

def test_init_graph_command_with_vulnid_succeeds(mock_api_client, mock_config_manager):
    """Test a successful 'init-graph' run with a single vulnID."""
    result = runner.invoke(research_app, ["init-graph", "--vulnid", "VULN-123"])
    assert result.exit_code == 0
    assert "[*] Found 1 vulnerability IDs to process." in result.stdout
    assert "Successful Triggers: 1" in result.stdout
    mock_api_client.post.assert_called_once_with("/vulnerability_records/VULN-123/actions/initialise-exploit-graph")

def test_init_graph_command_with_collection_succeeds(mock_api_client, mock_config_manager, tmp_path):
    """Test a successful 'init-graph' run with a collection file."""
    collection_file = tmp_path / "my-collection.txt"
    collection_file.write_text("VULN-001\nVULN-002")

    result = runner.invoke(research_app, ["init-graph", "--collection", "my-collection.txt"])
    
    assert result.exit_code == 0
    assert "[*] Found 2 vulnerability IDs to process." in result.stdout
    assert "Successful Triggers: 2" in result.stdout
    mock_api_client.post.assert_has_calls([
        call("/vulnerability_records/VULN-001/actions/initialise-exploit-graph"),
        call("/vulnerability_records/VULN-002/actions/initialise-exploit-graph")
    ], any_order=True)

def test_init_graph_command_collection_not_found(mock_config_manager):
    """Test that 'init-graph' exits if the collection file is not found."""
    result = runner.invoke(research_app, ["init-graph", "--collection", "non-existent-collection"])
    assert result.exit_code == 1
    assert "Error: Collection 'non-existent-collection' not found" in result.stdout

def test_init_graph_auth_error_handling(mocker, mock_config_manager):
    """Test graceful failure on AuthenticationError during 'init-graph' instantiation."""
    # Mock the entire class to fail on instantiation
    mocker.patch(
        "wafrunner_cli.commands.research.ApiClient",
        side_effect=AuthenticationError("Invalid API Key")
    )
    result = runner.invoke(research_app, ["init-graph", "--vulnid", "VULN-123"])
    assert result.exit_code == 1
    assert "API Error: Invalid API Key" in result.stdout

# --- Tests for the 'classify' command ---

def test_classify_command_no_identifier_fails():
    """Test that 'classify' exits with an error if no identifier is provided."""
    result = runner.invoke(research_app, ["classify"])
    assert result.exit_code == 1
    assert "Error: Please provide either a --collection or a --vulnid." in result.stdout

def test_classify_command_both_identifiers_fail():
    """Test that 'classify' exits with an error if both identifiers are provided."""
    result = runner.invoke(research_app, ["classify", "--collection", "my-coll", "--vulnid", "VULN-123"])
    assert result.exit_code == 1
    assert "Error: Options --collection and --vulnid are mutually exclusive." in result.stdout

def test_classify_command_mutually_exclusive_options_fail():
    """Test that 'classify' exits with an error if both --update and --retry are provided."""
    result = runner.invoke(research_app, ["classify", "--vulnid", "VULN-123", "--update", "--retry"])
    assert result.exit_code == 1
    assert "Error: --update and --retry are mutually exclusive." in result.stdout

def test_classify_command_with_vulnid_succeeds(mock_api_client, mock_config_manager):
    """Test a successful 'classify' run with a single vulnID."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {"linkID": "link-1", "scrapedStatus": "complete", "classifierStatus": "new"},
        {"linkID": "link-2", "scrapedStatus": "complete", "classifierStatus": "pending"},
    ]
    mock_api_client.get.return_value = mock_response

    result = runner.invoke(research_app, ["classify", "--vulnid", "VULN-123"])

    assert result.exit_code == 0
    assert "Classifier Triggers OK:      2" in result.stdout
    mock_api_client.get.assert_called_once_with("/vulnerability_records/VULN-123/data_sources")
    assert mock_api_client.post.call_count == 2

def test_classify_command_with_collection_succeeds(mock_api_client, mock_config_manager, tmp_path):
    """Test a successful 'classify' run with a collection file."""
    collection_file = tmp_path / "my-collection.txt"
    collection_file.write_text("VULN-001\nVULN-002")

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = [{"linkID": "link-1", "scrapedStatus": "complete", "classifierStatus": "new"}]
    mock_api_client.get.return_value = mock_response

    result = runner.invoke(research_app, ["classify", "--collection", "my-collection.txt"])

    assert result.exit_code == 0
    assert "Classifier Triggers OK:      2" in result.stdout
    assert mock_api_client.post.call_count == 2

def test_classify_command_skips_unscraped_sources(mock_api_client, mock_config_manager):
    """Test that 'classify' skips data sources that have not been scraped."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {"linkID": "link-1", "scrapedStatus": "new"},
        {"linkID": "link-2", "scrapedStatus": "pending"},
    ]
    mock_api_client.get.return_value = mock_response

    result = runner.invoke(research_app, ["classify", "--vulnid", "VULN-123"])

    assert result.exit_code == 0
    assert "Skipped (scrape incomplete): 2" in result.stdout
    mock_api_client.post.assert_not_called()

def test_classify_command_skips_classified_sources(mock_api_client, mock_config_manager):
    """Test that 'classify' skips data sources that have already been classified."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {"linkID": "link-1", "scrapedStatus": "complete", "classifierStatus": "complete"},
        {"linkID": "link-2", "scrapedStatus": "complete", "classifierStatus": "error"},
    ]
    mock_api_client.get.return_value = mock_response

    result = runner.invoke(research_app, ["classify", "--vulnid", "VULN-123"])

    assert result.exit_code == 0
    assert "Skipped (classifier status): 2" in result.stdout
    mock_api_client.post.assert_not_called()

def test_classify_auth_error_handling(mock_api_client, mock_config_manager):
    """Test graceful failure on AuthenticationError during 'classify'."""
    mock_api_client.get.side_effect = AuthenticationError("Invalid API Key")
    result = runner.invoke(research_app, ["classify", "--vulnid", "VULN-123"])
    assert result.exit_code == 1
    assert "API Error: Invalid API Key" in result.stdout

# --- Tests for the 'links' command ---

def test_links_command_no_identifier_fails():
    """Test that 'links' exits with an error if no identifier is provided."""
    result = runner.invoke(research_app, ["links"])
    assert result.exit_code == 1
    assert "Error: Please provide either a --collection or a --vulnid." in result.stdout

def test_links_command_both_identifiers_fail():
    """Test that 'links' exits with an error if both identifiers are provided."""
    result = runner.invoke(research_app, ["links", "--collection", "my-coll", "--vulnid", "VULN-123"])
    assert result.exit_code == 1
    assert "Error: Options --collection and --vulnid are mutually exclusive." in result.stdout

def test_links_command_with_vulnid_succeeds(mock_api_client, mock_config_manager):
    """Test a successful 'links' run with a single vulnID."""
    mock_vuln_response = MagicMock(spec=httpx.Response)
    mock_vuln_response.status_code = 200
    mock_vuln_response.json.return_value = {"cve_id": "CVE-2021-44228"}

    mock_data_response = MagicMock(spec=httpx.Response)
    mock_data_response.status_code = 200
    mock_data_response.json.return_value = [
        {
            "url": "http://example.com/webexploit",
            "cves": ["CVE-2021-44228"],
            "testCategory": "webExploit",
        }
    ]
    mock_api_client.get.side_effect = [mock_vuln_response, mock_data_response]

    result = runner.invoke(research_app, ["links", "--vulnid", "VULN-123"])
    output = strip_ansi(result.stdout)
    assert result.exit_code == 0
    assert "Data Sources for CVE-2021-44228 - VULN-123" in output
    assert "http://example.com/webexploit" in output

def test_links_command_no_data_sources(mock_api_client, mock_config_manager):
    """Test 'links' command when no data sources are found."""
    mock_vuln_response = MagicMock(spec=httpx.Response)
    mock_vuln_response.status_code = 200
    mock_vuln_response.json.return_value = {"cve_id": "CVE-2021-44228"}

    mock_data_response = MagicMock(spec=httpx.Response)
    mock_data_response.status_code = 404
    mock_api_client.get.side_effect = [mock_vuln_response, mock_data_response]

    result = runner.invoke(research_app, ["links", "--vulnid", "VULN-123"])
    assert result.exit_code == 0
    assert "No data sources found for CVE-2021-44228 - VULN-123" in result.stdout

def test_links_command_with_json_collection_uses_collection_cve_for_title(mock_api_client, mock_config_manager, tmp_path):
    """Test 'links' uses the CVE from the JSON collection for the title, not from the data source record."""
    # 1. Setup: Create a mock JSON collection file
    collection_dir = tmp_path / "collections"
    collection_dir.mkdir()
    collection_file = collection_dir / "my-collection.json"
    collection_file.write_text("""
    {
        "vulnerabilities": [
            {
                "cve_id": "CVE-FROM-COLLECTION", 
                "vuln_id": "VULN-123"
            }
        ]
    }
    """)

    # 2. Mock API responses
    # Only the data_sources endpoint should be called. The vuln_record endpoint should NOT be called.
    mock_data_response = MagicMock(spec=httpx.Response)
    mock_data_response.status_code = 200
    mock_data_response.json.return_value = [
        {
            "url": "http://example.com/exploit",
            "cves": ["CVE-FROM-DATASOURCE"], # This CVE should appear in the row, not the title
            "testCategory": "webExploit",
        }
    ]
    # We are NOT using side_effect here because only one type of GET call is expected.
    mock_api_client.get.return_value = mock_data_response

    # 3. Run the command
    result = runner.invoke(research_app, ["links", "--collection", "my-collection"])
    output = strip_ansi(result.stdout)

    # 4. Assert
    assert result.exit_code == 0
    # The API call to get the vuln record should have been skipped
    mock_api_client.get.assert_called_once_with("/vulnerability_records/VULN-123/data_sources/")
    
    # Assert the title uses the CVE from the collection file
    assert "Data Sources for CVE-FROM-COLLECTION - VULN-123" in output
    
    # Assert the table content is correct
    assert "http://example.com/exploit" in output
    assert "CVE-FROM-DATASOURCE" in output


def test_links_command_with_txt_collection_fetches_cve_for_title(mock_api_client, mock_config_manager, tmp_path):
    """Test 'links' fetches the CVE from the API for the title when using a .txt collection."""
    # 1. Setup: Create a mock .txt collection file
    collection_file = tmp_path / "my-collection.txt"
    collection_file.write_text("VULN-123")

    # 2. Mock API responses for both the vuln record and the data sources
    mock_vuln_response = MagicMock(spec=httpx.Response)
    mock_vuln_response.status_code = 200
    mock_vuln_response.json.return_value = {"cve_id": "CVE-FETCHED-FROM-API"}

    mock_data_response = MagicMock(spec=httpx.Response)
    mock_data_response.status_code = 200
    mock_data_response.json.return_value = [
        {
            "url": "http://example.com/exploit",
            "cves": ["CVE-FROM-DATASOURCE"],
        }
    ]
    # The command should first fetch the vuln record, then the data sources
    mock_api_client.get.side_effect = [mock_vuln_response, mock_data_response]

    # 3. Run the command
    result = runner.invoke(research_app, ["links", "--collection", "my-collection.txt"])
    output = strip_ansi(result.stdout)
    
    # 4. Assert
    assert result.exit_code == 0
    # Assert both API calls were made in the correct order
    mock_api_client.get.assert_has_calls([
        call("/vulnerability_records/VULN-123"),
        call("/vulnerability_records/VULN-123/data_sources/")
    ])
    
    # Assert the title uses the CVE fetched from the API
    assert "Data Sources for CVE-FETCHED-FROM-API - VULN-123" in output
    
    # Assert the table content is correct
    assert "http://example.com/exploit" in output
    assert "CVE-FROM-DATASOURCE" in output


def test_links_command_styling(mock_api_client, mock_config_manager):
    """Test the styling logic for the 'links' command."""
    mock_vuln_response = MagicMock(spec=httpx.Response)
    mock_vuln_response.status_code = 200
    mock_vuln_response.json.return_value = {"cve_id": "CVE-2021-44228"}

    mock_data_response = MagicMock(spec=httpx.Response)
    mock_data_response.status_code = 200
    mock_data_response.json.return_value = [
        {
            "url": "http://example.com/webexploit",
            "cves": ["CVE-2021-44228"],
            "testCategory": "webExploit",
        },
        {
            "url": "http://example.com/nonWebExploit",
            "cves": ["CVE-2021-44228"],
            "testCategory": "nonWebExploit",
        },
        {
            "url": "http://example.com/non-test",
            "cves": ["CVE-2021-44228"],
            "testCategory": "Non-test",
        },
        {
            "url": "http://example.com/classified-complete",
            "cves": ["CVE-2021-44228"],
            "classifierStatus": "complete",
        },
        {
            "url": "http://example.com/scraped-complete",
            "cves": ["CVE-2021-44228"],
            "scrapedStatus": "complete",
        },
        {
            "url": "http://example.com/default",
            "cves": ["CVE-2021-44228"],
        },
    ]
    mock_api_client.get.side_effect = [mock_vuln_response, mock_data_response]

    result = runner.invoke(research_app, ["links", "--vulnid", "VULN-123"])
    output = strip_ansi(result.stdout)
    assert result.exit_code == 0
    assert "http://example.com/webexploit" in output
    assert "http://example.com/nonWebExploit" in output
    assert "http://example.com/non-test" in output
    assert "http://example.com/classified-complete" in output
    assert "http://example.com/scraped-complete" in output
    assert "http://example.com/default" in output