import pytest
from typer.testing import CliRunner
from pathlib import Path
import json
from unittest.mock import MagicMock, call
import httpx
import typer

# The application object from the script being tested.
from wafrunner_cli.commands.cve import app as cve_app

# Use a fixed runner instance for all tests.
runner = CliRunner()


# --- Fixtures for Mocking and Test Setup ---

@pytest.fixture
def mock_api_client(mocker):
    """Mocks the ApiClient to control API responses during tests."""
    mock_client = mocker.MagicMock()
    # Patch the ApiClient constructor to return our mock instance.
    mocker.patch("wafrunner_cli.commands.cve.ApiClient", return_value=mock_client)
    return mock_client


@pytest.fixture
def mock_tracking_io(mocker):
    """Mocks the file I/O for the CVE tracking file."""
    mock_load = mocker.patch("wafrunner_cli.commands.cve.load_uploaded_cves_tracking", return_value={})
    mock_save = mocker.patch("wafrunner_cli.commands.cve.save_uploaded_cves_tracking")
    return mock_load, mock_save


@pytest.fixture
def mock_time_sleep(mocker):
    """Mocks time.sleep to speed up tests by preventing actual delays."""
    return mocker.patch("time.sleep")


# --- Helper for Creating Mock CVE Data ---

def create_mock_cve_file(cve_dir: Path, file_name: str, cve_records: list):
    """
    Creates a mock NVD JSON file with a more complete structure
    to ensure transformations work as expected.
    """
    file_path = cve_dir / file_name
    content = {"vulnerabilities": []}
    for record_info in cve_records:
        cve_id = record_info.get("id") # Can be None for missing cve_id test
        cve_item = {
                "cve": {
                    "id": cve_id, # This will be None if not provided
                    "lastModified": record_info.get("lastModified", "2024-01-01T00:00:00.000Z"),
                    # Add other fields the transformer looks for, even if empty, to prevent errors.
                    "descriptions": [{"lang": "en", "value": f"Description for {cve_id}"}],
                    "weaknesses": [],
                    "metrics": {},
                }
            }
        content["vulnerabilities"].append(cve_item)
    file_path.write_text(json.dumps(content))


# --- Fixtures for Test Setup ---

@pytest.fixture
def cve_input_dir(tmp_path: Path) -> Path:
    """Creates a temporary directory for mock CVE JSON files."""
    cve_dir = tmp_path / "cve-sources"
    cve_dir.mkdir()
    return cve_dir


# --- Test Cases ---

def test_upload_new_cve_is_created(cve_input_dir, mock_api_client, mock_tracking_io, mock_time_sleep): # Removed mock_transform_vulnerability
    cve_id = "CVE-2024-0001"
    last_modified = "2024-01-01T00:00:00.000Z"
    vuln_id = "VULN-ID-NEW-001" # Example vulnID for new creation
    mock_load, mock_save = mock_tracking_io
    create_mock_cve_file(cve_input_dir, "cve1.json", [{"id": cve_id, "lastModified": last_modified}])

    mock_api_client.get.return_value = MagicMock(status_code=404) # CVE not found
    mock_api_client.post.return_value = MagicMock(status_code=201, json=lambda: {"vulnID": vuln_id}) # Successful creation

    result = runner.invoke(cve_app, ["upload", "--input-dir", str(cve_input_dir)])

    assert result.exit_code == 0
    assert "Successfully Created" in result.stdout # Check for the outcome string
    assert "1" in result.stdout # Check for the count
    mock_api_client.get.assert_called_once()
    mock_api_client.post.assert_called_once()
    mock_save.assert_called_once_with({cve_id: {"lastModified": last_modified, "vulnID": vuln_id}})


def test_upload_existing_cve_is_skipped_by_default(cve_input_dir, mock_api_client, mock_tracking_io, mock_time_sleep): # Removed mock_transform_vulnerability
    cve_id = "CVE-2024-0002"
    last_modified = "2024-01-01T00:00:00.000Z"
    vuln_id = "VULN-ID-002"
    mock_load, mock_save = mock_tracking_io
    create_mock_cve_file(cve_input_dir, "cve2.json", [{"id": cve_id, "lastModified": last_modified}])

    mock_load.return_value = {cve_id: {"lastModified": last_modified, "vulnID": vuln_id}} # CVE is already tracked
    # Mock API to return that the CVE exists if it's queried (though it shouldn't be in this test)
    mock_api_client.get.return_value = MagicMock(status_code=200, json=lambda: [{"vulnID": vuln_id, "cveID": cve_id}])

    result = runner.invoke(cve_app, ["upload", "--input-dir", str(cve_input_dir)])

    assert result.exit_code == 0
    assert "Skipped (Existing, No --update)" in result.stdout # Check for the outcome string
    assert "1" in result.stdout # Check for the count
    # API calls should NOT be made because it was skipped based on local tracking.
    mock_api_client.get.assert_not_called() # No GET call if skipped by local tracking
    mock_api_client.put.assert_not_called()
    mock_api_client.post.assert_not_called()
    mock_save.assert_called_once_with(mock_load.return_value)


def test_upload_with_update_flag_updates_modified_cve(cve_input_dir, mock_api_client, mock_tracking_io, mock_time_sleep): # Removed mock_transform_vulnerability
    cve_id = "CVE-2024-0003"
    vuln_id = "VULN-ID-003"
    old_last_modified = "2024-01-01T00:00:00.000Z"
    new_last_modified = "2024-02-01T00:00:00.000Z"
    mock_load, mock_save = mock_tracking_io
    create_mock_cve_file(cve_input_dir, "cve3.json", [{"id": cve_id, "lastModified": new_last_modified}])

    mock_load.return_value = {cve_id: {"lastModified": old_last_modified, "vulnID": vuln_id}} # CVE is tracked but modified
    mock_api_client.put.return_value = MagicMock(status_code=200) # Successful update

    result = runner.invoke(cve_app, ["upload", "--input-dir", str(cve_input_dir), "--update"])

    assert result.exit_code == 0
    assert "Successfully Updated" in result.stdout # Check for the outcome string
    assert "1" in result.stdout # Check for the count
    mock_api_client.get.assert_not_called() # No GET call needed as vulnID is known from tracking
    mock_api_client.put.assert_called_once()
    mock_save.assert_called_once_with({cve_id: {"lastModified": new_last_modified, "vulnID": vuln_id}})


def test_upload_with_update_flag_skips_unmodified_cve(cve_input_dir, mock_api_client, mock_tracking_io, mock_time_sleep): # Removed mock_transform_vulnerability
    cve_id = "CVE-2024-0004"
    last_modified = "2024-01-01T00:00:00.000Z"
    vuln_id = "VULN-ID-004"
    mock_load, mock_save = mock_tracking_io
    create_mock_cve_file(cve_input_dir, "cve4.json", [{"id": cve_id, "lastModified": last_modified}])
    mock_load.return_value = {cve_id: {"lastModified": last_modified, "vulnID": vuln_id}}

    result = runner.invoke(cve_app, ["upload", "--input-dir", str(cve_input_dir), "--update"])
    
    assert result.exit_code == 0
    assert "Skipped (Unmodified)" in result.stdout # Check for the outcome string
    assert "1" in result.stdout # Check for the count
    mock_api_client.get.assert_not_called()
    mock_api_client.put.assert_not_called()


def test_upload_with_force_and_update_flags_updates_unmodified(cve_input_dir, mock_api_client, mock_tracking_io, mock_time_sleep): # Removed mock_transform_vulnerability
    cve_id = "CVE-2024-0005"
    last_modified = "2024-01-01T00:00:00.000Z"
    vuln_id = "VULN-ID-005"
    mock_load, mock_save = mock_tracking_io
    create_mock_cve_file(cve_input_dir, "cve5.json", [{"id": cve_id, "lastModified": last_modified}])
    mock_load.return_value = {cve_id: {"lastModified": last_modified, "vulnID": vuln_id}}
    mock_api_client.put.return_value = MagicMock(status_code=200) # Successful update

    result = runner.invoke(cve_app, ["upload", "--input-dir", str(cve_input_dir), "--update", "--force"])

    assert result.exit_code == 0
    assert "Successfully Updated" in result.stdout # Check for the outcome string
    assert "1" in result.stdout # Check for the count
    mock_api_client.put.assert_called_once()
    mock_save.assert_called_once_with({cve_id: {"lastModified": last_modified, "vulnID": vuln_id}})


def test_upload_force_without_update_fails(cve_input_dir):
    """
    Tests that using --force without --update is an error and exits.
    """
    result = runner.invoke(cve_app, ["upload", "--input-dir", str(cve_input_dir), "--force"])
    assert result.exit_code == 1
    assert "Error: --force can only be used in combination with --update" in result.stdout


def test_upload_conflict_cve_is_skipped_and_tracked(cve_input_dir, mock_api_client, mock_tracking_io, mock_time_sleep): # Removed mock_transform_vulnerability
    cve_id = "CVE-2024-0006"
    last_modified = "2024-01-01T00:00:00.000Z"
    mock_load, mock_save = mock_tracking_io
    create_mock_cve_file(cve_input_dir, "cve6.json", [{"id": cve_id, "lastModified": last_modified}])

    # Initial GET: CVE not found (404)
    mock_api_client.get.return_value = MagicMock(status_code=404)
    # POST: Conflict (409)
    mock_api_client.post.return_value = MagicMock(status_code=409)

    result = runner.invoke(cve_app, ["upload", "--input-dir", str(cve_input_dir)])

    assert result.exit_code == 0
    assert "Skipped (Conflict)" in result.stdout # Check for the outcome string
    assert "1" in result.stdout # Check for the count
    mock_api_client.get.assert_called_once() # Initial check
    mock_api_client.post.assert_called_once()
    mock_save.assert_called_once_with({cve_id: {"lastModified": last_modified, "vulnID": None}}) # Should track as skipped conflict, no vulnID


def test_upload_api_error_not_tracked(cve_input_dir, mock_api_client, mock_tracking_io, mock_time_sleep): # Removed mock_transform_vulnerability
    cve_id = "CVE-2024-0007"
    last_modified = "2024-01-01T00:00:00.000Z"
    mock_load, mock_save = mock_tracking_io
    create_mock_cve_file(cve_input_dir, "cve7.json", [{"id": cve_id, "lastModified": last_modified}])

    mock_api_client.get.return_value = MagicMock(status_code=404) # CVE not found
    mock_api_client.post.return_value = MagicMock(status_code=500, text="Internal Server Error") # API error

    result = runner.invoke(cve_app, ["upload", "--input-dir", str(cve_input_dir)])

    assert result.exit_code == 0
    assert "Errors" in result.stdout # Check for total errors
    assert "1" in result.stdout # Check for total errors count
    assert "Error Create Failed" in result.stdout # Check for specific error count
    mock_api_client.post.assert_called_once()
    mock_save.assert_called_once_with(mock_load.return_value) # Tracking should not be updated for errors


def test_upload_skipped_missing_cveid(cve_input_dir, mock_api_client, mock_tracking_io, mock_time_sleep): # Removed mock_transform_vulnerability
    # Create a mock CVE file with a record missing the 'id' field
    mock_load, mock_save = mock_tracking_io
    create_mock_cve_file(cve_input_dir, "cve_missing_id.json", [{"lastModified": "2024-01-01T00:00:00.000Z"}])

    result = runner.invoke(cve_app, ["upload", "--input-dir", str(cve_input_dir)])

    assert result.exit_code == 0
    assert "Skipped (No CVE ID)" in result.stdout # Check for the outcome string
    assert "1" in result.stdout # Check for the count
    mock_api_client.get.assert_not_called() # No API calls should be made for skipped records
    mock_api_client.post.assert_not_called()
    mock_save.assert_called_once_with(mock_load.return_value) # Tracking should not be updated for skipped records
