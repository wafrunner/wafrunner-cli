import pytest
from typer.testing import CliRunner
from pathlib import Path
import json
import time
from datetime import datetime
from typing import Any, Dict

from wafrunner_cli.commands.cve import app as cve_app
from wafrunner_cli.core.exceptions import AuthenticationError

runner = CliRunner()

# --- Fixtures for mocking ---


@pytest.fixture
def mock_api_client(mocker):
    """Mocks the ApiClient methods for controlling API responses."""
    mock_client = mocker.MagicMock()
    mocker.patch("wafrunner_cli.commands.cve.ApiClient", return_value=mock_client)
    return mock_client


@pytest.fixture
def mock_load_tracking(mocker):
    """Mocks load_uploaded_cves_tracking to control initial tracking state."""
    return mocker.patch(
        "wafrunner_cli.commands.cve.load_uploaded_cves_tracking", return_value={}
    )


@pytest.fixture
def mock_save_tracking(mocker):
    """Mocks save_uploaded_cves_tracking to capture saved data."""
    return mocker.patch("wafrunner_cli.commands.cve.save_uploaded_cves_tracking")


@pytest.fixture
def mock_transform_vulnerability(mocker):
    """Mocks transform_vulnerability to return a consistent payload."""
    return mocker.patch(
        "wafrunner_cli.commands.cve.transform_vulnerability",
        return_value={"cveID": "CVE-TEST-1234", "name": "Test Vuln"},
    )


@pytest.fixture
def mock_time_sleep(mocker):
    """Mocks time.sleep to prevent actual delays."""
    return mocker.patch("time.sleep")


@pytest.fixture
def mock_path_methods_for_tracking(mocker):
    """Mocks Path.exists and Path.mkdir for the tracking file path."""
    mocker.patch("pathlib.Path.exists", return_value=True)  # Assume input_dir exists
    mocker.patch("pathlib.Path.mkdir")
    # Mock the tracking file path specifically
    mocker.patch(
        "wafrunner_cli.commands.cve.get_uploaded_cves_tracking_path",
        return_value=Path("/tmp/uploaded_cves.json"),
    )


# --- Helper for creating mock CVE data ---
def create_mock_cve_data(cve_id: str, last_modified: str) -> Dict[str, Any]:
    return {
        "cve": {"id": cve_id, "lastModified": last_modified},
        "vulnerabilities": [{"cve": {"id": cve_id, "lastModified": last_modified}}],
    }


# --- Test Cases ---


def test_upload_new_cve(
    mocker,
    mock_api_client,
    mock_load_tracking,
    mock_save_tracking,
    mock_transform_vulnerability,
    mock_time_sleep,
    mock_path_methods_for_tracking,
):
    """Test that a new CVE is created and tracked."""
    cve_id = "CVE-2023-0001"
    last_modified = "2023-01-01T00:00:00.000Z"
    mock_api_client.get.return_value = None  # CVE not found in wafrunner
    mock_api_client.post.return_value = mocker.Mock(status_code=201)  # Successful creation
    mocker.patch(
        "glob.glob",
        return_value=[Path("/tmp/cve_data.json")],
    )
    mocker.patch(
        "builtins.open",
        mocker.mock_open(read_data=json.dumps(create_mock_cve_data(cve_id, last_modified))),
    )

    result = runner.invoke(cve_app, ["upload", "--input-dir", "/tmp"])

    assert result.exit_code == 0
    assert "Successfully Created: 1" in result.stdout
    mock_api_client.post.assert_called_once()
    mock_save_tracking.assert_called_once_with({cve_id: last_modified})


def test_upload_skipped_unmodified_cve(
    mocker,
    mock_api_client,
    mock_load_tracking,
    mock_save_tracking,
    mock_transform_vulnerability,
    mock_time_sleep,
    mock_path_methods_for_tracking,
):
    """Test that an unmodified CVE is skipped when --force is not used."""
    cve_id = "CVE-2023-0002"
    last_modified = "2023-01-01T00:00:00.000Z"
    mock_load_tracking.return_value = {cve_id: last_modified}  # Already tracked
    mocker.patch(
        "glob.glob",
        return_value=[Path("/tmp/cve_data.json")],
    )
    mocker.patch(
        "builtins.open",
        mocker.mock_open(read_data=json.dumps(create_mock_cve_data(cve_id, last_modified))),
    )

    result = runner.invoke(cve_app, ["upload", "--input-dir", "/tmp"])

    assert result.exit_code == 0
    assert "Skipped (Unmodified): 1" in result.stdout
    mock_api_client.get.assert_not_called()  # Should not query wafrunner API
    mock_api_client.post.assert_not_called()
    mock_api_client.put.assert_not_called()
    mock_save_tracking.assert_called_once_with({cve_id: last_modified})


def test_upload_modified_cve_updates(
    mocker,
    mock_api_client,
    mock_load_tracking,
    mock_save_tracking,
    mock_transform_vulnerability,
    mock_time_sleep,
    mock_path_methods_for_tracking,
):
    """Test that a modified CVE is updated and tracking is refreshed."""
    cve_id = "CVE-2023-0003"
    old_last_modified = "2023-01-01T00:00:00.000Z"
    new_last_modified = "2023-01-02T00:00:00.000Z"
    mock_load_tracking.return_value = {cve_id: old_last_modified}
    mock_api_client.get.return_value = [{"vulnID": "VULN-ID-003"}]  # CVE found
    mock_api_client.put.return_value = mocker.Mock(status_code=200)  # Successful update
    mocker.patch(
        "glob.glob",
        return_value=[Path("/tmp/cve_data.json")],
    )
    mocker.patch(
        "builtins.open",
        mocker.mock_open(read_data=json.dumps(create_mock_cve_data(cve_id, new_last_modified))),
    )

    result = runner.invoke(cve_app, ["upload", "--input-dir", "/tmp"])

    assert result.exit_code == 0
    assert "Successfully Updated: 1" in result.stdout
    mock_api_client.put.assert_called_once()
    mock_save_tracking.assert_called_once_with({cve_id: new_last_modified})


def test_upload_force_unmodified_cve_updates(
    mocker,
    mock_api_client,
    mock_load_tracking,
    mock_save_tracking,
    mock_transform_vulnerability,
    mock_time_sleep,
    mock_path_methods_for_tracking,
):
    """Test that an unmodified CVE is updated when --force is used."""
    cve_id = "CVE-2023-0004"
    last_modified = "2023-01-01T00:00:00.000Z"
    mock_load_tracking.return_value = {cve_id: last_modified}
    mock_api_client.get.return_value = [{"vulnID": "VULN-ID-004"}]  # CVE found
    mock_api_client.put.return_value = mocker.Mock(status_code=200)  # Successful update
    mocker.patch(
        "glob.glob",
        return_value=[Path("/tmp/cve_data.json")],
    )
    mocker.patch(
        "builtins.open",
        mocker.mock_open(read_data=json.dumps(create_mock_cve_data(cve_id, last_modified))),
    )

    result = runner.invoke(cve_app, ["upload", "--input-dir", "/tmp", "--force"])

    assert result.exit_code == 0
    assert "Successfully Updated: 1" in result.stdout
    mock_api_client.put.assert_called_once()
    mock_save_tracking.assert_called_once_with({cve_id: last_modified})


def test_upload_conflict_cve_is_skipped_and_tracked(
    mocker,
    mock_api_client,
    mock_load_tracking,
    mock_save_tracking,
    mock_transform_vulnerability,
    mock_time_sleep,
    mock_path_methods_for_tracking,
):
    """Test that a CVE causing a 409 conflict is skipped and tracked."""
    cve_id = "CVE-2023-0005"
    last_modified = "2023-01-01T00:00:00.000Z"
    mock_api_client.get.return_value = None  # CVE not found in wafrunner
    mock_api_client.post.return_value = mocker.Mock(status_code=409)  # Conflict
    mocker.patch(
        "glob.glob",
        return_value=[Path("/tmp/cve_data.json")],
    )
    mocker.patch(
        "builtins.open",
        mocker.mock_open(read_data=json.dumps(create_mock_cve_data(cve_id, last_modified))),
    )

    result = runner.invoke(cve_app, ["upload", "--input-dir", "/tmp"])

    assert result.exit_code == 0
    assert "Skipped (Conflict): 1" in result.stdout
    mock_api_client.post.assert_called_once()
    mock_save_tracking.assert_called_once_with({cve_id: last_modified})


def test_upload_api_error_not_tracked(
    mocker,
    mock_api_client,
    mock_load_tracking,
    mock_save_tracking,
    mock_transform_vulnerability,
    mock_time_sleep,
    mock_path_methods_for_tracking,
):
    """Test that a CVE causing an API error is not tracked."""
    cve_id = "CVE-2023-0006"
    last_modified = "2023-01-01T00:00:00.000Z"
    mock_api_client.get.return_value = None
    mock_api_client.post.return_value = mocker.Mock(
        status_code=500, text="Internal Server Error"
    )  # API error
    mocker.patch(
        "glob.glob",
        return_value=[Path("/tmp/cve_data.json")],
    )
    mocker.patch(
        "builtins.open",
        mocker.mock_open(read_data=json.dumps(create_mock_cve_data(cve_id, last_modified))),
    )

    result = runner.invoke(cve_app, ["upload", "--input-dir", "/tmp"])

    assert result.exit_code == 0
    assert "Errors: 1" in result.stdout
    assert "Create Failed: 1" in result.stdout
    mock_api_client.post.assert_called_once()
    mock_save_tracking.assert_called_once_with({})  # Tracking file should not be updated for this CVE


def test_upload_skipped_missing_cveid(
    mocker,
    mock_api_client,
    mock_load_tracking,
    mock_save_tracking,
    mock_transform_vulnerability,
    mock_time_sleep,
    mock_path_methods_for_tracking,
):
    """Test that a record missing a cveID is skipped."""
    # Mock data without a 'cve.id'
    mock_cve_data = {"cve": {"lastModified": "2023-01-01T00:00:00.000Z"}}
    mocker.patch(
        "glob.glob",
        return_value=[Path("/tmp/cve_data.json")],
    )
    mocker.patch(
        "builtins.open",
        mocker.mock_open(read_data=json.dumps(mock_cve_data)),
    )

    result = runner.invoke(cve_app, ["upload", "--input-dir", "/tmp"])

    assert result.exit_code == 0
    assert "Skipped (No CVE ID): 1" in result.stdout
    mock_api_client.get.assert_not_called()
    mock_api_client.post.assert_not_called()
    mock_api_client.put.assert_not_called()
    mock_save_tracking.assert_called_once_with({})