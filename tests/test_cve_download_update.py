import pytest
from typer.testing import CliRunner
from pathlib import Path
import json
import time
from datetime import datetime, timedelta

from wafrunner_cli.commands.cve import app as cve_app
from wafrunner_cli.commands.cve import (
    NIST_API_BASE_URL,
    RESULTS_PER_PAGE,
    REQUEST_DELAY_SECONDS,
    MAX_RETRIES,
    API_RETRY_DELAY,
    CHUNK_DAYS,
    isoformat_utc,
    generate_date_chunks_for_year,
    is_error_file, # Import the actual function to test it directly
)

runner = CliRunner()

# --- Fixtures for mocking ---

@pytest.fixture
def mock_path_methods(mocker):
    """Mocks Path.exists and Path.mkdir."""
    mock_exists = mocker.patch("pathlib.Path.exists", return_value=False)
    mock_mkdir = mocker.patch("pathlib.Path.mkdir")
    return mock_exists, mock_mkdir

@pytest.fixture
def mock_json_io(mocker):
    """Mocks json.load and json.dump."""
    mock_json_load = mocker.patch("json.load", return_value={})
    mock_json_dump = mocker.patch("json.dump")
    return mock_json_load, mock_json_dump

@pytest.fixture
def mock_time_sleep(mocker):
    """Mocks time.sleep."""
    return mocker.patch("time.sleep")

@pytest.fixture
def mock_download_cves_for_range(mocker):
    """Mocks the download_cves_for_range function."""
    return mocker.patch("wafrunner_cli.commands.cve.download_cves_for_range")

@pytest.fixture
def mock_is_error_file_func(mocker):
    """Mocks the is_error_file function (for controlling its return value in command tests)."""
    return mocker.patch("wafrunner_cli.commands.cve.is_error_file", return_value=False)

@pytest.fixture
def mock_progress(mocker):
    """Mocks rich.progress.Progress to prevent actual rendering."""
    mock_progress_instance = mocker.MagicMock()
    mocker.patch("wafrunner_cli.commands.cve.Progress", return_value=mock_progress_instance)
    return mock_progress_instance

@pytest.fixture
def mock_httpx_client(mocker):
    """Mocks httpx.Client for NIST API calls."""
    mock_client_instance = mocker.MagicMock()
    mocker.patch("httpx.Client", return_value=mock_client_instance)
    return mock_client_instance

# --- Test cases for --update flag in the download command ---

def test_download_no_update_file_exists_valid(
    mock_path_methods, mock_json_io, mock_time_sleep, mock_download_cves_for_range, mock_is_error_file_func, mock_progress, mock_httpx_client
):
    """
    Test download command when --update is False, file exists and is valid.
    Should skip download.
    """
    mock_path_methods[0].return_value = True  # Path.exists returns True
    mock_is_error_file_func.return_value = False  # File is not an error file

    year = 2023
    result = runner.invoke(cve_app, ["download", "--year", str(year)])

    assert result.exit_code == 0
    assert "already exists and appears valid. Skipping." in result.stdout
    mock_download_cves_for_range.assert_not_called()
    mock_path_methods[1].assert_called_once() # mkdir should still be called for the default path

def test_download_no_update_file_exists_invalid(
    mock_path_methods, mock_json_io, mock_time_sleep, mock_download_cves_for_range, mock_is_error_file_func, mock_progress, mock_httpx_client
):
    """
    Test download command when --update is False, file exists but is invalid.
    Should re-download.
    """
    mock_path_methods[0].return_value = True  # Path.exists returns True
    mock_is_error_file_func.return_value = True  # File is an error file

    year = 2023
    result = runner.invoke(cve_app, ["download", "--year", str(year)])

    assert result.exit_code == 0

    assert "exists but is incomplete or has errors." in result.stdout
    assert "Re-downloading." in result.stdout

    # For 2023, generate_date_chunks_for_year creates 4 chunks (365 / 120 = 3.04)
    assert mock_download_cves_for_range.call_count == 4
    mock_path_methods[1].assert_called_once() # mkdir should still be called for the default path

def test_download_update_file_exists_valid(
    mock_path_methods, mock_json_io, mock_time_sleep, mock_download_cves_for_range, mock_is_error_file_func, mock_progress, mock_httpx_client
):
    """
    Test download command when --update is True, file exists and is valid.
    Should re-download.
    """
    mock_path_methods[0].return_value = True  # Path.exists returns True
    mock_is_error_file_func.return_value = False  # File is not an error file (this call still happens but is ignored for decision)

    year = 2023
    result = runner.invoke(cve_app, ["download", "--year", str(year), "--update"])

    assert result.exit_code == 0
    assert "Data will be saved to" in result.stdout # Initial message
    assert "Update mode: True" in result.stdout
    assert "re-downloading due to --update flag" in result.stdout # Because update is True
    assert mock_download_cves_for_range.call_count == 4
    mock_path_methods[1].assert_called_once() # mkdir should still be called for the default path

def test_download_no_update_file_does_not_exist(
    mock_path_methods, mock_json_io, mock_time_sleep, mock_download_cves_for_range, mock_is_error_file_func, mock_progress, mock_httpx_client
):
    """
    Test download command when --update is False, file does not exist.
    Should download.
    """
    mock_path_methods[0].return_value = False  # Path.exists returns False

    year = 2023
    result = runner.invoke(cve_app, ["download", "--year", str(year)])

    assert result.exit_code == 0
    assert "Data will be saved to" in result.stdout # Initial message
    assert "Update mode: False" in result.stdout
    assert mock_download_cves_for_range.call_count == 4
    mock_path_methods[1].assert_called_once() # mkdir should still be called for the default path

def test_download_update_file_does_not_exist(
    mock_path_methods, mock_json_io, mock_time_sleep, mock_download_cves_for_range, mock_is_error_file_func, mock_progress, mock_httpx_client
):
    """
    Test download command when --update is True, file does not exist.
    Should download.
    """
    mock_path_methods[0].return_value = False  # Path.exists returns False

    year = 2023
    result = runner.invoke(cve_app, ["download", "--year", str(year), "--update"])

    assert result.exit_code == 0
    assert "Data will be saved to" in result.stdout # Initial message
    assert "Update mode: True" in result.stdout
    assert mock_download_cves_for_range.call_count == 4
    mock_path_methods[1].assert_called_once() # mkdir should still be called for the default path

# --- Test cases for the is_error_file function itself ---

def test_is_error_file_missing_file(mocker):
    """Test is_error_file with a non-existent file."""
    mock_open = mocker.patch("builtins.open", side_effect=FileNotFoundError)
    mock_print = mocker.patch("wafrunner_cli.commands.cve.print")
    assert is_error_file(Path("non_existent.json")) is True
    mock_print.assert_called_with(mocker.ANY, 'Error reading or decoding non_existent.json: [Errno 2] No such file or directory. Flagging for re-download.')

def test_is_error_file_invalid_json(mocker):
    """Test is_error_file with a file containing invalid JSON."""
    mock_open = mocker.patch("builtins.open", mocker.mock_open(read_data="invalid json"))
    mock_print = mocker.patch("wafrunner_cli.commands.cve.print")
    assert is_error_file(Path("invalid.json")) is True
    mock_print.assert_called_with(mocker.ANY, 'Error reading or decoding invalid.json: Expecting value: line 1 column 1 (char 0). Flagging for re-download.')

def test_is_error_file_incomplete_status(mocker):
    """Test is_error_file with a file having 'incomplete' download_status."""
    mock_open = mocker.patch("builtins.open", mocker.mock_open(read_data=json.dumps({"download_status": "incomplete", "totalResults": 10, "vulnerabilities": []})))
    mock_print = mocker.patch("wafrunner_cli.commands.cve.print")
    assert is_error_file(Path("incomplete.json")) is True
    mock_print.assert_called_with(mocker.ANY, "File incomplete.json has download status 'incomplete'. Flagging for re-download.")

def test_is_error_file_total_mismatch(mocker):
    """Test is_error_file with totalResults not matching actual vulnerabilities count."""
    mock_open = mocker.patch("builtins.open", mocker.mock_open(read_data=json.dumps({"download_status": "complete", "totalResults": 10, "vulnerabilities": [{"cve": {"id": "CVE-2023-1234"}}]})))
    mock_print = mocker.patch("wafrunner_cli.commands.cve.print")
    assert is_error_file(Path("mismatch.json")) is True
    mock_print.assert_called_with(mocker.ANY, 'File mismatch.json has totalResults=10 but contains 1 vulnerabilities. Flagging for re-download.')

def test_is_error_file_empty_results(mocker):
    """Test is_error_file with totalResults 0 and empty vulnerabilities."""
    mock_open = mocker.patch("builtins.open", mocker.mock_open(read_data=json.dumps({"totalResults": 0, "vulnerabilities": []})))
    mock_print = mocker.patch("wafrunner_cli.commands.cve.print")
    assert is_error_file(Path("empty.json")) is True
    # No warning for this specific case, as it's a valid "no results" scenario that still needs re-checking
    mock_print.assert_not_called() 

def test_is_error_file_valid_file(mocker):
    """Test is_error_file with a valid, complete file."""
    mock_open = mocker.patch("builtins.open", mocker.mock_open(read_data=json.dumps({"download_status": "complete", "totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2023-1234"}}]})))
    mock_print = mocker.patch("wafrunner_cli.commands.cve.print")
    assert is_error_file(Path("valid.json")) is False
    mock_print.assert_not_called()