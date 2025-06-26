import pytest
from pathlib import Path
import json
import time
from datetime import datetime, timedelta
import httpx

# Import the specific function and constants from the module
from wafrunner_cli.commands.cve import (
    download_cves_for_range,
    NIST_API_BASE_URL, # Not directly used in download_cves_for_range, but good for context
    RESULTS_PER_PAGE,
    REQUEST_DELAY_SECONDS,
    MAX_RETRIES,
    API_RETRY_DELAY,
    CHUNK_DAYS, # Not directly used in download_cves_for_range, but good for context
    isoformat_utc, # Not directly used in download_cves_for_range, but good for context
    generate_date_chunks_for_year, # Not directly used in download_cves_for_range, but good for context
    fetch_nist_page # The function whose interaction we are testing
)
from rich.progress import Progress, TaskID # For type hinting in fixtures

# --- Fixtures ---

@pytest.fixture
def mock_httpx_client_instance(mocker):
    """Mocks an httpx.Client instance."""
    return mocker.MagicMock(spec=httpx.Client)

@pytest.fixture
def mock_overall_progress(mocker):
    """Mocks rich.progress.Progress instance and its methods."""
    # Mock the Progress class itself, and its instance methods
    mock_progress_instance = mocker.MagicMock()
    mock_progress_instance.add_task.return_value = mocker.MagicMock() # Mock TaskID
    mocker.patch("wafrunner_cli.commands.cve.Progress", return_value=mock_progress_instance)
    return mock_progress_instance

@pytest.fixture
def mock_overall_task_id(mocker):
    """Mocks a rich.progress.TaskID. This is the parent task ID passed to download_cves_for_range."""
    return mocker.MagicMock()

@pytest.fixture
def mock_fetch_nist_page(mocker):
    """Mocks the fetch_nist_page function."""
    return mocker.patch("wafrunner_cli.commands.cve.fetch_nist_page")

@pytest.fixture
def mock_json_dump(mocker):
    """Mocks json.dump."""
    return mocker.patch("json.dump")

@pytest.fixture
def mock_time_sleep(mocker):
    """Mocks time.sleep."""
    return mocker.patch("time.sleep")

@pytest.fixture
def mock_rich_print(mocker):
    """Mocks rich.print."""
    return mocker.patch("rich.print")

# --- Test Data ---
TEST_START_DATE = "2023-01-01T00:00:00.000Z"
TEST_END_DATE = "2023-04-30T23:59:59.999Z"
TEST_OUTPUT_FILE = Path("/tmp/test_cve_chunk.json")

def create_mock_nist_response(total_results, current_page_count, start_index):
    """Helper to create a mock NIST API response structure."""
    vulnerabilities = []
    for i in range(current_page_count):
        vulnerabilities.append({"cve": {"id": f"CVE-TEST-{start_index + i}"}})
    return {
        "totalResults": total_results,
        "vulnerabilities": vulnerabilities,
        "startIndex": start_index,
        "resultsPerPage": RESULTS_PER_PAGE
    }

# --- Test Cases ---

def test_download_cves_for_range_success_single_page(
    mock_httpx_client_instance, mock_overall_progress, mock_overall_task_id,
    mock_fetch_nist_page, mock_json_dump, mock_time_sleep, mock_rich_print
):
    """Test successful download of a single-page chunk."""
    mock_fetch_nist_page.return_value = create_mock_nist_response(10, 10, 0)

    download_cves_for_range(
        mock_httpx_client_instance, TEST_START_DATE, TEST_END_DATE,
        TEST_OUTPUT_FILE, mock_overall_progress, mock_overall_task_id
    )

    mock_rich_print.assert_any_call(f"Downloading CVEs from {TEST_START_DATE} to {TEST_END_DATE}...")
    mock_fetch_nist_page.assert_called_once_with(
        mock_httpx_client_instance,
        {
            "pubStartDate": TEST_START_DATE,
            "pubEndDate": TEST_END_DATE,
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": 0,
        },
    )
    mock_overall_progress.add_task.assert_called_once_with(f"Chunk {TEST_OUTPUT_FILE.name}...", total=None, parent=mock_overall_task_id)
    mock_overall_progress.update.assert_any_call(mock_overall_progress.add_task.return_value, total=10)
    mock_overall_progress.update.assert_any_call(mock_overall_progress.add_task.return_value, advance=10)
    mock_overall_progress.remove_task.assert_called_once_with(mock_overall_progress.add_task.return_value)
    mock_json_dump.assert_called_once()
    saved_data = mock_json_dump.call_args[0][0]
    assert saved_data["totalResults"] == 10
    assert saved_data["download_status"] == "complete"
    assert len(saved_data["vulnerabilities"]) == 10
    mock_rich_print.assert_any_call(f"[green]Data saved to {TEST_OUTPUT_FILE} with status 'complete'.[/green]")
    mock_time_sleep.assert_not_called() # No sleep if only one page

def test_download_cves_for_range_success_multi_page(
    mock_httpx_client_instance, mock_overall_progress, mock_overall_task_id,
    mock_fetch_nist_page, mock_json_dump, mock_time_sleep, mock_rich_print
):
    """Test successful download of a multi-page chunk."""
    # Simulate two pages
    mock_fetch_nist_page.side_effect = [
        create_mock_nist_response(3000, RESULTS_PER_PAGE, 0), # First page
        create_mock_nist_response(3000, 1000, RESULTS_PER_PAGE), # Second page
    ]

    download_cves_for_range(
        mock_httpx_client_instance, TEST_START_DATE, TEST_END_DATE,
        TEST_OUTPUT_FILE, mock_overall_progress, mock_overall_task_id
    )

    mock_rich_print.assert_any_call(f"Downloading CVEs from {TEST_START_DATE} to {TEST_END_DATE}...")
    assert mock_fetch_nist_page.call_count == 2
    mock_overall_progress.update.assert_any_call(mock_overall_progress.add_task.return_value, total=3000)
    mock_overall_progress.update.assert_any_call(mock_overall_progress.add_task.return_value, advance=RESULTS_PER_PAGE)
    mock_overall_progress.update.assert_any_call(mock_overall_progress.add_task.return_value, advance=1000)
    mock_overall_progress.remove_task.assert_called_once_with(mock_overall_progress.add_task.return_value)
    mock_json_dump.assert_called_once()
    saved_data = mock_json_dump.call_args[0][0]
    assert saved_data["totalResults"] == 3000
    assert saved_data["download_status"] == "complete"
    assert len(saved_data["vulnerabilities"]) == 3000
    mock_rich_print.assert_any_call(f"[green]Data saved to {TEST_OUTPUT_FILE} with status 'complete'.[/green]")
    mock_time_sleep.assert_called_once_with(REQUEST_DELAY_SECONDS) # Sleep between pages

def test_download_cves_for_range_no_cves_found(
    mock_httpx_client_instance, mock_overall_progress, mock_overall_task_id,
    mock_fetch_nist_page, mock_json_dump, mock_time_sleep, mock_rich_print
):
    """Test when no CVEs are found for the range."""
    mock_fetch_nist_page.return_value = create_mock_nist_response(0, 0, 0)

    download_cves_for_range(
        mock_httpx_client_instance, TEST_START_DATE, TEST_END_DATE,
        TEST_OUTPUT_FILE, mock_overall_progress, mock_overall_task_id
    )

    mock_rich_print.assert_any_call(f"Downloading CVEs from {TEST_START_DATE} to {TEST_END_DATE}...")
    mock_fetch_nist_page.assert_called_once()
    mock_rich_print.assert_any_call(f"[yellow]No CVEs found for this range ({TEST_START_DATE} to {TEST_END_DATE}).[/yellow]")
    mock_overall_progress.update.assert_any_call(mock_overall_progress.add_task.return_value, total=0)
    mock_overall_progress.remove_task.assert_called_once_with(mock_overall_progress.add_task.return_value)
    mock_json_dump.assert_called_once()
    saved_data = mock_json_dump.call_args[0][0]
    assert saved_data["totalResults"] == 0
    assert saved_data["download_status"] == "complete"
    assert len(saved_data["vulnerabilities"]) == 0
    mock_rich_print.assert_any_call(f"[green]Data saved to {TEST_OUTPUT_FILE} with status 'complete'.[/green]")
    mock_time_sleep.assert_not_called()

def test_download_cves_for_range_fetch_page_none_then_success(
    mocker,
    mock_httpx_client_instance, mock_overall_progress, mock_overall_task_id,
    mock_fetch_nist_page, mock_json_dump, mock_time_sleep, mock_rich_print
):
    """Test retry logic: fetch_nist_page returns None once, then succeeds."""
    # First call to fetch_nist_page returns None, second call succeeds
    mock_fetch_nist_page.side_effect = [
        None, # First attempt for the chunk fails
        create_mock_nist_response(10, 10, 0) # Second attempt for the chunk succeeds
    ]

    download_cves_for_range(
        mock_httpx_client_instance, TEST_START_DATE, TEST_END_DATE,
        TEST_OUTPUT_FILE, mock_overall_progress, mock_overall_task_id
    )

    mock_rich_print.assert_any_call(f"Downloading CVEs from {TEST_START_DATE} to {TEST_END_DATE}...")
    # fetch_nist_page should be called twice (once for initial failure, once for retry)
    assert mock_fetch_nist_page.call_count == 2
    mock_rich_print.assert_any_call(mocker.ANY, "Failed to fetch page, retrying chunk.")
    mock_rich_print.assert_any_call(mocker.ANY, f"Retrying chunk {TEST_OUTPUT_FILE.name} in {API_RETRY_DELAY * (0 + 1)}s... (Attempt 1/{MAX_RETRIES})")
    mock_time_sleep.assert_called_once_with(API_RETRY_DELAY * (1 + 1)) # Sleep for first retry
    mock_json_dump.assert_called_once()
    saved_data = mock_json_dump.call_args[0][0]
    assert saved_data["download_status"] == "complete"
    mock_rich_print.assert_any_call(f"[green]Data saved to {TEST_OUTPUT_FILE} with status 'complete'.[/green]")

def test_download_cves_for_range_fetch_page_none_exhausts_retries(
    mocker,
    mock_httpx_client_instance, mock_overall_progress, mock_overall_task_id,
    mock_fetch_nist_page, mock_json_dump, mock_time_sleep, mock_rich_print
):
    """Test retry logic: fetch_nist_page always returns None, exhausting retries."""
    mock_fetch_nist_page.side_effect = [None] * (MAX_RETRIES + 1) # Fail all attempts

    download_cves_for_range(
        mock_httpx_client_instance, TEST_START_DATE, TEST_END_DATE,
        TEST_OUTPUT_FILE, mock_overall_progress, mock_overall_task_id
    )

    mock_rich_print.assert_any_call(f"Downloading CVEs from {TEST_START_DATE} to {TEST_END_DATE}...")
    assert mock_fetch_nist_page.call_count == MAX_RETRIES # Only MAX_RETRIES attempts for the chunk
    mock_rich_print.assert_any_call(mocker.ANY, "Failed to fetch page, retrying chunk.")
    mock_rich_print.assert_any_call(mocker.ANY, f"Failed to download chunk {TEST_OUTPUT_FILE.name} after {MAX_RETRIES} retries.")
    assert mock_time_sleep.call_count == MAX_RETRIES # Sleep after each failed retry
    mock_json_dump.assert_called_once()
    saved_data = mock_json_dump.call_args[0][0]
    assert saved_data["download_status"] == "failed"
    mock_rich_print.assert_any_call(f"[green]Data saved to {TEST_OUTPUT_FILE} with status 'failed'.[/green]")

def test_download_cves_for_range_fetch_page_raises_http_status_error_exhausts_retries(
    mocker,
    mock_httpx_client_instance, mock_overall_progress, mock_overall_task_id,
    mock_fetch_nist_page, mock_json_dump, mock_time_sleep, mock_rich_print
):
    """Test retry logic: fetch_nist_page raises HTTPStatusError, exhausting retries."""
    mock_response = mocker.MagicMock(spec=httpx.Response)
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_request = mocker.MagicMock(spec=httpx.Request)
    mock_request.url = "http://example.com/api"
    mock_fetch_nist_page.side_effect = [
        httpx.HTTPStatusError("Server error", request=mock_request, response=mock_response)
    ] * (MAX_RETRIES + 1)

    download_cves_for_range(
        mock_httpx_client_instance, TEST_START_DATE, TEST_END_DATE,
        TEST_OUTPUT_FILE, mock_overall_progress, mock_overall_task_id
    )

    mock_rich_print.assert_any_call(f"Downloading CVEs from {TEST_START_DATE} to {TEST_END_DATE}...")
    assert mock_fetch_nist_page.call_count == MAX_RETRIES
    mock_rich_print.assert_any_call(mocker.ANY, "Error downloading chunk test_cve_chunk.json: Server error")
    mock_rich_print.assert_any_call(mocker.ANY, f"Failed to download chunk {TEST_OUTPUT_FILE.name} after {MAX_RETRIES} retries.")
    assert mock_time_sleep.call_count == MAX_RETRIES
    mock_json_dump.assert_called_once()
    saved_data = mock_json_dump.call_args[0][0]
    assert saved_data["download_status"] == "failed"
    mock_rich_print.assert_any_call(f"[green]Data saved to {TEST_OUTPUT_FILE} with status 'failed'.[/green]")

def test_download_cves_for_range_fetch_page_raises_request_error_exhausts_retries(
    mocker,
    mock_httpx_client_instance, mock_overall_progress, mock_overall_task_id,
    mock_fetch_nist_page, mock_json_dump, mock_time_sleep, mock_rich_print
):
    """Test retry logic: fetch_nist_page raises RequestError, exhausting retries."""
    mock_request = mocker.MagicMock(spec=httpx.Request)
    mock_request.url = "http://example.com/api"
    mock_fetch_nist_page.side_effect = [
        httpx.RequestError("Network unreachable", request=mock_request)
    ] * (MAX_RETRIES + 1)

    download_cves_for_range(
        mock_httpx_client_instance, TEST_START_DATE, TEST_END_DATE,
        TEST_OUTPUT_FILE, mock_overall_progress, mock_overall_task_id
    )

    mock_rich_print.assert_any_call(f"Downloading CVEs from {TEST_START_DATE} to {TEST_END_DATE}...")
    assert mock_fetch_nist_page.call_count == MAX_RETRIES
    mock_rich_print.assert_any_call(mocker.ANY, "Error downloading chunk test_cve_chunk.json: Network unreachable")
    mock_rich_print.assert_any_call(mocker.ANY, f"Failed to download chunk {TEST_OUTPUT_FILE.name} after {MAX_RETRIES} retries.")
    assert mock_time_sleep.call_count == MAX_RETRIES
    mock_json_dump.assert_called_once()
    saved_data = mock_json_dump.call_args[0][0]
    assert saved_data["download_status"] == "failed"
    mock_rich_print.assert_any_call(f"[green]Data saved to {TEST_OUTPUT_FILE} with status 'failed'.[/green]")

def test_download_cves_for_range_fetch_page_raises_json_decode_error_exhausts_retries(
    mocker,
    mock_httpx_client_instance, mock_overall_progress, mock_overall_task_id,
    mock_fetch_nist_page, mock_json_dump, mock_time_sleep, mock_rich_print
):
    """Test retry logic: fetch_nist_page raises JSONDecodeError, exhausting retries."""
    mock_fetch_nist_page.side_effect = [
        json.JSONDecodeError("Invalid JSON", doc="{}", pos=0)
    ] * (MAX_RETRIES + 1)

    download_cves_for_range(
        mock_httpx_client_instance, TEST_START_DATE, TEST_END_DATE,
        TEST_OUTPUT_FILE, mock_overall_progress, mock_overall_task_id
    )

    mock_rich_print.assert_any_call(f"Downloading CVEs from {TEST_START_DATE} to {TEST_END_DATE}...")
    assert mock_fetch_nist_page.call_count == MAX_RETRIES
    mock_rich_print.assert_any_call(mocker.ANY, "Error downloading chunk test_cve_chunk.json: Invalid JSON")
    mock_rich_print.assert_any_call(mocker.ANY, f"Failed to download chunk {TEST_OUTPUT_FILE.name} after {MAX_RETRIES} retries.")
    assert mock_time_sleep.call_count == MAX_RETRIES
    mock_json_dump.assert_called_once()
    saved_data = mock_json_dump.call_args[0][0]
    assert saved_data["download_status"] == "failed"
    mock_rich_print.assert_any_call(f"[green]Data saved to {TEST_OUTPUT_FILE} with status 'failed'.[/green]")

def test_download_cves_for_range_io_error_on_save(
    mocker,
    mock_httpx_client_instance, mock_overall_progress, mock_overall_task_id,
    mock_fetch_nist_page, mock_json_dump, mock_time_sleep, mock_rich_print
):
    """Test handling of IOError when saving the file."""
    mock_fetch_nist_page.return_value = create_mock_nist_response(10, 10, 0)
    mock_json_dump.side_effect = IOError("Disk full")

    download_cves_for_range(
        mock_httpx_client_instance, TEST_START_DATE, TEST_END_DATE,
        TEST_OUTPUT_FILE, mock_overall_progress, mock_overall_task_id
    )

    mock_rich_print.assert_any_call(f"Downloading CVEs from {TEST_START_DATE} to {TEST_END_DATE}...")
    mock_json_dump.assert_called_once()
    mock_rich_print.assert_any_call(f"[bold red]File Error:[/bold red] Could not write to {TEST_OUTPUT_FILE}: Disk full[bold red]")
    # The download_status should still be 'complete' in the internal result before the save fails
    # but the file itself won't be written or will be corrupted.
    # The function doesn't re-raise, it just prints the error.
    saved_data = mock_json_dump.call_args[0][0]
    assert saved_data["download_status"] == "complete" # Status before save attempt failed