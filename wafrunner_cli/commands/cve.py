import typer
from rich import print
from typing import Any, Dict, Optional, Union
from pathlib import Path
import json
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeRemainingColumn,
    TaskID,
)
from datetime import datetime, timedelta
import httpx
import time
import glob
import concurrent.futures
from collections import Counter

from wafrunner_cli.core.api_client import ApiClient
from wafrunner_cli.core.exceptions import AuthenticationError
from wafrunner_cli.core.transformers import transform_vulnerability

app = typer.Typer(help="Commands for managing CVE data.")

# NIST API configuration
# NIST API configuration
NIST_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0" # Base URL for NIST NVD API
RESULTS_PER_PAGE = 2000  # Max allowed by NIST API per request
REQUEST_DELAY_SECONDS = 6  # Recommended delay in seconds between requests to NIST API
MAX_RETRIES = 3  # Maximum number of retries for a failed NIST API request
API_RETRY_DELAY = 5 # Initial delay for retries (exponential backoff)
CHUNK_DAYS = 120 # Number of days per chunk for NIST API requests (max allowed by NIST is 120)

# Constants for upload process
UPDATE_DELAY_SECONDS = 0.1



def get_default_cve_path() -> Path:
    """Returns the default path for storing downloaded CVEs."""
    config_dir = Path.home() / ".wafrunner"
    cve_path = config_dir / "data" / "cve-sources"
    return cve_path


def get_uploaded_cves_tracking_path() -> Path:
    """Returns the path for the CVE upload tracking file."""
    config_dir = Path.home() / ".wafrunner"
    tracking_path = config_dir / "data" / "uploaded_cves.json"
    return tracking_path


def load_uploaded_cves_tracking() -> Dict[str, str]:
    """Loads the CVE upload tracking data from the JSON file."""
    tracking_path = get_uploaded_cves_tracking_path()
    if not tracking_path.exists():
        return {}
    try:
        with open(tracking_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"[yellow]Warning: Could not load CVE upload tracking file {tracking_path}: {e}. Starting fresh.[/yellow]")
        return {}


def save_uploaded_cves_tracking(tracking_data: Dict[str, str]):
    """Saves the CVE upload tracking data to the JSON file."""
    tracking_path = get_uploaded_cves_tracking_path()
    tracking_path.parent.mkdir(parents=True, exist_ok=True)
    with open(tracking_path, "w", encoding="utf-8") as f:
        json.dump(tracking_data, f, indent=2)

def isoformat_utc(dt: datetime, start: bool = True) -> str:
    """
    Returns an ISO-8601 formatted string in UTC.
    If start is True, returns time as 00:00:00.000Z,
    otherwise returns 23:59:59.999Z.
    """
    if start:
        return dt.strftime("%Y-%m-%dT00:00:00.000Z")
    else:
        return dt.strftime("%Y-%m-%dT23:59:59.999Z")


def fetch_nist_page(client: httpx.Client, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Fetch a page of CVE data from NIST NVD API.
    Handles retries and specific error logging.
    """
    # Construct the full URL for logging purposes
    # httpx.Client.build_request creates a Request object which has the full URL
    request_obj = client.build_request("GET", "", params=params)
    url_for_logging = str(request_obj.url)

    try:
        response = client.get("", params=params)
        response.raise_for_status()  # Raise for 4xx/5xx errors
        return response.json()
    except httpx.HTTPStatusError as e:
        print(
            f"[bold red]API Error:[/bold red] NIST API returned status {e.response.status_code} for URL: {url_for_logging}. Response: {e.response.text[:200]}"
        )
        if e.response.status_code == 403:
            print("[bold yellow]Hint:[/bold yellow] 403 Forbidden - Check NIST API key usage limits or if key is required/set correctly.")
        elif e.response.status_code == 404:
            print("[bold yellow]Hint:[/bold yellow] 404 Not Found - API endpoint or requested resource might not exist.")
        elif e.response.status_code == 400:
            print(f"[bold yellow]Hint:[/bold yellow] 400 Bad Request - Check parameters: {params}")
    except httpx.RequestError as e:
        print(f"[bold red]Network Error:[/bold red] Failed to connect to NIST API at {url_for_logging!r}: {e}")
    except json.JSONDecodeError:
        print(f"[bold red]Error:[/bold red] Failed to decode JSON response from NIST API for URL: {url_for_logging}.")
    return None


def download_cves_for_range(
    client: httpx.Client,
    start_date_str: str,
    end_date_str: str,
    output_file: Path,
    overall_progress: Progress,
    overall_task_id: TaskID,
):
    """
    Download CVE records for the specified date range and save them to output_file.
    Handles pagination and uses exponential backoff for retries.
    """
    print(f"Downloading CVEs from {start_date_str} to {end_date_str}...")
    vulnerabilities_list = []
    start_index = 0
    total_results = -1  # Use -1 to indicate not yet known
    download_status = "incomplete"

    # Create a sub-task for progress within this range
    range_task = overall_progress.add_task(f"Chunk {output_file.name}...", total=None, parent=overall_task_id)

    retries_for_chunk = 0
    while retries_for_chunk < MAX_RETRIES:
        try:
            while total_results == -1 or start_index < total_results:
                params = {
                    "pubStartDate": start_date_str,
                    "pubEndDate": end_date_str,
                    "resultsPerPage": RESULTS_PER_PAGE,
                    "startIndex": start_index,
                }
                data = fetch_nist_page(client, params)
                if data is None:
                    # If fetch_nist_page returns None, it means all retries for that specific page failed.
                    # We should break from this inner loop and try the whole chunk again (outer loop).
                    raise Exception("Failed to fetch page, retrying chunk.")

                if total_results == -1:
                    total_results = data.get("totalResults", 0)
                    if total_results == 0:
                        print(f"[yellow]No CVEs found for this range ({start_date_str} to {end_date_str}).[/yellow]")
                        overall_progress.update(range_task, total=0)  # Set total to 0 for this task
                        break  # No CVEs, exit inner loop
                    overall_progress.update(range_task, total=total_results)

                batch = data.get("vulnerabilities", [])
                vulnerabilities_list.extend(batch)
                start_index += len(batch)
                overall_progress.update(range_task, advance=len(batch))

                if start_index >= total_results:
                    download_status = "complete"
                    break  # All pages retrieved for this range

                # Respect NIST rate limits between pages within a chunk
                time.sleep(REQUEST_DELAY_SECONDS)

            # If we reached here, the chunk download either completed or found no CVEs
            break  # Exit the outer retry loop for the chunk

        except Exception as e:
            print(f"[bold red]Error downloading chunk {output_file.name}: {e}[/bold red]")
            retries_for_chunk += 1
            if retries_for_chunk < MAX_RETRIES:
                delay = API_RETRY_DELAY * (retries_for_chunk + 1)
                print(f"[yellow]Retrying chunk {output_file.name} in {delay}s... (Attempt {retries_for_chunk}/{MAX_RETRIES})[/yellow]")
                time.sleep(delay)
            else:
                print(f"[bold red]Failed to download chunk {output_file.name} after {MAX_RETRIES} retries.[/bold red]")
                download_status = "failed"  # Mark as failed if all chunk retries exhausted

    overall_progress.remove_task(range_task)  # Remove sub-task after completion/failure

    result = {
        "totalResults": len(vulnerabilities_list),
        "vulnerabilities": vulnerabilities_list,
        "download_status": download_status,
    }
    try:
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[green]Data saved to {output_file} with status '{download_status}'.[/green]")
    except IOError as e:
        print(f"[bold red]File Error:[/bold red] Could not write to {output_file}: {e}[bold red]")


def is_error_file(file_path: Path) -> bool:
    """
    Check if the JSON file at file_path contains an error or empty result,
    or if its download_status is not 'complete'.
    """
    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        # Check for the original error condition (empty result)
        if data.get("totalResults") == 0 and not data.get("vulnerabilities"):
            return True

        # Check for the new download_status indicating issues
        if data.get("download_status") != "complete":
            print(f"[yellow]File {file_path.name} has download status '{data.get('download_status', 'unknown')}'. Flagging for re-download.[/yellow]")
            return True

        # Consider if totalResults doesn't match the actual number of vulnerabilities downloaded
        # This is a strong indicator of an incomplete download
        if data.get("totalResults") is not None and len(data.get("vulnerabilities", [])) != data["totalResults"]:
            print(f"[yellow]File {file_path.name} has totalResults={data['totalResults']} but contains {len(data.get('vulnerabilities', []))} vulnerabilities. Flagging for re-download.[/yellow]")
            return True

        return False  # File appears valid and complete
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[yellow]Error reading or decoding {file_path.name}: {e}. Flagging for re-download.[/yellow]")
        return True  # Treat missing or invalid JSON file as an error file
    except Exception as e:
        print(f"[bold red]Unexpected error checking {file_path.name}: {e}. Flagging for re-download.[/bold red]")
        return True


def generate_date_chunks_for_year(year: int, chunk_days: int = CHUNK_DAYS):
    """
    Generate date chunks for a given year. Each chunk is a tuple:
    (start_date_iso, end_date_iso, part_number)
    """
    chunks = []
    start_dt = datetime(year, 1, 1)
    end_dt = datetime(year, 12, 31)
    part = 1
    current_start = start_dt
    while current_start <= end_dt:
        current_end = current_start + timedelta(days=chunk_days - 1)
        if current_end > end_dt:
            current_end = end_dt
        start_str = isoformat_utc(current_start, start=True)
        end_str = isoformat_utc(current_end, start=False)
        chunks.append((start_str, end_str, part))
        part += 1
        current_start = current_end + timedelta(days=1)  # Start next chunk one day after current_end
    return chunks


def process_record(api_client: ApiClient, vuln_source_data: Dict[str, Any], force_upload: bool, uploaded_cves_tracking: Dict[str, str]) -> str:
    """
    Processes a single CVE record: checks existence, transforms, and uploads/updates.
    Returns a string outcome: 'created', 'updated', 'skipped_*', 'error_*'.
    """
    cve_info = vuln_source_data.get("cve", {})
    cve_id = cve_info.get("id")
    if not cve_id:
        return "skipped_missing_cveid"
    
    nist_last_modified = cve_info.get("lastModified")

    # Check if already uploaded and unmodified, unless --force is used
    if not force_upload and cve_id in uploaded_cves_tracking and uploaded_cves_tracking[cve_id] == nist_last_modified:
        return "skipped_unmodified"

    try:
        # 1. Check if CVE exists in wafrunner
        existing_records = api_client.get(
            "/vulnerability_records", params={"cveID": cve_id}
        )

        existing_vulnID = None
        if existing_records and isinstance(existing_records, list) and len(existing_records) > 0:
            if len(existing_records) > 1:
                print(
                    f"[yellow]Warning: Multiple records found for {cve_id}. Using first one.[/yellow]"
                )
            existing_vulnID = existing_records[0].get("vulnID")

        # 2. Transform data from NIST format to wafrunner format
        payload = transform_vulnerability(vuln_source_data, existing_vulnID)
        if not payload:
            return "error_transform_failed"

        # 3. Create or Update the record in wafrunner
        if existing_vulnID:
            # UPDATE
            response = api_client.put(
                f"/vulnerability_records/{existing_vulnID}", json=payload
            )
            if response.status_code == 200:
                uploaded_cves_tracking[cve_id] = nist_last_modified
                time.sleep(UPDATE_DELAY_SECONDS)  # Delay on successful update
                return "updated"
            else:
                print(
                    # Only print first 100 chars of response text to avoid overly long messages
                    f"[red]Update for {cve_id} ({existing_vulnID}) failed: {response.status_code} {response.text[:100]}[/red]"
                )
                return "error_update_failed"
        else:
            # CREATE
            response = api_client.post("/vulnerability_records", json=payload)
            if response.status_code in [200, 201]:
                uploaded_cves_tracking[cve_id] = nist_last_modified  # Track on successful create
                time.sleep(UPDATE_DELAY_SECONDS)  # Delay on successful create
                return "created"
            elif response.status_code == 409:  # Conflict, already exists
                print(f"[yellow]Warning: Create for CVE {cve_id} failed with 409 Conflict. Record likely created by another process. Treating as success.[/yellow]")
                uploaded_cves_tracking[cve_id] = nist_last_modified # Treat as success, so track it
                return "skipped_conflict"
            else:
                print(
                    # Only print first 100 chars of response text to avoid overly long messages
                    f"[red]Create for {cve_id} failed: {response.status_code} {response.text[:100]}[/red]"
                )
                return "error_create_failed"

    except AuthenticationError as e:
        # This will be caught by the main try/except block in the command
        raise e
    except Exception as e:
        print(f"[bold red]Error processing {cve_id}: {e}[/bold red]")
        return "error_processing_record"


@app.command()
def download(
    year: int = typer.Option(
        ...,  # ... makes this a required option
        "--year",
        "-y",
        help="The year of the CVEs to download from NIST.",
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Directory to save CVE files. Defaults to '~/.wafrunner/data/cve-sources/'.",
        file_okay=False,
        dir_okay=True,
        writable=True,
        resolve_path=True,
    ),
    update: bool = typer.Option(
        False,
        "--update",
        "-u",
        help="Update mode: re-download data even if files already exist and appear valid.",
    ),
):
    """
    Download CVE data for a specific year from the NIST NVD API.
    """
    if output_dir is None:
        output_dir = get_default_cve_path()
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Initializing CVE download for the year [bold cyan]{year}[/bold cyan] from NIST...")
    print(f"Data will be saved to [green]{output_dir}[/green]. Update mode: {update}")

    chunks = generate_date_chunks_for_year(year)
    total_chunks = len(chunks)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed} of {task.total})"),
        TimeRemainingColumn(),
        transient=False, # Keep progress bar visible until finished
    ) as overall_progress:
        overall_task = overall_progress.add_task(f"Processing {total_chunks} date chunks for {year}...", total=total_chunks)

        with httpx.Client(base_url=NIST_API_BASE_URL, timeout=60.0) as client:
            for i, (start_date_str, end_date_str, part_num) in enumerate(chunks):
                file_name = f"nvd-cves-{year}-{part_num}.json"
                output_path = output_dir / file_name

                if output_path.exists() and not update:
                    if not is_error_file(output_path):
                        print(f"[green]File {output_path.name} already exists and appears valid. Skipping.[/green]")
                        overall_progress.update(overall_task, advance=1)
                        continue
                    else:
                        print(f"[yellow]File {output_path.name} exists but is incomplete or has errors. Re-downloading.[/yellow]")

                download_cves_for_range(
                    client, start_date_str, end_date_str, output_path, overall_progress, overall_task
                )

                overall_progress.update(overall_task, advance=1)
                if i < total_chunks - 1:
                    time.sleep(REQUEST_DELAY_SECONDS)  # Delay between chunks

    print("\n[bold green]✔ All CVE data download attempts finished.[/bold green]")


@app.command()
def upload(
    input_dir: Optional[Path] = typer.Option(
        None,
        "--input-dir",
        "-i",
        help="Directory with CVE JSON files. Defaults to '~/.wafrunner/data/cve-sources/'.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
    max_workers: int = typer.Option(
        20, "--max-workers", help="Max number of parallel workers for API calls."
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force upload of all CVEs, even if they appear unmodified.",
    ),
):
    """
    Upload CVEs from local JSON files to the wafrunner system.
    """
    if input_dir is None:
        input_dir = get_default_cve_path()
        if not input_dir.exists():
            print(
                f"[bold red]Error:[/bold red] Default directory {input_dir} does not exist. "
                "Please run 'cve download' first or specify an --input-dir."
            )
            raise typer.Exit(code=1)

    print(f"Starting CVE upload from [green]{input_dir}[/green]...")

    try:
        api_client = ApiClient()  # Check for token early

        json_files = glob.glob(str(input_dir / "*.json"))
        if not json_files:
            print(f"[yellow]No JSON files found in {input_dir}.[/yellow]")
            raise typer.Exit()

        uploaded_cves_tracking = load_uploaded_cves_tracking()
        all_records = []
        print("Reading and parsing JSON files...")
        for file_path in json_files:
            try:
                # Use utf-8 encoding as specified in the reference script
                with open(file_path, "r", encoding='utf-8') as f:
                    data = json.load(f)
                
                vulnerabilities_in_file = []
                if isinstance(data, dict) and 'cve' in data and 'vulnerabilities' not in data:
                    # Single CVE object at root, like {"cve": {...}}
                    vulnerabilities_in_file = [data]
                elif isinstance(data, dict) and 'vulnerabilities' in data:
                    # NVD JSON format: {"vulnerabilities": [...]}
                    vulnerabilities_in_file = data['vulnerabilities']
                elif isinstance(data, list):
                    # Just a list of CVE objects
                    vulnerabilities_in_file = data
                else:
                    print(f"[yellow]Warning: Unrecognized JSON structure in {Path(file_path).name}. Skipping file.[/yellow]")
                    continue # Skip this file if structure is not recognized

                valid_records = [v for v in vulnerabilities_in_file if isinstance(v, dict)]
                num_invalid_records = len(vulnerabilities_in_file) - len(valid_records)
                if num_invalid_records > 0:
                    print(f"[yellow]Warning: Skipped {num_invalid_records} invalid records (not dictionaries) in {Path(file_path).name}.[/yellow]")
                all_records.extend(valid_records)
            except (json.JSONDecodeError, IOError) as e:
                print(f"[yellow]Warning: Could not read or parse {file_path}: {e}[/yellow]")
        total_records = len(all_records)
        print(f"Found {total_records} CVE records to process.")
        outcomes = Counter()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed} of {task.total})"),
            TimeRemainingColumn(),
        ) as progress:
            task = progress.add_task("Uploading CVEs...", total=total_records)

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_cve = {
                    executor.submit(process_record, api_client, record, force, uploaded_cves_tracking): record
                    for record in all_records
                }

                for future in concurrent.futures.as_completed(future_to_cve):
                    result = future.result()
                    outcomes[result] += 1
                    progress.update(task, advance=1)

        # Print summary
        print("\n[bold green]✔ CVE upload process finished.[/bold green]")
        print("--- Summary ---")
        print(f"Successfully Created: [green]{outcomes['created']}[/green]")
        print(f"Successfully Updated: [cyan]{outcomes['updated']}[/cyan]")
        print(f"Skipped (Conflict): [yellow]{outcomes['skipped_conflict']}[/yellow]")
        print(f"Skipped (Unmodified): [yellow]{outcomes['skipped_unmodified']}[/yellow]")
        print(f"Skipped (No CVE ID): [yellow]{outcomes['skipped_missing_cveid']}[/yellow]")
        total_errors = sum(v for k, v in outcomes.items() if k.startswith("error_"))
        print(f"Errors: [bold red]{total_errors}[/bold red]")
        if total_errors > 0:
            print("  - Transform Failed:", outcomes["error_transform_failed"])
            print("  - Create Failed:", outcomes["error_create_failed"])
            print("  - Update Failed:", outcomes["error_update_failed"])
            print("  - Record Processing Error:", outcomes["error_processing_record"])
        
        save_uploaded_cves_tracking(uploaded_cves_tracking)

    except AuthenticationError as e:
        print(f"[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        raise typer.Exit(code=1)


@app.command()
def search(
    keyword: str = typer.Option(..., "--keyword", "-k", help="Keyword to search for."),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output-file",
        "-o",
        help="File to save the search results to.",
        dir_okay=False,
        writable=True,
        resolve_path=True,
    ),
):
    """
    Search for CVEs based on a keyword.
    """
    try:
        api_client = ApiClient()
        print(f"Searching for CVEs with keyword: [bold cyan]{keyword}[/bold cyan]...")

        # Search against the vulnerability records in the wafrunner system
        results = api_client.get("/vulnerability_records/search", params={"keyword": keyword})

        if not results:
            print("[yellow]No results found.[/yellow]")
            raise typer.Exit()

        if output_file:
            try:
                with open(output_file, "w") as f:
                    json.dump(results, f, indent=2)
                print(f"\n[green]✔ Search results saved successfully to {output_file}[/green]")
            except IOError as e:
                print(f"[bold red]File Error:[/bold red] Could not write to file {output_file}. {e}")
                raise typer.Exit(code=1)
        else:
            table = Table(title="CVE Search Results")
            table.add_column("CVE ID", style="cyan", no_wrap=True)
            table.add_column("Summary", style="magenta")
            table.add_column("CVSS Score", justify="right", style="green")

            # Assuming results is a list of dicts
            for item in results:
                score = item.get("score", "N/A")
                table.add_row(
                    item.get("cve_id", "N/A"), item.get("summary", "N/A"), str(score)
                )
            print(table)

    except AuthenticationError as e:
        print(f"[bold red]API Error:[/bold red] {e}")
        if "403" in str(e):
            print(
                "[bold yellow]Hint:[/bold yellow] A '403 Forbidden' error means the server understands your request but refuses to authorize it. "
                "Please check if your API token has the required permissions (scopes) to access this endpoint."
            )
        raise typer.Exit(code=1)
    except httpx.RequestError:
        # ApiClient prints detailed network errors, so we just exit.
        raise typer.Exit(code=1)


@app.command("get-vulnid")
def get_vulnid(
    cve_file: Path = typer.Option(
        ..., "--cve-file", help="Path to the CVE file to look up."
    ),
    output_file: Optional[Path] = typer.Option(
        None, "--output-file", help="File to save the VulnID to."
    ),
):
    """
    Look up the internal vulnerability ID for a given CVE file.
    """
    print(f"Placeholder for 'wafrunner cve get-vulnid' for file: {cve_file}")