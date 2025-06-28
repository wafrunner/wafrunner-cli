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

# Assumes local project structure contains these modules
from wafrunner_cli.core.api_client import ApiClient
from wafrunner_cli.core.exceptions import AuthenticationError

app = typer.Typer(help="Commands for managing CVE data.")

# NIST API configuration
NIST_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
REQUEST_DELAY_SECONDS = 6
MAX_RETRIES = 3
API_RETRY_DELAY = 5
CHUNK_DAYS = 120

# Constants for upload process
UPDATE_DELAY_SECONDS = 0.1 # Delay after a successful create or update

# --- Utility Functions ---

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


def load_uploaded_cves_tracking() -> Dict[str, Dict[str, str]]:
    """
    Loads the CVE upload tracking data from a JSON file.
    The data structure is: {cveID: {"lastModified": "...", "vulnID": "..."}}
    """
    tracking_path = get_uploaded_cves_tracking_path()
    if not tracking_path.exists():
        return {}
    try:
        with open(tracking_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"[yellow]Warning: Could not load CVE upload tracking file {tracking_path}: {e}. Starting fresh.[/yellow]")
        return {}


def save_uploaded_cves_tracking(tracking_data: Dict[str, Dict[str, str]]):
    """Saves the CVE upload tracking data to a JSON file."""
    tracking_path = get_uploaded_cves_tracking_path()
    tracking_path.parent.mkdir(parents=True, exist_ok=True)
    with open(tracking_path, "w", encoding="utf-8") as f:
        json.dump(tracking_data, f, indent=2)

# --- Download Command Helpers ---

def isoformat_utc(dt: datetime, start: bool = True) -> str:
    """Returns an ISO-8601 formatted string in UTC, formatted for NIST API."""
    if start:
        return dt.strftime("%Y-%m-%dT00:00:00.000Z")
    else:
        return dt.strftime("%Y-%m-%dT23:59:59.999Z")


def fetch_nist_page(client: httpx.Client, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Fetches a single page of CVE data from the NIST NVD API."""
    request_obj = client.build_request("GET", "", params=params)
    url_for_logging = str(request_obj.url)
    try:
        response = client.get("", params=params)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as e:
        print(f"[bold red]API Error:[/bold red] NIST API returned status {e.response.status_code} for URL: {url_for_logging}. Response: {e.response.text[:200]}")
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
    """Downloads all CVE records for a specified date range, handling pagination."""
    print(f"Downloading CVEs from {start_date_str} to {end_date_str}...")
    vulnerabilities_list = []
    start_index = 0
    total_results = -1
    download_status = "incomplete"
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
                    raise Exception("Failed to fetch page, retrying chunk.")
                if total_results == -1:
                    total_results = data.get("totalResults", 0)
                    if total_results == 0:
                        print(f"[yellow]No CVEs found for this range ({start_date_str} to {end_date_str}).[/yellow]")
                        overall_progress.update(range_task, total=0)
                        download_status = "complete"
                        break
                    overall_progress.update(range_task, total=total_results)
                batch = data.get("vulnerabilities", [])
                vulnerabilities_list.extend(batch)
                start_index += len(batch)
                overall_progress.update(range_task, advance=len(batch))
                if start_index >= total_results:
                    download_status = "complete"
                    break
                time.sleep(REQUEST_DELAY_SECONDS)
            break
        except Exception as e:
            print(f"[bold red]Error downloading chunk {output_file.name}: {e}[/bold red]")
            retries_for_chunk += 1
            if retries_for_chunk < MAX_RETRIES:
                delay = API_RETRY_DELAY * (retries_for_chunk + 1)
                print(f"[yellow]Retrying chunk {output_file.name} in {delay}s... (Attempt {retries_for_chunk}/{MAX_RETRIES})[/yellow]")
                time.sleep(delay)
            else:
                print(f"[bold red]Failed to download chunk {output_file.name} after {MAX_RETRIES} retries.[/bold red]")
                download_status = "failed"
    overall_progress.remove_task(range_task)
    result = {
        "totalResults": len(vulnerabilities_list),
        "vulnerabilities": vulnerabilities_list,
        "download_status": download_status,
    }
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"[green]Data saved to {output_file} with status '{download_status}'.[/green]")
    except IOError as e:
        print(f"[bold red]File Error:[/bold red] Could not write to {output_file}: {e}")


def is_error_file(file_path: Path) -> bool:
    """Checks if a downloaded JSON file is incomplete or indicates a failure."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("download_status") != "complete":
            print(f"[yellow]File {file_path.name} has download status '{data.get('download_status', 'unknown')}'. Flagging for re-download.[/yellow]")
            return True
        if len(data.get("vulnerabilities", [])) != data.get("totalResults", 0):
            print(f"[yellow]File {file_path.name} has mismatched counts. Flagging for re-download.[/yellow]")
            return True
        return False
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[yellow]Error reading or decoding {file_path.name}: {e}. Flagging for re-download.[/yellow]")
        return True
    except Exception as e:
        print(f"[bold red]Unexpected error checking {file_path.name}: {e}. Flagging for re-download.[/bold red]")
        return True


def generate_date_chunks_for_year(year: int, chunk_days: int = CHUNK_DAYS):
    """Generates date chunks for a given year to use in API requests."""
    chunks = []
    start_dt = datetime(year, 1, 1)
    end_dt = datetime(year, 12, 31)
    part = 1
    current_start = start_dt
    while current_start <= end_dt:
        current_end = min(current_start + timedelta(days=chunk_days - 1), end_dt)
        chunks.append((isoformat_utc(current_start, start=True), isoformat_utc(current_end, start=False), part))
        current_start = current_end + timedelta(days=1)
        part += 1
    return chunks

# --- Upload Command Helpers ---

def api_request_with_retry(api_client, method, url, **kwargs):
    """Makes an API request with retry logic for 5xx errors and network issues."""
    cve_id_for_log = kwargs.get('params', {}).get('cveID', 'N/A')
    for attempt in range(MAX_RETRIES):
        try:
            response = getattr(api_client, method)(url, **kwargs)
            
            if method.upper() == "GET" and response.status_code == 404:
                return response
            if method.upper() == "POST" and response.status_code == 409:
                return response
            if 500 <= response.status_code < 600:
                print(f"[yellow]API {method.upper()} to {url} for CVE {cve_id_for_log} failed with {response.status_code}. Retrying in {API_RETRY_DELAY * (attempt + 1)}s...[/yellow]")
                time.sleep(API_RETRY_DELAY * (attempt + 1))
                if attempt == MAX_RETRIES - 1:
                    response.raise_for_status()
                continue
            response.raise_for_status()
            return response
        except httpx.RequestError as e:
            print(f"[red]Network/Request error on {method.upper()} {url} for CVE {cve_id_for_log}: {e} (Attempt {attempt + 1}/{MAX_RETRIES})[/red]")
            if attempt == MAX_RETRIES - 1:
                raise
            time.sleep(API_RETRY_DELAY * (attempt + 1))
    
    print(f"[red]API {method.upper()} to {url} for CVE {cve_id_for_log} failed after {MAX_RETRIES} retries.[/red]")
    return None

def get_existing_vulnerability(api_client: ApiClient, cve_id: str) -> tuple[Optional[str], str]:
    """
    Checks if a vulnerability exists via the API.
    Returns a tuple of (vuln_id, status) where status is 'found', 'not_found', or 'error'.
    """
    try:
        response = api_request_with_retry(api_client, "get", "/vulnerability_records", params={"cveID": cve_id})
        if response is None:
            return None, 'error'
        if response.status_code == 404:
            return None, 'not_found'
        
        data = response.json()
        
        if isinstance(data, list):
            if not data: return None, 'not_found'
            if len(data) > 1: print(f"[yellow]Warning: Multiple records found for {cve_id}. Using the first one.[/yellow]")
            record = data[0]
        elif isinstance(data, dict):
             record = data
        else:
            print(f"[red]Error: Unexpected response format for {cve_id}. Got {type(data)}[/red]")
            return None, 'error'

        vuln_id = record.get("vulnID")
        return (str(vuln_id), 'found') if vuln_id else (None, 'error')
            
    except (httpx.RequestError, httpx.HTTPStatusError, json.JSONDecodeError) as e:
        print(f"[red]API communication error checking for {cve_id}: {e}[/red]")
        return None, 'error'

def transform_vulnerability(vuln_source_data: Dict[str, Any], existing_vulnID: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Transforms vulnerability data from NIST format to the API payload format."""
    try:
        cve = vuln_source_data.get("cve", {})
        cveID = cve.get("id")
        if not cveID:
            print("[red]Error: Source data is missing 'cve.id'. Cannot transform.[/red]")
            return None

        descriptions = cve.get("descriptions", [])
        description_en = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description provided.")
        published_date = (cve.get("published") or "")[:10]
        last_updated_date = (cve.get("lastModified") or "")[:10]
        cwe_ids = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                    cwe_ids.append(desc["value"])
        cweIDs_payload = sorted(list(set(cwe_ids))) or ["N/A"]
        nist_base_score = 0.0
        metrics = cve.get("metrics", {})
        for metric_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_version, [])
            if metric_list:
                primary_metric = next((m for m in metric_list if m.get("type") == "Primary"), metric_list[0])
                if isinstance(primary_metric.get("cvssData", {}).get("baseScore"), (int, float)):
                    nist_base_score = float(primary_metric["cvssData"]["baseScore"])
                    break
                elif 'baseScore' in primary_metric and isinstance(primary_metric['baseScore'], (int, float)):
                    nist_base_score = float(primary_metric['baseScore'])
                    break
        
        payload = {
            "cveID": cveID,
            "name": f"Vulnerability {cveID}",
            "description": description_en,
            "mitigation": "No mitigation available.",
            "last_updated_date": last_updated_date,
            "published_date": published_date,
            "nist_base_score": nist_base_score,
            "cweIDs": cweIDs_payload,
            "tags": ["Auto-Generated"],
            "affected_systems": ["Unknown"],
            "raw_data": json.loads(json.dumps(vuln_source_data, default=str))
        }
        if existing_vulnID: payload["vulnID"] = existing_vulnID
        return payload
    except Exception as e:
        cve_id_for_log = vuln_source_data.get("cve", {}).get("id", "UNKNOWN")
        print(f"[red]Error during transformation for {cve_id_for_log}: {e}[/red]")
        return None

def process_record(api_client: ApiClient, vuln_source_data: Dict[str, Any], force: bool, update: bool, tracking_info: Optional[Dict[str, str]]) -> tuple:
    """
    Processes a single CVE record, returning an outcome tuple for aggregation.
    Return format: (outcome_str, cve_id, last_modified, vuln_id)
    """
    cve_info = vuln_source_data.get("cve", {})
    cve_id = cve_info.get("id")
    if not cve_id:
        return ("skipped_no_cve_id", None, None, None)
    
    last_modified = cve_info.get("lastModified")
    
    is_tracked = tracking_info and tracking_info.get("vulnID")
    is_modified = not tracking_info or tracking_info.get("lastModified") != last_modified

    # --- UPDATE PATH ---
    # An update can only happen if the --update flag is used.
    if update and (is_tracked or get_existing_vulnerability(api_client, cve_id)[0]):
        # If --force is used, update regardless of modification date.
        # Otherwise, only update if the record has been modified.
        if force or is_modified:
            # Determine the vulnID, from tracking if possible, otherwise from the API.
            vuln_id = (tracking_info.get("vulnID") if is_tracked else get_existing_vulnerability(api_client, cve_id)[0])
            if not vuln_id:
                return ("error_get_failed", cve_id, None, None)
            
            payload = transform_vulnerability(vuln_source_data, vuln_id)
            if not payload: return ("error_transform_failed", cve_id, None, None)
            try:
                api_request_with_retry(api_client, "put", f"/vulnerability_records/{vuln_id}", json=payload)
                time.sleep(UPDATE_DELAY_SECONDS)
                return ("updated", cve_id, last_modified, vuln_id)
            except Exception as e:
                print(f"[bold red]Exception during PUT for {cve_id}: {e}[/bold red]")
                return ("error_update_failed", cve_id, None, None)
        else:
            # --update flag was used, but the record was not modified.
            return ("skipped_unmodified", cve_id, last_modified, tracking_info.get("vulnID"))

    # --- SKIP EXISTING PATH ---
    # If not in update mode, skip any existing record.
    if not update and (is_tracked or get_existing_vulnerability(api_client, cve_id)[0]):
        return ("skipped_existing", cve_id, last_modified, tracking_info.get("vulnID") if is_tracked else get_existing_vulnerability(api_client, cve_id)[0])

    # --- CREATE PATH ---
    # If we reach here, the record is new.
    payload = transform_vulnerability(vuln_source_data, None)
    if not payload: return ("error_transform_failed", cve_id, None, None)
    try:
        response = api_request_with_retry(api_client, "post", "/vulnerability_records", json=payload)
        if response.status_code in [200, 201]:
            new_vuln_id = response.json().get("vulnID")
            time.sleep(UPDATE_DELAY_SECONDS)
            return ("created", cve_id, last_modified, new_vuln_id)
        elif response.status_code == 409:
            print(f"[yellow]Warning: Create for {cve_id} failed with 409 Conflict.[/yellow]")
            return ("skipped_conflict", cve_id, last_modified, None)
        else:
            return ("error_create_failed", cve_id, None, None)
    except Exception as e:
        print(f"[bold red]Exception during POST for {cve_id}: {e}[/bold red]")
        return ("error_create_failed", cve_id, None, None)

# --- Typer Commands ---

@app.command()
def download(
    year: Optional[int] = typer.Option(
        None, "--year", "-y", help="The year of the CVEs to download. Required unless --all-time is used."
    ),
    all_time: bool = typer.Option(
        False, "--all-time", "-a", help="Download CVEs from 1999 to the current year. Cannot be used with --year."
    ),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Directory to save CVE files."),
    update: bool = typer.Option(False, "--update", "-u", help="Re-download data even if files exist."),
):
    """Download CVE data for a specific year from the NIST NVD API."""
    if all_time and year is not None: print("[bold red]Error:[/bold red] Cannot use --all-time with --year. Please choose one."); raise typer.Exit(code=1)
    if not all_time and year is None: print("[bold red]Error:[/bold red] Either --year or --all-time must be provided."); raise typer.Exit(code=1)

    start_year = 1999 if all_time else year
    end_year = datetime.now().year if all_time else year

    if output_dir is None: output_dir = get_default_cve_path()
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Initializing CVE download from [bold cyan]{start_year}[/bold cyan] to [bold cyan]{end_year}[/bold cyan] from NIST...")
    print(f"Data will be saved to [green]{output_dir}[/green]. Update mode: {update}")

    all_chunks_with_years = []
    for current_y in range(start_year, end_year + 1):
        chunks_for_year = generate_date_chunks_for_year(current_y)
        all_chunks_with_years.extend([(s, e, p, current_y) for s, e, p in chunks_for_year])

    total_chunks = len(all_chunks_with_years)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TextColumn("({task.completed} of {task.total})"), TimeRemainingColumn(), transient=False) as progress:
        task = progress.add_task(f"Processing {total_chunks} date chunks...", total=total_chunks)
        with httpx.Client(base_url=NIST_API_BASE_URL, timeout=60.0) as client:
            for i, (start_str, end_str, part, chunk_year) in enumerate(all_chunks_with_years):
                path = output_dir / f"nvd-cves-{chunk_year}-{part}.json"
                if path.exists() and not update and not is_error_file(path):
                    print(f"[green]File {path.name} is valid. Skipping.[/green]")
                    progress.update(task, advance=1)
                    continue
                download_cves_for_range(client, start_str, end_str, path, progress, task)
                progress.update(task, advance=1)
                if i < total_chunks - 1: time.sleep(REQUEST_DELAY_SECONDS)
    print("\n[bold green]✔ Download process finished.[/bold green]")


@app.command()
def upload(
    input_dir: Optional[Path] = typer.Option(None, "--input-dir", "-i", help="Directory containing CVE JSON files."),
    max_workers: int = typer.Option(20, "--max-workers", help="Max number of parallel workers."),
    update: bool = typer.Option(False, "--update", "-u", help="Allow updating of existing CVE records."),
    force: bool = typer.Option(False, "--force", "-f", help="Force update of existing records, regardless of modification date. Requires --update."),
):
    """Upload CVEs from local JSON files to the remote system."""
    if input_dir is None: input_dir = get_default_cve_path()
    if not input_dir.exists():
        print(f"[bold red]Error:[/bold red] Directory {input_dir} does not exist.")
        raise typer.Exit(code=1)
    if force and not update:
        print("[bold red]Error:[/bold red] --force can only be used in combination with --update.")
        raise typer.Exit(code=1)

    print(f"Starting CVE upload from [green]{input_dir}[/green]...")
    try:
        api_client = ApiClient()
        json_files = glob.glob(str(input_dir / "*.json"))
        if not json_files:
            print(f"[yellow]No JSON files found in {input_dir}.[/yellow]")
            raise typer.Exit(code=1)

        uploaded_cves_tracking = load_uploaded_cves_tracking()
        
        unique_cves = {}
        print("Reading, parsing, and de-duplicating JSON files...")
        for file_path in json_files:
            with open(file_path, "r", encoding='utf-8') as f: data = json.load(f)
            for record in data.get('vulnerabilities', []):
                cve_id = record.get("cve", {}).get("id")
                # If there's no CVE ID, we can't de-duplicate, so just add it.
                # We use a unique key to avoid overwriting other records without an ID.
                if not cve_id:
                    unique_cves[f"no-id-{len(unique_cves)}"] = record
                    continue
                last_mod = record.get("cve", {}).get("lastModified")
                if last_mod and (cve_id not in unique_cves or last_mod > unique_cves[cve_id].get("cve",{}).get("lastModified")):
                    unique_cves[cve_id] = record
        
        records_to_process = list(unique_cves.values())
        total_records = len(records_to_process)
        print(f"Found {total_records} unique CVE records to process.")
        if total_records == 0:
            print("[yellow]No valid records found to upload.[/yellow]")
            raise typer.Exit(code=1)

        outcomes = Counter()
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TextColumn("({task.completed} of {task.total})"), TimeRemainingColumn()) as progress:
            task = progress.add_task("Uploading CVEs...", total=total_records)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(process_record, api_client, record, force, update, uploaded_cves_tracking.get(record.get("cve",{}).get("id"))): record
                    for record in records_to_process
                }
                for future in concurrent.futures.as_completed(futures):
                    # Unpack the result tuple from process_record
                    outcome_str, cve_id, last_modified, vuln_id = future.result()
                    outcomes[outcome_str] += 1
                    if cve_id and last_modified:
                        uploaded_cves_tracking[cve_id] = {"lastModified": last_modified, "vulnID": vuln_id}
                    progress.update(task, advance=1)
        
        print("\n[bold green]✔ CVE upload process finished.[/bold green]")
        table = Table(title="Upload Summary")
        table.add_column("Outcome", style="cyan"); table.add_column("Count", style="magenta", justify="right")
        table.add_row("Successfully Created", f"[green]{outcomes['created']}[/green]")
        table.add_row("Successfully Updated", f"[cyan]{outcomes['updated']}[/cyan]")
        table.add_row("Skipped (Existing, No --update)", f"[yellow]{outcomes['skipped_existing']}[/yellow]")
        table.add_row("Skipped (Unmodified)", f"[yellow]{outcomes['skipped_unmodified']}[/yellow]")
        table.add_row("Skipped (Conflict)", f"[yellow]{outcomes['skipped_conflict']}[/yellow]")
        total_errors = sum(v for k, v in outcomes.items() if k.startswith("error_"))
        table.add_row("Total Errors", f"[bold red]{total_errors}[/bold red]")
        if total_errors > 0:
            for key, value in outcomes.items():
                if key.startswith("error_") and value > 0: table.add_row(f"  - {key.replace('_', ' ').title()}", str(value))
        print(table)
        
        save_uploaded_cves_tracking(uploaded_cves_tracking)

    except AuthenticationError as e:
        print(f"[bold red]API Error:[/bold red] {e}"); raise typer.Exit(code=1)
    except Exception as e:
        if not isinstance(e, typer.Exit): print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        raise typer.Exit(code=1)

@app.command()
def search(keyword: str):
    """Search for CVEs (Placeholder)."""
    print(f"Searching for: {keyword}")
