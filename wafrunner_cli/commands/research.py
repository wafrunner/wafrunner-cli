import json
import time
import random
from functools import partial
from pathlib import Path
from typing import List, Optional, Callable, Any
from datetime import datetime, timezone
import concurrent.futures

import typer
import httpx
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeRemainingColumn,
    TaskProgressColumn,
)
from rich.table import Table

from wafrunner_cli.core.api_client import ApiClient
from wafrunner_cli.core.exceptions import AuthenticationError
from wafrunner_cli.core.lookup_service import lookup_ids


# --- Smart Concurrency Utilities ---
def calculate_optimal_workers(collection_size: int, base_workers: int = 4) -> int:
    """
    Calculate optimal worker count based on collection size.

    Args:
        collection_size: Number of items to process
        base_workers: Base number of workers (default: 4)

    Returns:
        Optimal number of workers (2-8 range)
    """
    if collection_size <= 5:
        return 2
    elif collection_size <= 20:
        return 3
    elif collection_size <= 50:
        return base_workers
    elif collection_size <= 100:
        return min(6, base_workers + 2)
    elif collection_size <= 200:
        return min(8, base_workers + 4)
    else:
        return 8  # Cap at 8 for very large collections


def retry_with_backoff(
    func: Callable[[], Any],
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
) -> Any:
    """
    Retry failed requests with exponential backoff and jitter.

    Args:
        func: Function to retry
        max_retries: Maximum number of retry attempts
        base_delay: Base delay in seconds
        max_delay: Maximum delay in seconds

    Returns:
        Result of the function call

    Raises:
        Last exception if all retries fail
    """
    last_exception = None

    for attempt in range(max_retries + 1):
        try:
            return func()
        except httpx.HTTPStatusError as e:
            last_exception = e
            if e.response.status_code == 500 and attempt < max_retries:
                # Calculate delay with exponential backoff and jitter
                delay = min(base_delay * (2**attempt) + random.uniform(0, 1), max_delay)
                time.sleep(delay)
                continue
            # For non-500 errors or final attempt, re-raise immediately
            raise
        except Exception as e:
            last_exception = e
            if attempt < max_retries:
                # For other exceptions, use shorter delay
                delay = min(base_delay * (1.5**attempt), max_delay / 2)
                time.sleep(delay)
                continue
            raise

    # This should never be reached, but just in case
    if last_exception:
        raise last_exception


def create_worker_with_retry(api_client: ApiClient, max_retries: int = 3):
    """
    Create a worker function that includes retry logic for API calls.

    Args:
        api_client: The API client instance
        max_retries: Maximum number of retries for 500 errors

    Returns:
        A function that wraps API calls with retry logic
    """

    def worker_with_retry(operation_func: Callable[[], Any]) -> Any:
        """Execute an operation with retry logic."""
        return retry_with_backoff(operation_func, max_retries)

    return worker_with_retry


# --- Config Manager (for data dir only) ---
class ConfigManager:
    def __init__(self):
        self._data_dir = Path.home() / ".wafrunner" / "data"
        self._data_dir.mkdir(parents=True, exist_ok=True)

    def get_data_dir(self) -> Path:
        return self._data_dir.expanduser()


# --- Helper Function for Collections ---
def get_vuln_identifiers_from_collection(
    collection_name: str, config_manager: ConfigManager
) -> List[dict]:
    """
    Parses a collection file (.json or .txt) and returns a list of vulnerability
    identifiers.
    For JSON, expects a list of objects with 'cve_id' and 'vuln_id'.
    For TXT, assumes each line is a vuln_id or cve_id.
    Returns: A list of dictionaries, e.g.,
    [{'cve_id': 'CVE-xxx', 'vuln_id': 'guid-xxx'}, ...]
    """
    data_dir = config_manager.get_data_dir()
    console = Console()
    txt_path = data_dir / collection_name
    txt_path2 = data_dir / f"{collection_name}.txt"
    json_path = data_dir / "collections" / f"{collection_name}.json"

    identifiers = []

    if json_path.is_file():
        target_path = json_path
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            vulnerabilities = data.get("vulnerabilities", [])
            for v in vulnerabilities:
                if v.get("vuln_id"):
                    identifiers.append(
                        {"cve_id": v.get("cve_id"), "vuln_id": v.get("vuln_id")}
                    )
        except (IOError, json.JSONDecodeError) as e:
            console.print(
                f"[bold red]File Error:[/bold red] Could not read or parse JSON file "
                f"{target_path}: {e}"
            )
            raise typer.Exit(code=1)
    elif txt_path.is_file() or txt_path2.is_file():
        target_path = txt_path if txt_path.is_file() else txt_path2
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                for line in f:
                    identifier = line.strip()
                    if identifier:
                        resolved_ids = lookup_ids(identifier)
                        if resolved_ids:
                            identifiers.append(resolved_ids)
                        else:
                            console.print(
                                f"[bold yellow]Warning:[/bold yellow] Could not "
                                f"resolve identifier: {identifier}"
                            )
        except IOError as e:
            console.print(
                f"[bold red]File Error:[/bold red] Could not read file "
                f"{target_path}: {e}"
            )
            raise typer.Exit(code=1)
    else:
        console.print(
            f"[bold red]Error:[/bold red] Collection "
            f"'[bold yellow]{collection_name}[/bold yellow]' not found."
        )
        raise typer.Exit(code=1)

    if not identifiers:
        console.print(
            f"[bold yellow]Warning:[/bold yellow] The collection "
            f"'{collection_name}' is empty or invalid."
        )
        raise typer.Exit()

    return identifiers


def _resolve_identifier(identifier: str) -> str | None:
    """Resolves a CVE or vulnID to a vulnID."""
    console = Console()
    ids = lookup_ids(identifier)
    if not ids:
        console.print(
            f"[bold red]Error:[/bold red] Could not resolve identifier: {identifier}"
        )
        raise typer.Exit(code=1)
    return ids.get("vuln_id")


app = typer.Typer(
    name="research",
    help="Commands for initiating research and analysis tasks.",
    no_args_is_help=True,
)


@app.command()
def github(
    collection: Optional[str] = typer.Option(
        None,
        "--collection",
        "-c",
        help="Name of the collection file containing vulnerability IDs.",
    ),
    identifier: Optional[str] = typer.Option(
        None, "--id", "-i", help="A single vulnerability ID or CVE ID to process."
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force a new search even if a completed search already exists.",
    ),
    max_workers: int = typer.Option(
        4,
        "--max-workers",
        help="Max number of parallel workers for large collections.",
    ),
):
    """Trigger GitHub searches for vulnerabilities from a collection or a single ID."""
    console = Console()
    if not collection and not identifier:
        console.print(
            "[bold red]Error:[/bold red] Please provide either a --collection or an "
            "--id."
        )
        raise typer.Exit(code=1)
    if collection and identifier:
        console.print(
            "[bold red]Error:[/bold red] Options --collection and --id are mutually "
            "exclusive."
        )
        raise typer.Exit(code=1)

    try:
        config_mgr = ConfigManager()
        api_client = ApiClient()

        if identifier:
            vuln_id = _resolve_identifier(identifier)
            vuln_ids = [vuln_id] if vuln_id else []
        else:
            identifiers = get_vuln_identifiers_from_collection(collection, config_mgr)
            vuln_ids = [item["vuln_id"] for item in identifiers]

        if not vuln_ids:
            console.print(
                "[bold red]Error:[/bold red] No valid vulnerability IDs found to "
                "process."
            )
            raise typer.Exit(code=1)

        # Calculate optimal worker count based on collection size
        optimal_workers = calculate_optimal_workers(len(vuln_ids), max_workers)
        if optimal_workers != max_workers:
            console.print(
                f"[*] Adjusted worker count from {max_workers} to {optimal_workers} "
                f"based on collection size ({len(vuln_ids)} items)"
            )
            max_workers = optimal_workers

        console.print(f"Found {len(vuln_ids)} vulnerability ID(s) to process.")
        if force:
            console.print(
                "[bold yellow]Running in force mode: all vulnerabilities will be "
                "searched.[/bold yellow]"
            )

        skipped = 0
        failed = 0
        triggered = 0

        def process_vuln(current_vuln_id):
            nonlocal skipped, failed, triggered
            try:
                # Use retry logic for the GET request
                response = retry_with_backoff(
                    lambda: api_client.get(f"/vulnerability_records/{current_vuln_id}")
                )
            except AuthenticationError as e:
                raise e  # Re-raise to be caught by the main handler
            except Exception as e:
                console.print(f"[red]API error for {current_vuln_id}: {e}[/red]")
                failed += 1
                return

            if response.status_code == 404:
                console.print(
                    f"Info: Record not found for {current_vuln_id}. Skipping."
                )
                failed += 1
                return

            try:
                record = response.json()
            except Exception as e:
                console.print(
                    f"[red]Failed to parse record for {current_vuln_id}: {e}[/red]"
                )
                failed += 1
                return

            if not force:
                github_searches = record.get("github_searches", [])
                skip_search = False
                if isinstance(github_searches, list):
                    for entry in github_searches:
                        if (
                            isinstance(entry, dict)
                            and entry.get("status", "").lower() == "complete"
                        ):
                            skip_search = True
                            break
                if skip_search:
                    skipped += 1
                    return

            try:
                # Use retry logic for the POST request
                post_response = retry_with_backoff(
                    lambda: api_client.post(
                        f"/vulnerability_records/{current_vuln_id}/actions/search",
                        json={"searchType": "github"},
                    )
                )
            except Exception as e:
                console.print(
                    f"[bold red]Failed to trigger search for {current_vuln_id}: "
                    f"{e}[/bold red]"
                )
                failed += 1
                return

            if post_response.status_code not in (200, 201, 204, 409):
                console.print(
                    f"[bold red]Failed to trigger search for {current_vuln_id}. "
                    f"Status: {post_response.status_code}[/bold red]"
                )
                failed += 1
            else:
                triggered += 1

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task(
                "[green]Processing VulnIDs...", total=len(vuln_ids)
            )

            if len(vuln_ids) <= 5:
                for idx, current_vuln_id in enumerate(vuln_ids, 1):
                    process_vuln(current_vuln_id)
                    if idx % 50 == 0 or len(vuln_ids) < 50:
                        console.print(
                            f"Triggered GitHub search for {current_vuln_id}... "
                            f"({idx}/{len(vuln_ids)})"
                        )
                    progress.advance(task)
            else:
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=max_workers
                ) as executor:
                    futures = {
                        executor.submit(process_vuln, vid): vid for vid in vuln_ids
                    }
                    for idx, future in enumerate(
                        concurrent.futures.as_completed(futures), 1
                    ):
                        # Optionally, print progress every 50
                        if idx % 50 == 0 or len(vuln_ids) < 50:
                            console.print(
                                f"Processed {idx} of {len(vuln_ids)} vulnerability "
                                f"IDs..."
                            )
                        progress.advance(task)

        console.print(
            "\n[bold green]✔ Finished processing all vulnerability IDs.[/bold green]"
        )
        console.print(
            f"Triggered: [green]{triggered}[/green], "
            f"Skipped: [yellow]{skipped}[/yellow], "
            f"Failed: [red]{failed}[/red]"
        )

    except AuthenticationError as e:
        console.print(f"\n[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except httpx.RequestError:
        console.print(
            "\n[bold red]Network Error:[/bold red] A network error occurred while "
            "communicating with the API."
        )
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command()
def scrape(
    collection: Optional[str] = typer.Option(
        None,
        "--collection",
        "-c",
        help="Name of the collection file containing vulnerability IDs.",
    ),
    identifier: Optional[str] = typer.Option(
        None, "--id", "-i", help="A single vulnerability ID or CVE ID to process."
    ),
    max_workers: int = typer.Option(
        4, "--max-workers", "-t", help="Number of worker threads."
    ),
):
    """Trigger scrapes for data sources associated with vulnerabilities."""
    console = Console()
    if not collection and not identifier:
        console.print(
            "[bold red]Error:[/bold red] Please provide either a --collection or an "
            "--id."
        )
        raise typer.Exit(code=1)
    if collection and identifier:
        console.print(
            "[bold red]Error:[/bold red] Options --collection and --id are mutually "
            "exclusive."
        )
        raise typer.Exit(code=1)

    try:
        config_mgr = ConfigManager()
        api_client = ApiClient()

        if identifier:
            vuln_id = _resolve_identifier(identifier)
            vuln_ids = [vuln_id] if vuln_id else []
        else:
            identifiers = get_vuln_identifiers_from_collection(collection, config_mgr)
            vuln_ids = [item["vuln_id"] for item in identifiers]

        if not vuln_ids:
            console.print(
                "[bold red]Error:[/bold red] No valid vulnerability IDs found to "
                "process."
            )
            raise typer.Exit(code=1)

        total_vulns = len(vuln_ids)
        # Calculate optimal worker count based on collection size
        optimal_workers = calculate_optimal_workers(total_vulns, max_workers)
        if optimal_workers != max_workers:
            console.print(
                f"[*] Adjusted worker count from {max_workers} to {optimal_workers} "
                f"based on collection size ({total_vulns} items)"
            )
            max_workers = optimal_workers

        console.print(
            f"[*] Found {total_vulns} vulnerability ID(s) to process for scraping."
        )
        console.print(f"[*] Using {max_workers} worker threads.")

        def process_vuln_for_scrape(current_vuln_id):
            result = {
                "vulnID": current_vuln_id,
                "triggered": 0,
                "skipped": 0,
                "error": None,
            }
            try:
                # --- Real API call to get data sources ---
                response = api_client.get(
                    f"/vulnerability_records/{current_vuln_id}/data_sources"
                )
                if response.status_code == 404:
                    result["error"] = "No data sources found"
                    return result

                try:
                    data_sources = response.json()
                except Exception as e:
                    result["error"] = f"Failed to parse data sources: {e}"
                    return result

                for record in data_sources:
                    if not isinstance(record, dict):
                        continue

                    link_id = record.get("linkID")
                    scraped_status = str(record.get("scrapedStatus", "")).lower()

                    if not link_id:
                        result["skipped"] += 1
                        continue

                    if scraped_status in ("complete", "error"):
                        result["skipped"] += 1
                        continue

                    # --- Real API call to trigger scrape ---
                    try:
                        post_response = api_client.post(
                            (
                                f"/vulnerability_records/{current_vuln_id}/"
                                f"data_sources/{link_id}/actions/scrape"
                            ),
                            json={},
                        )
                        if post_response.status_code in (200, 201, 409):
                            result["triggered"] += 1
                    except Exception:
                        # Silently continue - individual scrape failures
                        # don't fail the whole operation
                        pass

            except AuthenticationError:
                raise
            except Exception as e:
                result["error"] = str(e)

            return result

        total_triggered = 0
        total_skipped = 0
        processed_count = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("•"),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                f"[green]Processing {total_vulns} VulnIDs...", total=total_vulns
            )
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers
            ) as executor:
                future_to_vulnid = {
                    executor.submit(process_vuln_for_scrape, vuln_id): vuln_id
                    for vuln_id in vuln_ids
                }
                for future in concurrent.futures.as_completed(future_to_vulnid):
                    vuln_id = future_to_vulnid[future]
                    try:
                        result = future.result()
                        processed_count += 1
                        total_triggered += result.get("triggered", 0)
                        total_skipped += result.get("skipped", 0)
                        if result.get("error"):
                            console.print(
                                f"[yellow]Warning for {vuln_id}: {result['error']}[/yellow]"
                            )
                        elif (
                            result.get("triggered", 0) > 0
                            or result.get("skipped", 0) > 0
                        ):
                            console.print(
                                f"Summary for {vuln_id}: Triggered [bold "
                                f"green]{result['triggered']}[/bold green] scrapes, "
                                f"skipped [bold yellow]{result['skipped']}[/bold yellow] "
                                "data sources."
                            )
                    except Exception as exc:
                        if isinstance(exc, AuthenticationError):
                            raise
                        console.print(f"[red]Error processing {vuln_id}: {exc}[/red]")
                    progress.advance(task)

        console.print(
            "\n[bold green]✔ Finished processing all vulnerability IDs for "
            "scraping.[/bold green]"
        )
        console.print(
            f"Total triggered: [green]{total_triggered}[/green], "
            f"Total skipped: [yellow]{total_skipped}[/yellow]"
        )

    except AuthenticationError as e:
        console.print(f"\n[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except httpx.RequestError:
        console.print(
            "\n[bold red]Network Error:[/bold red] A network error occurred while "
            "communicating with the API."
        )
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command()
def classify(
    collection: Optional[str] = typer.Option(
        None,
        "--collection",
        "-c",
        help="Name of the collection file containing vulnerability IDs.",
    ),
    identifier: Optional[str] = typer.Option(
        None, "--id", "-i", help="A single vulnerability ID or CVE ID to process."
    ),
    update: bool = typer.Option(
        False,
        "--update",
        "-u",
        help="Trigger classifier even if status is 'complete' or 'error'.",
    ),
    retry: bool = typer.Option(
        False, "--retry", "-r", help="Trigger classifier ONLY if status is 'error'."
    ),
    max_workers: int = typer.Option(
        4, "--max-workers", "-t", help="Number of worker threads."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-V", help="Show progress bar and verbose logs."
    ),
    log_dir: Optional[Path] = typer.Option(
        None,
        "--log-dir",
        help="Directory to save the detailed JSON log file (default: ./run_logs)",
    ),
):
    """
    Trigger classifier for vulnerabilities from a collection or a single ID.

    You must provide either --collection/-c or --id/-i.
    """
    console = Console()
    if not collection and not identifier:
        console.print(
            "[bold red]Error:[/bold red] Please provide either a --collection or an "
            "--id."
        )
        raise typer.Exit(code=1)
    if collection and identifier:
        console.print(
            "[bold red]Error:[/bold red] Options --collection and --id are mutually "
            "exclusive."
        )
        raise typer.Exit(code=1)
    if update and retry:
        console.print(
            "[bold red]Error:[/bold red] --update and --retry are mutually exclusive."
        )
        raise typer.Exit(code=1)

    try:
        config_mgr = ConfigManager()
        api_client = ApiClient()

        if identifier:
            vuln_id = _resolve_identifier(identifier)
            vuln_ids = [vuln_id] if vuln_id else []
        else:
            identifiers = get_vuln_identifiers_from_collection(collection, config_mgr)
            vuln_ids = [item["vuln_id"] for item in identifiers]

        if not vuln_ids:
            console.print(
                "[bold red]Error:[/bold red] No valid vulnerability IDs found to "
                "process."
            )
            raise typer.Exit(code=1)

        total_vulns = len(vuln_ids)
        mode_str = "Update" if update else "Retry" if retry else "Standard"
        if not log_dir:
            log_dir = Path("./run_logs")
        log_dir.mkdir(parents=True, exist_ok=True)

        # Calculate optimal worker count based on collection size
        optimal_workers = calculate_optimal_workers(total_vulns, max_workers)
        if optimal_workers != max_workers:
            console.print(
                f"[*] Adjusted worker count from {max_workers} to {optimal_workers} "
                f"based on collection size ({total_vulns} items)"
            )
            max_workers = optimal_workers

        console.print(f"[*] Found {total_vulns} vulnerability IDs to process.")
        console.print(f"[*] Mode: {mode_str}")
        console.print(f"[*] Using {max_workers} worker threads.")
        console.print(f"[*] Detailed log file will be saved in: {log_dir}")

        # --- Worker function ---
        def process_vulnerability(vulnID):
            results = {
                "vulnID": vulnID,
                "status": "processed",
                "sources_found": 0,
                "triggered_ok": [],
                "trigger_failed": [],
                "skipped_scrape": [],
                "skipped_classify": [],
                "skipped_linkid": 0,
                "error_fetching_sources": False,
            }

            # --- API GET data sources ---
            try:
                # Use the same headers as the example script (handled by ApiClient)
                response = retry_with_backoff(
                    lambda: api_client.get(
                        f"/vulnerability_records/{vulnID}/data_sources"
                    )
                )
                if (
                    response.status_code == 204
                    or response.status_code == 404
                    or not response.content
                ):
                    results["status"] = "no_sources_found"
                    return results
                data_sources = response.json()
            except AuthenticationError as e:
                raise e  # Re-raise to be caught by the main handler
            except Exception as e:
                results["status"] = "error_fetching_sources"
                results["error_fetching_sources"] = True
                results["error_message"] = str(e)
                return results

            if not data_sources:
                results["status"] = "no_sources_found"
                return results

            results["sources_found"] = len(data_sources)

            for record in data_sources:
                linkID_value = record.get("linkID")
                if not linkID_value:
                    results["skipped_linkid"] += 1
                    continue

                scraped_status = str(record.get("scrapedStatus", "")).lower()
                if scraped_status != "complete":
                    results["skipped_scrape"].append(linkID_value)
                    continue

                classifier_status = str(record.get("classifierStatus", "")).lower()
                should_skip = False
                if retry:
                    if classifier_status != "error":
                        should_skip = True
                elif not update:
                    if classifier_status in ["complete", "error"]:
                        should_skip = True

                if should_skip:
                    results["skipped_classify"].append(linkID_value)
                    continue

                # --- API POST trigger classify ---
                try:
                    post_response = retry_with_backoff(
                        partial(
                            api_client.post,
                            f"/vulnerability_records/{vulnID}/data_sources/"
                            f"{linkID_value}/actions/classify",
                            json={},
                        )
                    )
                    if 200 <= post_response.status_code < 300:
                        results["triggered_ok"].append(linkID_value)
                    else:
                        results["trigger_failed"].append(linkID_value)
                        if verbose:
                            console.print(
                                f"[red]Failed to trigger classify for "
                                f"{vulnID}/{linkID_value}: Status "
                                f"{post_response.status_code} - "
                                f"{post_response.text}[/red]"
                            )
                except Exception as e:
                    results["trigger_failed"].append(linkID_value)
                    if verbose:
                        console.print(
                            f"[red]Failed to trigger classify for "
                            f"{vulnID}/{linkID_value}: {e}[/red]"
                        )
            return results

        # --- Multithreaded execution ---
        all_results = []
        total_triggered_ok = 0
        total_trigger_failed = 0
        total_skipped_scrape = 0
        total_skipped_classify = 0
        total_skipped_linkid = 0
        total_error_fetching = 0
        processed_vuln_count = 0

        start_time = time.time()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("•"),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                f"[green]Processing {total_vulns} VulnIDs...", total=total_vulns
            )
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers
            ) as executor:
                future_to_vulnid = {
                    executor.submit(process_vulnerability, vuln_id): vuln_id
                    for vuln_id in vuln_ids
                }
                for future in concurrent.futures.as_completed(future_to_vulnid):
                    vuln_id = future_to_vulnid[future]
                    try:
                        result = future.result()
                        all_results.append(result)
                        processed_vuln_count += 1
                        total_triggered_ok += len(result.get("triggered_ok", []))
                        total_trigger_failed += len(result.get("trigger_failed", []))
                        total_skipped_scrape += len(result.get("skipped_scrape", []))
                        total_skipped_classify += len(
                            result.get("skipped_classify", [])
                        )
                        total_skipped_linkid += result.get("skipped_linkid", 0)
                        total_error_fetching += (
                            1 if result.get("error_fetching_sources") else 0
                        )
                    except Exception as exc:
                        if isinstance(exc, AuthenticationError):
                            raise
                        all_results.append(
                            {
                                "vulnID": vuln_id,
                                "status": "thread_exception",
                                "error": str(exc),
                            }
                        )
                        total_error_fetching += 1
                    progress.advance(task)

        end_time = time.time()
        console.print("\n--- Processing Summary ---")
        console.print(f"Mode: {mode_str}")
        console.print(f"Processed {processed_vuln_count}/{total_vulns} vulnIDs.")
        console.print(f"Classifier Triggers OK:      {total_triggered_ok}")
        console.print(f"Classifier Triggers Failed:  {total_trigger_failed}")
        console.print(f"Skipped (scrape incomplete): {total_skipped_scrape}")
        console.print(f"Skipped (classifier status): {total_skipped_classify}")
        console.print(f"Skipped (missing linkID):    {total_skipped_linkid}")
        console.print(f"Errors Fetching Sources:     {total_error_fetching}")
        console.print(f"Total processing time: {end_time - start_time:.2f} seconds")

        # --- Write Detailed Log File ---
        log_filename = (
            f"classifier_trigger_log_{mode_str}_{time.strftime('%Y%m%d-%H%M%S')}.json"
        )
        log_filepath = log_dir / log_filename
        log_data = {
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": mode_str,
            "threads": max_workers,
            "input_collection": collection,
            "input_vulnid": identifier,
            "summary": {
                "processed_vulnIDs": processed_vuln_count,
                "total_vulnIDs_in_collection": total_vulns,
                "total_triggered_ok": total_triggered_ok,
                "total_trigger_failed": total_trigger_failed,
                "total_skipped_scrape": total_skipped_scrape,
                "total_skipped_classify": total_skipped_classify,
                "total_skipped_linkid": total_skipped_linkid,
                "total_error_fetching_sources": total_error_fetching,
                "processing_time_seconds": round(end_time - start_time, 2),
            },
            "details_per_vulnID": all_results,
        }
        try:
            with log_filepath.open("w", encoding="utf-8") as f_log:
                json.dump(log_data, f_log, indent=4)
            console.print(f"[*] Detailed results saved to: {log_filepath}")
        except Exception as e:
            console.print(
                f"\n[red]Error writing detailed log file to {log_dir}: {e}[/red]"
            )

        if total_trigger_failed > 0 or total_error_fetching > 0:
            console.print(
                "\n[bold yellow]Completed with errors. Check logs above and the "
                "detailed log file.[/bold yellow]"
            )

    except AuthenticationError as e:
        console.print(f"\n[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("init-graph")
def init_graph(
    collection: Optional[str] = typer.Option(
        None,
        "--collection",
        "-c",
        help="Name of the collection file containing vulnerability IDs.",
    ),
    identifier: Optional[str] = typer.Option(
        None, "--id", "-i", help="A single vulnerability ID or CVE ID to process."
    ),
    max_workers: int = typer.Option(
        4, "--max-workers", "-t", help="Number of worker threads."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-V", help="Show progress bar and verbose logs."
    ),
    log_dir: Optional[Path] = typer.Option(
        None,
        "--log-dir",
        help="Directory to save the detailed JSON log file (default: ./run_logs)",
    ),
):
    """
    Trigger exploit graph initialization for vulnerabilities.

    You must provide either --collection/-c or --id/-i.
    """
    console = Console()
    if not collection and not identifier:
        console.print(
            "[bold red]Error:[/bold red] Please provide either a --collection or an "
            "--id."
        )
        raise typer.Exit(code=1)
    if collection and identifier:
        console.print(
            "[bold red]Error:[/bold red] Options --collection and --id are mutually "
            "exclusive."
        )
        raise typer.Exit(code=1)

    try:
        config_mgr = ConfigManager()
        api_client = ApiClient()
        if identifier:
            vuln_id = _resolve_identifier(identifier)
            vuln_ids = [vuln_id] if vuln_id else []
        else:
            identifiers = get_vuln_identifiers_from_collection(collection, config_mgr)
            vuln_ids = [item["vuln_id"] for item in identifiers]

        if not vuln_ids:
            console.print(
                "[bold red]Error:[/bold red] No valid vulnerability IDs found to "
                "process."
            )
            raise typer.Exit(code=1)

        total_vulns = len(vuln_ids)
        if not log_dir:
            log_dir = Path("./run_logs")
        log_dir.mkdir(parents=True, exist_ok=True)

        # Calculate optimal worker count based on collection size
        optimal_workers = calculate_optimal_workers(total_vulns, max_workers)
        if optimal_workers != max_workers:
            console.print(
                f"[*] Adjusted worker count from {max_workers} to {optimal_workers} "
                f"based on collection size ({total_vulns} items)"
            )
            max_workers = optimal_workers

        console.print(f"[*] Found {total_vulns} vulnerability IDs to process.")
        console.print(f"[*] Using {max_workers} worker threads.")
        console.print(f"[*] Detailed log file will be saved in: {log_dir}")

        def process_vuln_for_graph(vulnID):
            result = {
                "vulnID": vulnID,
                "status": "processed",
                "error": None,
                "status_code": None,
            }
            try:
                # First check if a graph already exists
                try:
                    graph_check_response = retry_with_backoff(
                        lambda: api_client.get(
                            f"/vulnerability_records/{vulnID}/exploit-graph"
                        )
                    )
                    # If the graph endpoint returns 200, a graph already exists
                    if graph_check_response.status_code == 200:
                        result["status"] = "skipped"
                        result["error"] = "Graph already exists"
                        return result
                    # If 404, no graph exists - proceed with initialization
                    # Other status codes are treated as errors, but we'll still try to initialize
                except Exception as e:
                    # If we can't check (network error, etc.), proceed with initialization attempt
                    # (might be a network issue, but we'll try anyway)
                    if verbose:
                        console.print(
                            f"[yellow]Warning: Could not check for existing graph for {vulnID}: {e}[/yellow]"
                        )

                # POST to /vulnerability.../initialise-exploit-graph
                response = retry_with_backoff(
                    lambda: api_client.post(
                        f"/vulnerability_records/{vulnID}/actions/"
                        "initialise-exploit-graph",
                        json={},
                    )
                )
                result["status_code"] = response.status_code
                if 200 <= response.status_code < 300:
                    result["status"] = "success"
                else:
                    result["status"] = "failed"
                    result["error"] = f"HTTP {response.status_code}: {response.text}"
                    if verbose:
                        console.print(
                            f"[red]Failed to trigger exploit graph for {vulnID}: "
                            f"{result['error']}[/red]"
                        )
            except Exception as e:
                if isinstance(e, AuthenticationError):
                    raise
                result["status"] = "failed"
                result["error"] = str(e)
                if verbose:
                    console.print(f"[red]Exception for {vulnID}: {e}[/red]")
            return result

        all_results = []
        total_success = 0
        total_failed = 0
        total_skipped = 0
        processed_vuln_count = 0

        start_time = time.time()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("•"),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                f"[green]Processing {total_vulns} VulnIDs...", total=total_vulns
            )
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers
            ) as executor:
                future_to_vulnid = {
                    executor.submit(process_vuln_for_graph, vuln_id): vuln_id
                    for vuln_id in vuln_ids
                }
                for future in concurrent.futures.as_completed(future_to_vulnid):
                    vuln_id = future_to_vulnid[future]
                    try:
                        result = future.result()
                        all_results.append(result)
                        processed_vuln_count += 1
                        if result.get("status") == "success":
                            total_success += 1
                        elif result.get("status") == "skipped":
                            total_skipped += 1
                        else:
                            total_failed += 1
                    except Exception as exc:
                        if isinstance(exc, AuthenticationError):
                            raise
                        all_results.append(
                            {
                                "vulnID": vuln_id,
                                "status": "thread_exception",
                                "error": str(exc),
                            }
                        )
                        total_failed += 1
                    progress.advance(task)

        end_time = time.time()
        duration = end_time - start_time
        rate = processed_vuln_count / duration if duration > 0 else 0

        console.print("\n--- Processing Summary ---")
        console.print(f"Processed {processed_vuln_count}/{total_vulns} vulnIDs.")
        console.print(f"Successful Triggers: {total_success}")
        console.print(f"Skipped (graph exists): {total_skipped}")
        console.print(f"Failed Triggers:     {total_failed}")
        console.print(
            f"Total processing time: {duration:.2f} seconds ({rate:.2f} vulnIDs/sec)"
        )

        # --- Write Detailed Log File ---
        log_filename = (
            f"exploit_graph_trigger_log_{time.strftime('%Y%m%d-%H%M%S')}.json"
        )
        log_filepath = log_dir / log_filename
        log_data = {
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
            "threads": max_workers,
            "input_collection": collection,
            "input_vulnid": identifier,
            "summary": {
                "processed_vulnIDs": processed_vuln_count,
                "total_vulnIDs_in_collection": total_vulns,
                "total_success": total_success,
                "total_skipped": total_skipped,
                "total_failed": total_failed,
                "processing_time_seconds": round(duration, 2),
                "processing_rate_vulnIDs_per_sec": round(rate, 2),
            },
            "details_per_vulnID": all_results,
        }
        try:
            with log_filepath.open("w", encoding="utf-8") as f_log:
                json.dump(log_data, f_log, indent=4)
            console.print(f"[*] Detailed results saved to: {log_filepath}")
        except Exception as e:
            console.print(
                f"\n[red]Error writing detailed log file to {log_dir}: {e}[/red]"
            )

        if total_failed > 0:
            console.print(
                "\n[bold yellow]Completed with errors. Check logs above and the "
                "detailed log file.[/bold yellow]"
            )

    except AuthenticationError as e:
        console.print(f"\n[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("init-scdef")
def init_scdef(
    collection: Optional[str] = typer.Option(
        None,
        "--collection",
        "-c",
        help="Name of the collection file containing vulnerability IDs.",
    ),
    identifier: Optional[str] = typer.Option(
        None, "--id", "-i", help="A single vulnerability ID or CVE ID to process."
    ),
    graph: Optional[str] = typer.Option(
        None, "--graph", "-g", help="Graph ID to use for SCDEF initialization."
    ),
    max_workers: int = typer.Option(
        4, "--max-workers", "-t", help="Number of worker threads."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-V", help="Show progress bar and verbose logs."
    ),
    log_dir: Optional[Path] = typer.Option(
        None,
        "--log-dir",
        help="Directory to save the detailed JSON log file (default: ./run_logs)",
    ),
):
    """
    Trigger SCDEF initialization for vulnerabilities.

    You must provide either --collection/-c or --id/-i.
    """
    console = Console()
    if not collection and not identifier:
        console.print(
            "[bold red]Error:[/bold red] Please provide either a --collection or an "
            "--id."
        )
        raise typer.Exit(code=1)
    if collection and identifier:
        console.print(
            "[bold red]Error:[/bold red] Options --collection and --id are mutually "
            "exclusive."
        )
        raise typer.Exit(code=1)

    try:
        config_mgr = ConfigManager()
        api_client = ApiClient()
        if identifier:
            vuln_id = _resolve_identifier(identifier)
            vuln_ids = [vuln_id] if vuln_id else []
        else:
            identifiers = get_vuln_identifiers_from_collection(collection, config_mgr)
            vuln_ids = [item["vuln_id"] for item in identifiers]

        if not vuln_ids:
            console.print(
                "[bold red]Error:[/bold red] No valid vulnerability IDs found to "
                "process."
            )
            raise typer.Exit(code=1)

        total_vulns = len(vuln_ids)
        if not log_dir:
            log_dir = Path("./run_logs")
        log_dir.mkdir(parents=True, exist_ok=True)

        # Calculate optimal worker count based on collection size
        optimal_workers = calculate_optimal_workers(total_vulns, max_workers)
        if optimal_workers != max_workers:
            console.print(
                f"[*] Adjusted worker count from {max_workers} to {optimal_workers} "
                f"based on collection size ({total_vulns} items)"
            )
            max_workers = optimal_workers

        console.print(f"[*] Found {total_vulns} vulnerability IDs to process.")
        console.print(f"[*] Using {max_workers} worker threads.")
        console.print(f"[*] Detailed log file will be saved in: {log_dir}")

        def process_vuln_for_scdef(vulnID):
            result = {
                "vulnID": vulnID,
                "status": "processed",
                "error": None,
                "status_code": None,
            }
            try:
                # Prepare request body
                request_body = {}
                if graph:
                    request_body["graphID"] = graph

                # POST to /vulnerability.../initialise-scdef
                response = api_client.post(
                    f"/vulnerability_records/{vulnID}/actions/initialise-scdef",
                    json=request_body,
                )
                result["status_code"] = response.status_code
                if 200 <= response.status_code < 300:
                    result["status"] = "success"
                else:
                    result["status"] = "failed"
                    result["error"] = f"HTTP {response.status_code}: {response.text}"
                    if verbose:
                        console.print(
                            f"[red]Failed to trigger SCDEF initialization for {vulnID}: "
                            f"{result['error']}[/red]"
                        )
            except Exception as e:
                if isinstance(e, AuthenticationError):
                    raise
                result["status"] = "failed"
                result["error"] = str(e)
                if verbose:
                    console.print(f"[red]Exception for {vulnID}: {e}[/red]")
            return result

        all_results = []
        total_success = 0
        total_failed = 0
        processed_vuln_count = 0

        start_time = time.time()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("•"),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                f"[green]Processing {total_vulns} VulnIDs...", total=total_vulns
            )
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers
            ) as executor:
                future_to_vulnid = {
                    executor.submit(process_vuln_for_scdef, vuln_id): vuln_id
                    for vuln_id in vuln_ids
                }
                for future in concurrent.futures.as_completed(future_to_vulnid):
                    vuln_id = future_to_vulnid[future]
                    try:
                        result = future.result()
                        all_results.append(result)
                        processed_vuln_count += 1
                        if result.get("status") == "success":
                            total_success += 1
                        else:
                            total_failed += 1
                    except Exception as exc:
                        if isinstance(exc, AuthenticationError):
                            raise
                        all_results.append(
                            {
                                "vulnID": vuln_id,
                                "status": "thread_exception",
                                "error": str(exc),
                            }
                        )
                        total_failed += 1
                    progress.advance(task)

        end_time = time.time()
        duration = end_time - start_time
        rate = processed_vuln_count / duration if duration > 0 else 0

        console.print("\n--- Processing Summary ---")
        console.print(f"Processed {processed_vuln_count}/{total_vulns} vulnIDs.")
        console.print(f"Successful Triggers: {total_success}")
        console.print(f"Failed Triggers:     {total_failed}")
        console.print(
            f"Total processing time: {duration:.2f} seconds ({rate:.2f} vulnIDs/sec)"
        )

        # --- Write Detailed Log File ---
        log_filename = f"scdef_init_log_{time.strftime('%Y%m%d-%H%M%S')}.json"
        log_filepath = log_dir / log_filename
        log_data = {
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
            "threads": max_workers,
            "input_collection": collection,
            "input_vulnid": identifier,
            "graph_id": graph,
            "summary": {
                "processed_vulnIDs": processed_vuln_count,
                "total_vulnIDs_in_collection": total_vulns,
                "total_success": total_success,
                "total_failed": total_failed,
                "processing_time_seconds": round(duration, 2),
                "processing_rate_vulnIDs_per_sec": round(rate, 2),
            },
            "details_per_vulnID": all_results,
        }
        try:
            with log_filepath.open("w", encoding="utf-8") as f_log:
                json.dump(log_data, f_log, indent=4)
            console.print(f"[*] Detailed results saved to: {log_filepath}")
        except Exception as e:
            console.print(
                f"\n[red]Error writing detailed log file to {log_dir}: {e}[/red]"
            )

        if total_failed > 0:
            console.print(
                "\n[bold yellow]Completed with errors. Check logs above and the "
                "detailed log file.[/bold yellow]"
            )

    except AuthenticationError as e:
        console.print(f"\n[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("refine-graph")
def refine_graph(
    collection: Optional[str] = typer.Option(
        None,
        "--collection",
        "-c",
        help="Name of the collection file containing vulnerability IDs.",
    ),
    identifier: Optional[str] = typer.Option(
        None, "--id", "-i", help="A single vulnerability ID or CVE ID to process."
    ),
    max_workers: int = typer.Option(
        4, "--max-workers", "-t", help="Number of worker threads."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-V", help="Show progress bar and verbose logs."
    ),
    log_dir: Optional[Path] = typer.Option(
        None,
        "--log-dir",
        help="Directory to save the detailed JSON log file (default: ./run_logs)",
    ),
):
    """
    Trigger exploit graph refinement for vulnerabilities.

    You must provide either --collection/-c or --id/-i.
    """
    console = Console()
    if not collection and not identifier:
        console.print(
            "[bold red]Error:[/bold red] Please provide either a --collection or an "
            "--id."
        )
        raise typer.Exit(code=1)
    if collection and identifier:
        console.print(
            "[bold red]Error:[/bold red] Options --collection and --id are mutually "
            "exclusive."
        )
        raise typer.Exit(code=1)

    try:
        config_mgr = ConfigManager()
        api_client = ApiClient()
        if identifier:
            vuln_id = _resolve_identifier(identifier)
            vuln_ids = [vuln_id] if vuln_id else []
        else:
            identifiers = get_vuln_identifiers_from_collection(collection, config_mgr)
            vuln_ids = [item["vuln_id"] for item in identifiers]

        if not vuln_ids:
            console.print(
                "[bold red]Error:[/bold red] No valid vulnerability IDs found to "
                "process."
            )
            raise typer.Exit(code=1)

        total_vulns = len(vuln_ids)
        if not log_dir:
            log_dir = Path("./run_logs")
        log_dir.mkdir(parents=True, exist_ok=True)

        # Calculate optimal worker count based on collection size
        optimal_workers = calculate_optimal_workers(total_vulns, max_workers)
        if optimal_workers != max_workers:
            console.print(
                f"[*] Adjusted worker count from {max_workers} to {optimal_workers} "
                f"based on collection size ({total_vulns} items)"
            )
            max_workers = optimal_workers

        console.print(f"[*] Found {total_vulns} vulnerability IDs to process.")
        console.print(f"[*] Using {max_workers} worker threads.")
        console.print(f"[*] Detailed log file will be saved in: {log_dir}")

        def process_vuln_for_graph_refinement(vulnID):
            result = {
                "vulnID": vulnID,
                "status": "processed",
                "error": None,
                "status_code": None,
            }
            try:
                # POST to /vulnerability.../refine-exploit-graph
                response = retry_with_backoff(
                    lambda: api_client.post(
                        f"/vulnerability_records/{vulnID}/actions/"
                        "refine-exploit-graph",
                        json={},
                    )
                )
                result["status_code"] = response.status_code
                if 200 <= response.status_code < 300:
                    result["status"] = "success"
                else:
                    result["status"] = "failed"
                    result["error"] = f"HTTP {response.status_code}: {response.text}"
                    if verbose:
                        console.print(
                            f"[red]Failed to trigger exploit graph refinement for {vulnID}: "
                            f"{result['error']}[/red]"
                        )
            except Exception as e:
                if isinstance(e, AuthenticationError):
                    raise
                result["status"] = "failed"
                result["error"] = str(e)
                if verbose:
                    console.print(f"[red]Exception for {vulnID}: {e}[/red]")
            return result

        all_results = []
        total_success = 0
        total_failed = 0
        processed_vuln_count = 0

        start_time = time.time()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("•"),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                f"[green]Processing {total_vulns} VulnIDs...", total=total_vulns
            )
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers
            ) as executor:
                future_to_vulnid = {
                    executor.submit(process_vuln_for_graph_refinement, vuln_id): vuln_id
                    for vuln_id in vuln_ids
                }
                for future in concurrent.futures.as_completed(future_to_vulnid):
                    vuln_id = future_to_vulnid[future]
                    try:
                        result = future.result()
                        all_results.append(result)
                        processed_vuln_count += 1
                        if result.get("status") == "success":
                            total_success += 1
                        else:
                            total_failed += 1
                    except Exception as exc:
                        if isinstance(exc, AuthenticationError):
                            raise
                        all_results.append(
                            {
                                "vulnID": vuln_id,
                                "status": "thread_exception",
                                "error": str(exc),
                            }
                        )
                        total_failed += 1
                    progress.advance(task)

        end_time = time.time()
        duration = end_time - start_time
        rate = processed_vuln_count / duration if duration > 0 else 0

        console.print("\n--- Processing Summary ---")
        console.print(f"Processed {processed_vuln_count}/{total_vulns} vulnIDs.")
        console.print(f"Successful Triggers: {total_success}")
        console.print(f"Failed Triggers:     {total_failed}")
        console.print(
            f"Total processing time: {duration:.2f} seconds ({rate:.2f} vulnIDs/sec)"
        )

        # --- Write Detailed Log File ---
        log_filename = (
            f"exploit_graph_refinement_log_{time.strftime('%Y%m%d-%H%M%S')}.json"
        )
        log_filepath = log_dir / log_filename
        log_data = {
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
            "threads": max_workers,
            "input_collection": collection,
            "input_vulnid": identifier,
            "summary": {
                "processed_vulnIDs": processed_vuln_count,
                "total_vulnIDs_in_collection": total_vulns,
                "total_success": total_success,
                "total_failed": total_failed,
                "processing_time_seconds": round(duration, 2),
                "processing_rate_vulnIDs_per_sec": round(rate, 2),
            },
            "details_per_vulnID": all_results,
        }
        try:
            with log_filepath.open("w", encoding="utf-8") as f_log:
                json.dump(log_data, f_log, indent=4)
            console.print(f"[*] Detailed results saved to: {log_filepath}")
        except Exception as e:
            console.print(
                f"\n[red]Error writing detailed log file to {log_dir}: {e}[/red]"
            )

        if total_failed > 0:
            console.print(
                "\n[bold yellow]Completed with errors. Check logs above and the "
                "detailed log file.[/bold yellow]"
            )

    except AuthenticationError as e:
        console.print(f"\n[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("update-source")
def update_source(
    collection: Optional[str] = typer.Option(
        None,
        "--collection",
        "-c",
        help="Name of the collection file containing vulnerability IDs.",
    ),
    identifier: Optional[str] = typer.Option(
        None,
        "--id",
        "-i",
        help="A single vulnerability ID (CVE-XXXX-YYYY or vulnID UUID) to process.",
    ),
    max_workers: int = typer.Option(
        4, "--max-workers", "-t", help="Number of worker threads."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-V", help="Show progress bar and verbose logs."
    ),
    log_dir: Optional[Path] = typer.Option(
        None,
        "--log-dir",
        help="Directory to save the detailed JSON log file (default: ./run_logs)",
    ),
):
    """
    Trigger vulnerability updates from NIST API source.

    You must provide either --collection/-c or --id/-i.

    The --id parameter accepts both CVE IDs (CVE-XXXX-YYYY) and vulnID UUIDs.
    Examples:
      wafrunner research update-source -i CVE-2024-1234
      wafrunner research update-source -i 1d4f8624-8acf-4c57-ab06-2b7bdf93ca36
      wafrunner research update-source -c my-vulnerabilities
    """
    console = Console()
    if not collection and not identifier:
        console.print(
            "[bold red]Error:[/bold red] Please provide either a --collection or an "
            "--id."
        )
        raise typer.Exit(code=1)
    if collection and identifier:
        console.print(
            "[bold red]Error:[/bold red] Options --collection and --id are mutually "
            "exclusive."
        )
        raise typer.Exit(code=1)

    try:
        config_mgr = ConfigManager()
        api_client = ApiClient()

        if identifier:
            vuln_id = _resolve_identifier(identifier)
            vuln_ids = [vuln_id] if vuln_id else []
        else:
            identifiers = get_vuln_identifiers_from_collection(collection, config_mgr)
            vuln_ids = [item["vuln_id"] for item in identifiers]

        if not vuln_ids:
            console.print(
                "[bold red]Error:[/bold red] No valid vulnerability IDs found to "
                "process."
            )
            raise typer.Exit(code=1)

        total_vulns = len(vuln_ids)
        if not log_dir:
            log_dir = Path("./run_logs")
        log_dir.mkdir(parents=True, exist_ok=True)

        # Calculate optimal worker count based on collection size
        optimal_workers = calculate_optimal_workers(total_vulns, max_workers)
        if optimal_workers != max_workers:
            console.print(
                f"[*] Adjusted worker count from {max_workers} to {optimal_workers} "
                f"based on collection size ({total_vulns} items)"
            )
            max_workers = optimal_workers

        console.print(f"[*] Found {total_vulns} vulnerability IDs to process.")
        console.print(f"[*] Using {max_workers} worker threads.")
        console.print(f"[*] Detailed log file will be saved in: {log_dir}")

        def process_vuln_for_update_source(vulnID):
            result = {
                "vulnID": vulnID,
                "status": "processed",
                "error": None,
                "status_code": None,
            }
            try:
                # POST to /vulnerability.../update-from-source
                response = retry_with_backoff(
                    lambda: api_client.post(
                        f"/vulnerability_records/{vulnID}/actions/update-from-source",
                        json={},  # Empty body as per Lambda function
                    )
                )
                result["status_code"] = response.status_code
                if response.status_code == 202:
                    result["status"] = "success"
                elif response.status_code == 400:
                    result["status"] = "failed"
                    result["error"] = "Invalid vulnID or bad request"
                elif response.status_code == 500:
                    result["status"] = "failed"
                    result["error"] = "Server error or queue configuration issue"
                else:
                    result["status"] = "failed"
                    result["error"] = f"HTTP {response.status_code}: {response.text}"
                    if verbose:
                        console.print(
                            f"[red]Failed to trigger update from source for {vulnID}: "
                            f"{result['error']}[/red]"
                        )
            except Exception as e:
                if isinstance(e, AuthenticationError):
                    raise
                result["status"] = "failed"
                result["error"] = str(e)
                if verbose:
                    console.print(f"[red]Exception for {vulnID}: {e}[/red]")
            return result

        all_results = []
        total_success = 0
        total_failed = 0
        processed_vuln_count = 0

        start_time = time.time()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("•"),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                f"[green]Processing {total_vulns} VulnIDs...", total=total_vulns
            )
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers
            ) as executor:
                future_to_vulnid = {
                    executor.submit(process_vuln_for_update_source, vuln_id): vuln_id
                    for vuln_id in vuln_ids
                }
                for future in concurrent.futures.as_completed(future_to_vulnid):
                    vuln_id = future_to_vulnid[future]
                    try:
                        result = future.result()
                        all_results.append(result)
                        processed_vuln_count += 1
                        if result.get("status") == "success":
                            total_success += 1
                        else:
                            total_failed += 1
                    except Exception as exc:
                        if isinstance(exc, AuthenticationError):
                            raise
                        all_results.append(
                            {
                                "vulnID": vuln_id,
                                "status": "thread_exception",
                                "error": str(exc),
                            }
                        )
                        total_failed += 1
                    progress.advance(task)

        end_time = time.time()
        duration = end_time - start_time
        rate = processed_vuln_count / duration if duration > 0 else 0

        console.print("\n--- Processing Summary ---")
        console.print(f"Processed {processed_vuln_count}/{total_vulns} vulnIDs.")
        console.print(f"Successful Updates: {total_success}")
        console.print(f"Failed Updates:     {total_failed}")
        console.print(
            f"Total processing time: {duration:.2f} seconds ({rate:.2f} vulnIDs/sec)"
        )

        # --- Write Detailed Log File ---
        log_filename = f"update_source_log_{time.strftime('%Y%m%d-%H%M%S')}.json"
        log_filepath = log_dir / log_filename
        log_data = {
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
            "threads": max_workers,
            "input_collection": collection,
            "input_vulnid": identifier,
            "summary": {
                "processed_vulnIDs": processed_vuln_count,
                "total_vulnIDs_in_collection": total_vulns,
                "total_success": total_success,
                "total_failed": total_failed,
                "processing_time_seconds": round(duration, 2),
                "processing_rate_vulnIDs_per_sec": round(rate, 2),
            },
            "details_per_vulnID": all_results,
        }
        try:
            with log_filepath.open("w", encoding="utf-8") as f_log:
                json.dump(log_data, f_log, indent=4)
            console.print(f"[*] Detailed results saved to: {log_filepath}")
        except Exception as e:
            console.print(
                f"\n[red]Error writing detailed log file to {log_dir}: {e}[/red]"
            )

        if total_failed > 0:
            console.print(
                "\n[bold yellow]Completed with errors. Check logs above and the "
                "detailed log file.[/bold yellow]"
            )

    except AuthenticationError as e:
        console.print(f"\n[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except httpx.RequestError:
        console.print(
            "\n[bold red]Network Error:[/bold red] A network error occurred while "
            "communicating with the API."
        )
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command()
def links(
    collection: Optional[str] = typer.Option(
        None,
        "--collection",
        "-c",
        help="Name of the collection file containing vulnerability IDs.",
    ),
    identifier: Optional[str] = typer.Option(
        None, "--id", "-i", help="A single vulnerability ID or CVE ID to process."
    ),
):
    """
    Fetches and displays data source links and their statuses for vulnerabilities.
    """
    console = Console()
    if not collection and not identifier:
        console.print(
            "[bold red]Error:[/bold red] Please provide either a --collection or an "
            "--id."
        )
        raise typer.Exit(code=1)
    if collection and identifier:
        console.print(
            "[bold red]Error:[/bold red] Options --collection and --id are mutually "
            "exclusive."
        )
        raise typer.Exit(code=1)

    try:
        config_mgr = ConfigManager()
        api_client = ApiClient()

        if identifier:
            resolved_ids = lookup_ids(identifier)
            if resolved_ids:
                identifiers = [resolved_ids]
            else:
                console.print(
                    f"[bold red]Error:[/bold red] Could not resolve "
                    f"identifier: {identifier}"
                )
                raise typer.Exit(code=1)
        else:
            identifiers = get_vuln_identifiers_from_collection(collection, config_mgr)

        for item in identifiers:
            vuln_id = item["vuln_id"]
            cve_id = item.get("cve_id")

            try:
                # If CVE ID is not in the collection, fetch it from the API
                if not cve_id:
                    vuln_response = api_client.get(f"/vulnerability_records/{vuln_id}")
                    vuln_data = vuln_response.json()
                    cve_id = vuln_data.get("cve_id", "N/A")

                # Fetch data sources
                response = api_client.get(
                    f"/vulnerability_records/{vuln_id}/data_sources"
                )

                if response.status_code == 404:
                    console.print(
                        f"[italic grey]No data sources found for {cve_id} - "
                        f"{vuln_id}[/italic grey]"
                    )
                    continue

                response.raise_for_status()
                data_sources = response.json()

                if not data_sources:
                    console.print(
                        f"[italic grey]No data sources found for {cve_id} - "
                        f"{vuln_id}[/italic grey]"
                    )
                    continue

                # Sort data sources
                data_sources.sort(key=lambda x: x.get("testCategory") != "webExploit")

                table = Table(
                    title=f"Data Sources for {cve_id} - {vuln_id}", show_lines=True
                )
                table.add_column("URL", style="cyan", no_wrap=False, width=45)
                table.add_column("linkID", style="dim", no_wrap=True, width=38)
                table.add_column("Scraped", style="green", width=10)
                table.add_column("Size (KB)", style="magenta", justify="right")
                table.add_column("Classified", style="blue", width=10)
                table.add_column("Analysed", style="yellow", width=10)
                table.add_column("Test Category", style="green", width=15)

                for source in data_sources:
                    url = source.get("url", "")
                    link_id = source.get("linkID", "N/A")
                    scraped_status = source.get("scrapedStatus", "")
                    s3_file_size = source.get("s3FileSize")
                    classifier_status = source.get("classifierStatus", "")
                    analysed1_status = source.get("analysed1Status", "")
                    test_category = source.get("testCategory", "")

                    if scraped_status == "error":
                        scraped_status = "[red]error[/red]"
                    if classifier_status == "error":
                        classifier_status = "[red]error[/red]"
                    if analysed1_status == "error":
                        analysed1_status = "[red]error[/red]"

                    s3_file_size_kb = "N/A"
                    if isinstance(s3_file_size, (int, float)) and s3_file_size > 0:
                        s3_file_size_kb = f"{s3_file_size / 1024:.1f}"
                    elif s3_file_size == 0:
                        s3_file_size_kb = "0.0"

                    style = ""
                    if test_category == "webExploit":
                        style = "bold red"
                    elif test_category == "nonWebExploit":
                        style = "bold amber"
                    elif test_category == "Non-test":
                        style = "bold grey"
                    elif not test_category:
                        if classifier_status in ("complete", "error"):
                            style = "amber"
                        elif scraped_status == "complete":
                            style = "italic white"
                        elif scraped_status == "error":
                            style = "italic amber"
                        else:
                            style = "italic grey"

                    table.add_row(
                        f"[{style}]{url}[/{style}]",
                        link_id,
                        scraped_status,
                        s3_file_size_kb,
                        classifier_status,
                        analysed1_status,
                        test_category,
                    )

                console.print(table)

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    console.print(
                        f"[italic grey]No data sources found for "
                        f"{vuln_id}[/italic grey]"
                    )
                else:
                    console.print(
                        f"[bold red]Error fetching data for {vuln_id}: "
                        f"{e.response.status_code}[/bold red]"
                    )
            except httpx.RequestError as e:
                console.print(f"[bold red]Network error for {vuln_id}: {e}[/bold red]")

    except AuthenticationError as e:
        console.print(f"\n[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command()
def show(
    collection: Optional[str] = typer.Option(
        None,
        "--collection",
        "-c",
        help="Name of the collection file containing vulnerability IDs.",
    ),
    identifier: Optional[str] = typer.Option(
        None, "--id", "-i", help="A single vulnerability ID or CVE ID to process."
    ),
):
    """
    Fetches and displays exploit graph, SCDEF, and data source links for vulnerabilities.
    """
    console = Console()
    if not collection and not identifier:
        console.print(
            "[bold red]Error:[/bold red] Please provide either a --collection or an "
            "--id."
        )
        raise typer.Exit(code=1)
    if collection and identifier:
        console.print(
            "[bold red]Error:[/bold red] Options --collection and --id are mutually "
            "exclusive."
        )
        raise typer.Exit(code=1)

    try:
        config_mgr = ConfigManager()
        api_client = ApiClient()

        if identifier:
            resolved_ids = lookup_ids(identifier)
            if resolved_ids:
                identifiers = [resolved_ids]
            else:
                console.print(
                    f"[bold red]Error:[/bold red] Could not resolve "
                    f"identifier: {identifier}"
                )
                raise typer.Exit(code=1)
        else:
            identifiers = get_vuln_identifiers_from_collection(collection, config_mgr)

        for item in identifiers:
            vuln_id = item["vuln_id"]
            cve_id = item.get("cve_id")

            try:
                # If CVE ID is not in the collection, fetch it from the API
                if not cve_id:
                    vuln_response = api_client.get(f"/vulnerability_records/{vuln_id}")
                    vuln_data = vuln_response.json()
                    cve_id = vuln_data.get("cve_id", "N/A")

                # Fetch exploit graph information
                graph_id = None
                graph_created_at = None
                graph_updated_at = None
                exploit_graph = None
                try:
                    graph_response = api_client.get(
                        f"/vulnerability_records/{vuln_id}/exploit-graph"
                    )
                    if graph_response.status_code == 200:
                        graph_data = graph_response.json()
                        # Check for exploitGraph array to determine if graph exists
                        exploit_graph = graph_data.get("exploitGraph")
                        graph_id = (
                            graph_data.get("exploitGraphInstanceID")
                            or graph_data.get("graphID")
                            or graph_data.get("graph_id")
                            or graph_data.get("id")
                        )
                        graph_created_at = (
                            graph_data.get("graphCreatedTime")
                            or graph_data.get("createdAt")
                            or graph_data.get("created_at")
                        )
                        graph_updated_at = (
                            graph_data.get("graphUpdatedTime")
                            or graph_data.get("updatedAt")
                            or graph_data.get("updated_at")
                        )
                except httpx.HTTPStatusError:
                    # 404 or other HTTP errors - graph doesn't exist or error, continue
                    pass
                except Exception:
                    # Other errors (network, etc.) - continue
                    pass

                # Fetch SCDEF information
                scdefs = []
                try:
                    # Use the correct endpoint: /security-control-definitions (plural)
                    scdef_response = api_client.get(
                        f"/vulnerability_records/{vuln_id}/security-control-definitions"
                    )
                    if scdef_response.status_code == 200:
                        scdef_data = scdef_response.json()
                        # API returns an array of SCDEF objects
                        if isinstance(scdef_data, list):
                            scdefs = scdef_data
                        elif isinstance(scdef_data, dict):
                            # Handle case where it might be a single object wrapped
                            scdefs = [scdef_data]
                except httpx.HTTPStatusError:
                    # 404 or other HTTP errors - SCDEFs don't exist or error, continue
                    pass
                except Exception:
                    # Other errors (network, etc.) - continue
                    pass

                # Display graph and SCDEF information
                console.print(f"\n[bold cyan]{cve_id} - {vuln_id}[/bold cyan]")

                # Exploit Graph section
                console.print("\n[bold]Exploit Graph:[/bold]")
                if exploit_graph is not None and len(exploit_graph) > 0:
                    if graph_id:
                        console.print(f"  ID: {graph_id}")
                    if graph_created_at:
                        console.print(f"  Created at: {graph_created_at}")
                    if graph_updated_at:
                        console.print(f"  Updated at: {graph_updated_at}")
                    console.print(f"  Vectors: {len(exploit_graph)}")
                else:
                    console.print("  [italic grey]No exploit graph found[/italic grey]")

                # SCDEF section
                console.print("\n[bold]Security Controls Definition:[/bold]")
                if scdefs and len(scdefs) > 0:
                    console.print(f"  Found {len(scdefs)} SCDEF(s)")
                    # Display information about the first SCDEF (or all if there are few)
                    for idx, scdef in enumerate(scdefs[:3], 1):  # Show first 3
                        scdef_id = (
                            scdef.get("scdefID")
                            or scdef.get("scdef_id")
                            or scdef.get("id")
                        )
                        scdef_created_at = (
                            scdef.get("scdefCreatedTime")
                            or scdef.get("createdAt")
                            or scdef.get("created_at")
                        )
                        scdef_updated_at = (
                            scdef.get("scdefUpdatedTime")
                            or scdef.get("updatedAt")
                            or scdef.get("updated_at")
                        )
                        if len(scdefs) > 1:
                            console.print(f"\n  SCDEF {idx}:")
                        if scdef_id:
                            console.print(f"    ID: {scdef_id}")
                        if scdef_created_at:
                            console.print(f"    Created at: {scdef_created_at}")
                        if scdef_updated_at:
                            console.print(f"    Updated at: {scdef_updated_at}")
                        # Show exploit vector ID if available
                        exploit_vector_id = scdef.get("exploitVectorID")
                        if exploit_vector_id:
                            console.print(f"    Exploit Vector ID: {exploit_vector_id}")
                    if len(scdefs) > 3:
                        console.print(f"\n  ... and {len(scdefs) - 3} more SCDEF(s)")
                else:
                    console.print("  [italic grey]No SCDEF found[/italic grey]")

                # Fetch data sources
                response = api_client.get(
                    f"/vulnerability_records/{vuln_id}/data_sources"
                )

                if response.status_code == 404:
                    console.print(
                        f"\n[italic grey]No data sources found for {cve_id} - "
                        f"{vuln_id}[/italic grey]"
                    )
                    continue

                response.raise_for_status()
                data_sources = response.json()

                if not data_sources:
                    console.print(
                        f"\n[italic grey]No data sources found for {cve_id} - "
                        f"{vuln_id}[/italic grey]"
                    )
                    continue

                # Sort data sources
                data_sources.sort(key=lambda x: x.get("testCategory") != "webExploit")

                table = Table(
                    title=f"Data Sources for {cve_id} - {vuln_id}", show_lines=True
                )
                table.add_column("URL", style="cyan", no_wrap=False, width=45)
                table.add_column("linkID", style="dim", no_wrap=True, width=38)
                table.add_column("Scraped", style="green", width=10)
                table.add_column("Size (KB)", style="magenta", justify="right")
                table.add_column("Classified", style="blue", width=10)
                table.add_column("Analysed", style="yellow", width=10)
                table.add_column("Test Category", style="green", width=15)

                for source in data_sources:
                    url = source.get("url", "")
                    link_id = source.get("linkID", "N/A")
                    scraped_status = source.get("scrapedStatus", "")
                    s3_file_size = source.get("s3FileSize")
                    classifier_status = source.get("classifierStatus", "")
                    analysed1_status = source.get("analysed1Status", "")
                    test_category = source.get("testCategory", "")

                    if scraped_status == "error":
                        scraped_status = "[red]error[/red]"
                    if classifier_status == "error":
                        classifier_status = "[red]error[/red]"
                    if analysed1_status == "error":
                        analysed1_status = "[red]error[/red]"

                    s3_file_size_kb = "N/A"
                    if isinstance(s3_file_size, (int, float)) and s3_file_size > 0:
                        s3_file_size_kb = f"{s3_file_size / 1024:.1f}"
                    elif s3_file_size == 0:
                        s3_file_size_kb = "0.0"

                    style = ""
                    if test_category == "webExploit":
                        style = "bold red"
                    elif test_category == "nonWebExploit":
                        style = "bold amber"
                    elif test_category == "Non-test":
                        style = "bold grey"
                    elif not test_category:
                        if classifier_status in ("complete", "error"):
                            style = "amber"
                        elif scraped_status == "complete":
                            style = "italic white"
                        elif scraped_status == "error":
                            style = "italic amber"
                        else:
                            style = "italic grey"

                    table.add_row(
                        f"[{style}]{url}[/{style}]",
                        link_id,
                        scraped_status,
                        s3_file_size_kb,
                        classifier_status,
                        analysed1_status,
                        test_category,
                    )

                console.print("\n")
                console.print(table)

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    console.print(
                        f"[italic grey]No data sources found for "
                        f"{vuln_id}[/italic grey]"
                    )
                else:
                    console.print(
                        f"[bold red]Error fetching data for {vuln_id}: "
                        f"{e.response.status_code}[/bold red]"
                    )
            except httpx.RequestError as e:
                console.print(f"[bold red]Network error for {vuln_id}: {e}[/bold red]")

    except AuthenticationError as e:
        console.print(f"\n[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
