import os
import sys
import json
import time
from pathlib import Path
from typing import List, Optional, Any
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

# --- Config Manager (for data dir only) ---
class ConfigManager:
    def __init__(self):
        self._data_dir = Path.home() / ".wafrunner" / "data"
        self._data_dir.mkdir(parents=True, exist_ok=True)

    def get_data_dir(self) -> Path:
        return self._data_dir.expanduser()

# --- Helper Function for Collections ---
def get_vuln_identifiers_from_collection(collection_name: str, config_manager: ConfigManager) -> List[dict]:
    """
    Parses a collection file (.json or .txt) and returns a list of vulnerability identifiers.
    For JSON, expects a list of objects with 'cve_id' and 'vuln_id'.
    For TXT, assumes each line is a vuln_id.
    Returns: A list of dictionaries, e.g., [{'cve_id': 'CVE-xxx', 'vuln_id': 'guid-xxx'}, ...]
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
            with open(target_path, "r", encoding='utf-8') as f:
                data = json.load(f)
            vulnerabilities = data.get("vulnerabilities", [])
            for v in vulnerabilities:
                if v.get("vuln_id"):
                    identifiers.append({
                        "cve_id": v.get("cve_id"),
                        "vuln_id": v.get("vuln_id")
                    })
        except (IOError, json.JSONDecodeError) as e:
            console.print(f"[bold red]File Error:[/bold red] Could not read or parse JSON file {target_path}: {e}")
            raise typer.Exit(code=1)
    elif txt_path.is_file() or txt_path2.is_file():
        target_path = txt_path if txt_path.is_file() else txt_path2
        try:
            with open(target_path, "r", encoding='utf-8') as f:
                for line in f:
                    vuln_id = line.strip()
                    if vuln_id:
                        identifiers.append({"cve_id": None, "vuln_id": vuln_id})
        except IOError as e:
            console.print(f"[bold red]File Error:[/bold red] Could not read file {target_path}: {e}")
            raise typer.Exit(code=1)
    else:
        console.print(f"[bold red]Error:[/bold red] Collection '[bold yellow]{collection_name}[/bold yellow]' not found.")
        raise typer.Exit(code=1)

    if not identifiers:
        console.print(f"[bold yellow]Warning:[/bold yellow] The collection '{collection_name}' is empty or invalid.")
        raise typer.Exit()
        
    return identifiers

app = typer.Typer(
    name="research",
    help="Commands for initiating research and analysis tasks.",
    no_args_is_help=True
)




@app.command()
def github(
    collection: Optional[str] = typer.Option(None, "--collection", "-c", help="Name of the collection file containing vulnerability IDs."),
    vulnid: Optional[str] = typer.Option(None, "--vulnid", "-v", help="A single vulnerability ID to process."),
    force: bool = typer.Option(False, "--force", "-f", help="Force a new search even if a completed search already exists."),
    max_workers: int = typer.Option(10, "--max-workers", help="Max number of parallel workers for large collections."),
):
    """Trigger GitHub searches for vulnerabilities from a collection or a single ID."""
    console = Console()
    if not collection and not vulnid:
        console.print("[bold red]Error:[/bold red] Please provide either a --collection or a --vulnid.")
        raise typer.Exit(code=1)
    if collection and vulnid:
        console.print("[bold red]Error:[/bold red] Options --collection and --vulnid are mutually exclusive.")
        raise typer.Exit(code=1)

    try:
        config_mgr = ConfigManager()
        api_client = ApiClient()
        
        if vulnid:
            vuln_ids = [vulnid]
        else:
            identifiers = get_vuln_identifiers_from_collection(collection, config_mgr)
            vuln_ids = [item['vuln_id'] for item in identifiers]

        console.print(f"Found {len(vuln_ids)} vulnerability ID(s) to process.")
        if force:
            console.print("[bold yellow]Running in force mode: all vulnerabilities will be searched.[/bold yellow]")

        skipped = 0
        failed = 0
        triggered = 0

        def process_vuln(current_vuln_id):
            nonlocal skipped, failed, triggered
            try:
                response = api_client.get(f"/vulnerability_records/{current_vuln_id}")
            except AuthenticationError as e:
                raise e  # Re-raise to be caught by the main handler
            except Exception as e:
                console.print(f"[red]API error for {current_vuln_id}: {e}[/red]")
                failed += 1
                return

            if response.status_code == 404:
                console.print(f"Info: Record not found for {current_vuln_id}. Skipping.")
                failed += 1
                return

            try:
                record = response.json()
            except Exception as e:
                console.print(f"[red]Failed to parse record for {current_vuln_id}: {e}[/red]")
                failed += 1
                return

            if not force:
                github_searches = record.get("github_searches", [])
                skip_search = False
                if isinstance(github_searches, list):
                    for entry in github_searches:
                        if isinstance(entry, dict) and entry.get("status", "").lower() == "complete":
                            skip_search = True
                            break
                if skip_search:
                    skipped += 1
                    return

            try:
                post_response = api_client.post(
                    f"/vulnerability_records/{current_vuln_id}/actions/search",
                    json={"searchType": "github"}
                )
            except Exception as e:
                console.print(f"[bold red]Failed to trigger search for {current_vuln_id}: {e}[/bold red]")
                failed += 1
                return

            if post_response.status_code not in (200, 201, 204, 409):
                console.print(f"[bold red]Failed to trigger search for {current_vuln_id}. Status: {post_response.status_code}[/bold red]")
                failed += 1
            else:
                triggered += 1

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[green]Processing VulnIDs...", total=len(vuln_ids))

            if len(vuln_ids) <= 5:
                for idx, current_vuln_id in enumerate(vuln_ids, 1):
                    process_vuln(current_vuln_id)
                    if idx % 50 == 0 or len(vuln_ids) < 50:
                        console.print(f"Triggered GitHub search for {current_vuln_id}... ({idx}/{len(vuln_ids)})")
                    progress.advance(task)
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {executor.submit(process_vuln, vid): vid for vid in vuln_ids}
                    for idx, future in enumerate(concurrent.futures.as_completed(futures), 1):
                        # Optionally, print progress every 50
                        if idx % 50 == 0 or len(vuln_ids) < 50:
                            console.print(f"Processed {idx} of {len(vuln_ids)} vulnerability IDs...")
                        progress.advance(task)

        console.print(f"\n[bold green]✔ Finished processing all vulnerability IDs.[/bold green]")
        console.print(f"Triggered: [green]{triggered}[/green], Skipped: [yellow]{skipped}[/yellow], Failed: [red]{failed}[/red]")

    except AuthenticationError as e:
        console.print(f"\n[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except httpx.RequestError:
        console.print("\n[bold red]Network Error:[/bold red] A network error occurred while communicating with the API.")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command()
def scrape(
    collection: Optional[str] = typer.Option(None, "--collection", "-c", help="Name of the collection file containing vulnerability IDs."),
    vulnid: Optional[str] = typer.Option(None, "--vulnid", "-id", help="A single vulnerability ID to process.")
):
    """Trigger scrapes for data sources associated with vulnerabilities."""
    console = Console()
    if not collection and not vulnid:
        console.print("[bold red]Error:[/bold red] Please provide either a --collection or a --vulnid.")
        raise typer.Exit(code=1)
    if collection and vulnid:
        console.print("[bold red]Error:[/bold red] Options --collection and --vulnid are mutually exclusive.")
        raise typer.Exit(code=1)

    try:
        config_mgr = ConfigManager()
        api_client = ApiClient()

        if vulnid:
            vuln_ids = [vulnid]
        else:
            identifiers = get_vuln_identifiers_from_collection(collection, config_mgr)
            vuln_ids = [item['vuln_id'] for item in identifiers]

        console.print(f"Found {len(vuln_ids)} vulnerability ID(s) to process for scraping.")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[green]Processing VulnIDs...", total=len(vuln_ids))

            for current_vuln_id in vuln_ids:
                progress.update(task, description=f"[green]Processing {current_vuln_id}[/green]")

                # --- Real API call to get data sources ---
                try:
                    response = api_client.get(f"/vulnerability_records/{current_vuln_id}/data_sources")
                except AuthenticationError as e:
                    raise e  # Re-raise to be caught by the main handler
                except Exception as e:
                    console.print(f"[red]API error for {current_vuln_id}: {e}[/red]")
                    progress.advance(task)
                    continue

                if response.status_code == 404:
                    console.print(f"Info: No data sources found for {current_vuln_id} (or record not found).")
                    progress.advance(task)
                    continue

                try:
                    data_sources = response.json()
                except Exception as e:
                    console.print(f"[red]Failed to parse data sources for {current_vuln_id}: {e}[/red]")
                    progress.advance(task)
                    continue

                triggered_count = 0
                skipped_count = 0
                for record in data_sources:
                    if not isinstance(record, dict):
                        console.print(f"[yellow]Warning:[/yellow] Skipping invalid data source record (not a dict) for {current_vuln_id}.")
                        continue

                    link_id = record.get("linkID")
                    scraped_status = str(record.get("scrapedStatus", "")).lower()

                    if not link_id:
                        console.print(f"[yellow]Warning:[/yellow] Skipping record for {current_vuln_id} due to missing linkID.")
                        skipped_count += 1
                        continue

                    if scraped_status in ("complete", "error"):
                        skipped_count += 1
                        continue

                    # --- Real API call to trigger scrape ---
                    try:
                        post_response = api_client.post(
                            f"/vulnerability_records/{current_vuln_id}/data_sources/{link_id}/actions/scrape",
                            json={}
                            )
                    except Exception as e:
                        console.print(f"[red]Failed to trigger scrape for linkID: {link_id} ({e})[/red]")
                        continue

                    if post_response.status_code not in (200, 201, 409):
                        console.print(f"[red]Failed to trigger scrape for linkID: {link_id} (Status: {post_response.status_code})[/red]")
                    else:
                        triggered_count += 1

                console.print(f"Summary for {current_vuln_id}: Triggered [bold green]{triggered_count}[/bold green] scrapes, skipped [bold yellow]{skipped_count}[/bold yellow] data sources.")
                progress.advance(task)

        console.print("\n[bold green]✔ Finished processing all vulnerability IDs for scraping.[/bold green]")

    except AuthenticationError as e:
        console.print(f"\n[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except httpx.RequestError:
        console.print("\n[bold red]Network Error:[/bold red] A network error occurred while communicating with the API.")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred:[/bold red] {e}")
        raise typer.Exit(code=1)

@app.command()
def classify(
    collection: Optional[str] = typer.Option(None, "--collection", "-c", help="Name of the collection file containing vulnerability IDs."),
    vulnid: Optional[str] = typer.Option(None, "--vulnid", "-v", help="A single vulnerability ID to process."),
    update: bool = typer.Option(False, "--update", "-u", help="Trigger classifier even if status is 'complete' or 'error'."),
    retry: bool = typer.Option(False, "--retry", "-r", help="Trigger classifier ONLY if status is 'error'."),
    max_workers: int = typer.Option(16, "--max-workers", "-t", help="Number of worker threads."),
    verbose: bool = typer.Option(False, "--verbose", "-V", help="Show progress bar and verbose logs."),
    log_dir: Optional[Path] = typer.Option(None, "--log-dir", help="Directory to save the detailed JSON log file (default: ./run_logs)"),
):
    """
    Trigger classifier for vulnerabilities from a collection or a single ID, using multithreading.

    You must provide either --collection/-c or --vulnid/-v.
    """
    console = Console()
    if not collection and not vulnid:
        console.print("[bold red]Error:[/bold red] Please provide either a --collection or a --vulnid.")
        raise typer.Exit(code=1)
    if collection and vulnid:
        console.print("[bold red]Error:[/bold red] Options --collection and --vulnid are mutually exclusive.")
        raise typer.Exit(code=1)
    if update and retry:
        console.print("[bold red]Error:[/bold red] --update and --retry are mutually exclusive.")
        raise typer.Exit(code=1)

    try:
        config_mgr = ConfigManager()
        api_client = ApiClient()
        
        if vulnid:
            vuln_ids = [vulnid]
        else:
            identifiers = get_vuln_identifiers_from_collection(collection, config_mgr)
            vuln_ids = [item['vuln_id'] for item in identifiers]
            
        total_vulns = len(vuln_ids)
        mode_str = "Update" if update else "Retry" if retry else "Standard"
        if not log_dir:
            log_dir = Path("./run_logs")
        log_dir.mkdir(parents=True, exist_ok=True)

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
                response = api_client.get(f"/vulnerability_records/{vulnID}/data_sources")
                if response.status_code == 204 or response.status_code == 404 or not response.content:
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
                    post_response = api_client.post(
                        f"/vulnerability_records/{vulnID}/data_sources/{linkID_value}/actions/classify",
                        json={},  # Always send an empty JSON body
                    )
                    if 200 <= post_response.status_code < 300:
                        results["triggered_ok"].append(linkID_value)
                    else:
                        results["trigger_failed"].append(linkID_value)
                        if verbose:
                            console.print(f"[red]Failed to trigger classify for {vulnID}/{linkID_value}: Status {post_response.status_code} - {post_response.text}[/red]")
                except Exception as e:
                    results["trigger_failed"].append(linkID_value)
                    if verbose:
                        console.print(f"[red]Failed to trigger classify for {vulnID}/{linkID_value}: {e}[/red]")
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
            transient=False
        ) as progress:
            task = progress.add_task(
                f"[green]Processing {total_vulns} VulnIDs...", total=total_vulns
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
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
                        total_skipped_classify += len(result.get("skipped_classify", []))
                        total_skipped_linkid += result.get("skipped_linkid", 0)
                        total_error_fetching += 1 if result.get("error_fetching_sources") else 0
                    except Exception as exc:
                        if isinstance(exc, AuthenticationError):
                            raise
                        all_results.append({"vulnID": vuln_id, "status": "thread_exception", "error": str(exc)})
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
        log_filename = f"classifier_trigger_log_{mode_str}_{time.strftime('%Y%m%d-%H%M%S')}.json"
        log_filepath = log_dir / log_filename
        log_data = {
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": mode_str,
            "threads": max_workers,
            "input_collection": collection,
            "input_vulnid": vulnid,
            "summary": {
                "processed_vulnIDs": processed_vuln_count,
                "total_vulnIDs_in_collection": total_vulns,
                "total_triggered_ok": total_triggered_ok,
                "total_trigger_failed": total_trigger_failed,
                "total_skipped_scrape": total_skipped_scrape,
                "total_skipped_classify": total_skipped_classify,
                "total_skipped_linkid": total_skipped_linkid,
                "total_error_fetching_sources": total_error_fetching,
                "processing_time_seconds": round(end_time - start_time, 2)
            },
            "details_per_vulnID": all_results
        }
        try:
            with log_filepath.open('w', encoding='utf-8') as f_log:
                json.dump(log_data, f_log, indent=4)
            console.print(f"[*] Detailed results saved to: {log_filepath}")
        except Exception as e:
            console.print(f"\n[red]Error writing detailed log file to {log_dir}: {e}[/red]")

        if total_trigger_failed > 0 or total_error_fetching > 0:
            console.print("\n[bold yellow]Completed with errors. Check logs above and the detailed log file.[/bold yellow]")

    except AuthenticationError as e:
        console.print(f"\n[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)

@app.command("init-graph")
def init_graph(
    collection: Optional[str] = typer.Option(None, "--collection", "-c", help="Name of the collection file containing vulnerability IDs."),
    vulnid: Optional[str] = typer.Option(None, "--vulnid", "-v", help="A single vulnerability ID to process."),
    max_workers: int = typer.Option(16, "--max-workers", "-t", help="Number of worker threads."),
    verbose: bool = typer.Option(False, "--verbose", "-V", help="Show progress bar and verbose logs."),
    log_dir: Optional[Path] = typer.Option(None, "--log-dir", help="Directory to save the detailed JSON log file (default: ./run_logs)"),
):
    """
    Trigger exploit graph initialization for vulnerabilities from a collection or a single ID, using multithreading.

    You must provide either --collection/-c or --vulnid/-v.
    """
    console = Console()
    if not collection and not vulnid:
        console.print("[bold red]Error:[/bold red] Please provide either a --collection or a --vulnid.")
        raise typer.Exit(code=1)
    if collection and vulnid:
        console.print("[bold red]Error:[/bold red] Options --collection and --vulnid are mutually exclusive.")
        raise typer.Exit(code=1)

    try:
        config_mgr = ConfigManager()
        api_client = ApiClient()
        if vulnid:
            vuln_ids = [vulnid]
        else:
            identifiers = get_vuln_identifiers_from_collection(collection, config_mgr)
            vuln_ids = [item['vuln_id'] for item in identifiers]
            
        total_vulns = len(vuln_ids)
        if not log_dir:
            log_dir = Path("./run_logs")
        log_dir.mkdir(parents=True, exist_ok=True)

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
                # POST to /vulnerability_records/{vulnID}/actions/initialise-exploit-graph
                response = api_client.post(
                    f"/vulnerability_records/{vulnID}/actions/initialise-exploit-graph"
                )
                result["status_code"] = response.status_code
                if 200 <= response.status_code < 300:
                    result["status"] = "success"
                else:
                    result["status"] = "failed"
                    result["error"] = f"HTTP {response.status_code}: {response.text}"
                    if verbose:
                        console.print(f"[red]Failed to trigger exploit graph for {vulnID}: {result['error']}[/red]")
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
            transient=False
        ) as progress:
            task = progress.add_task(
                f"[green]Processing {total_vulns} VulnIDs...", total=total_vulns
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
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
                        else:
                            total_failed += 1
                    except Exception as exc:
                        if isinstance(exc, AuthenticationError):
                            raise
                        all_results.append({"vulnID": vuln_id, "status": "thread_exception", "error": str(exc)})
                        total_failed += 1
                    progress.advance(task)

        end_time = time.time()
        duration = end_time - start_time
        rate = processed_vuln_count / duration if duration > 0 else 0

        console.print("\n--- Processing Summary ---")
        console.print(f"Processed {processed_vuln_count}/{total_vulns} vulnIDs.")
        console.print(f"Successful Triggers: {total_success}")
        console.print(f"Failed Triggers:     {total_failed}")
        console.print(f"Total processing time: {duration:.2f} seconds ({rate:.2f} vulnIDs/sec)")

        # --- Write Detailed Log File ---
        log_filename = f"exploit_graph_trigger_log_{time.strftime('%Y%m%d-%H%M%S')}.json"
        log_filepath = log_dir / log_filename
        log_data = {
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
            "threads": max_workers,
            "input_collection": collection,
            "input_vulnid": vulnid,
            "summary": {
                "processed_vulnIDs": processed_vuln_count,
                "total_vulnIDs_in_collection": total_vulns,
                "total_success": total_success,
                "total_failed": total_failed,
                "processing_time_seconds": round(duration, 2),
                "processing_rate_vulnIDs_per_sec": round(rate, 2)
            },
            "details_per_vulnID": all_results
        }
        try:
            with log_filepath.open('w', encoding='utf-8') as f_log:
                json.dump(log_data, f_log, indent=4)
            console.print(f"[*] Detailed results saved to: {log_filepath}")
        except Exception as e:
            console.print(f"\n[red]Error writing detailed log file to {log_dir}: {e}[/red]")

        if total_failed > 0:
            console.print("\n[bold yellow]Completed with errors. Check logs above and the detailed log file.[/bold yellow]")

    except AuthenticationError as e:
        console.print(f"\n[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command()
def links(
    collection: Optional[str] = typer.Option(None, "--collection", "-c", help="Name of the collection file containing vulnerability IDs."),
    vulnid: Optional[str] = typer.Option(None, "--vulnid", "-v", help="A single vulnerability ID to process."),
):
    """
    Fetches and displays data source links for vulnerabilities.
    """
    console = Console()
    if not collection and not vulnid:
        console.print("[bold red]Error:[/bold red] Please provide either a --collection or a --vulnid.")
        raise typer.Exit(code=1)
    if collection and vulnid:
        console.print("[bold red]Error:[/bold red] Options --collection and --vulnid are mutually exclusive.")
        raise typer.Exit(code=1)

    try:
        config_mgr = ConfigManager()
        api_client = ApiClient()
        
        if vulnid:
            identifiers = [{"cve_id": None, "vuln_id": vulnid}]
        else:
            identifiers = get_vuln_identifiers_from_collection(collection, config_mgr)

        for item in identifiers:
            vuln_id = item['vuln_id']
            cve_id = item.get('cve_id')

            try:
                # If CVE ID is not in the collection, fetch it from the API
                if not cve_id:
                    vuln_response = api_client.get(f"/vulnerability_records/{vuln_id}")
                    vuln_data = vuln_response.json()
                    cve_id = vuln_data.get("cve_id", "N/A")

                # Fetch data sources
                response = api_client.get(f"/vulnerability_records/{vuln_id}/data_sources/")
                
                if response.status_code == 404:
                    console.print(f"[italic grey]No data sources found for {cve_id} - {vuln_id}[/italic grey]")
                    continue

                response.raise_for_status()
                data_sources = response.json()

                if not data_sources:
                    console.print(f"[italic grey]No data sources found for {cve_id} - {vuln_id}[/italic grey]")
                    continue

                # Sort data sources
                data_sources.sort(key=lambda x: x.get('testCategory') != 'webExploit')

                table = Table(title=f"Data Sources for {cve_id} - {vuln_id}")
                table.add_column("URL", style="cyan", no_wrap=False, width=50)
                table.add_column("CVEs", style="magenta", no_wrap=True)
                table.add_column("Test Category", style="green")

                for source in data_sources:
                    url = source.get("url", "")
                    cves = source.get("cves", [])
                    test_category = source.get("testCategory", "")
                    classifier_status = source.get("classifierStatus", "")
                    scraped_status = source.get("scrapedStatus", "")

                    style = ""
                    if test_category == 'webExploit':
                        style = "bold red"
                    elif test_category == 'nonWebExploit':
                        style = "bold amber"
                    elif test_category == 'Non-test':
                        style = "bold grey"
                    elif not test_category:
                        if classifier_status == 'complete' or classifier_status == 'error':
                            style = "amber"
                        elif scraped_status == 'complete':
                            style = "italic white"
                        elif scraped_status == 'error':
                            style = "italic amber"
                        else:
                            style = "italic grey"
                    
                    cve_display = ", ".join(cves[:1])
                    if len(cves) > 1:
                        cve_display += ", ..."

                    table.add_row(
                        f"[{style}]{url}[/{style}]",
                        cve_display,
                        test_category,
                    )
                
                console.print(table)

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    console.print(f"[italic grey]No data sources found for {vuln_id}[/italic grey]")
                else:
                    console.print(f"[bold red]Error fetching data for {vuln_id}: {e.response.status_code}[/bold red]")
            except httpx.RequestError as e:
                console.print(f"[bold red]Network error for {vuln_id}: {e}[/bold red]")

    except AuthenticationError as e:
        console.print(f"\n[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()
