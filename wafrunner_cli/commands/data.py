import json
import time
import random
from pathlib import Path
from typing import Optional
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

from wafrunner_cli.core.api_client import ApiClient
from wafrunner_cli.core.exceptions import AuthenticationError
from wafrunner_cli.core.lookup_service import lookup_ids
from wafrunner_cli.commands.research import (
    ConfigManager,
    get_vuln_identifiers_from_collection,
    calculate_optimal_workers,
    retry_with_backoff,
)

app = typer.Typer(help="Commands for downloading and managing research artifacts.")


@app.command("get-graph")
def get_graph(
    collection: Optional[str] = typer.Option(
        None,
        "--collection",
        "-c",
        help="Name of the collection file containing vulnerability IDs.",
    ),
    identifier: Optional[str] = typer.Option(
        None, "--id", "-i", help="A single vulnerability ID or CVE ID to process."
    ),
    output_dir: Path = typer.Option(
        Path("./exploit-graphs"),
        "--output-dir",
        "-o",
        help="Directory to save downloaded graphs (default: ./exploit-graphs).",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing local graph files.",
    ),
    use_vuln_id_filename: bool = typer.Option(
        False,
        "--uuid",
        help="Save files using vuln_id (UUID) instead of CVE ID as filename.",
    ),
    max_workers: int = typer.Option(
        4, "--max-workers", "-t", help="Number of worker threads."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-V", help="Show progress bar and verbose logs."
    ),
):
    """
    Download exploit graphs to local files.

    Saves each graph as a JSON file named by CVE ID (default) or UUID (--uuid).
    Skips graphs that already exist locally unless --force is set.

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
            resolved_ids = lookup_ids(identifier)
            if not resolved_ids:
                console.print(
                    f"[bold red]Error:[/bold red] Could not resolve "
                    f"identifier: {identifier}"
                )
                raise typer.Exit(code=1)
            identifiers_list = [resolved_ids]
        else:
            identifiers_list = get_vuln_identifiers_from_collection(
                collection, config_mgr
            )

        if not identifiers_list:
            console.print(
                "[bold red]Error:[/bold red] No valid vulnerability IDs found to "
                "process."
            )
            raise typer.Exit(code=1)

        total_vulns = len(identifiers_list)

        # Create output directory
        output_dir = output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        # Calculate optimal worker count
        optimal_workers = calculate_optimal_workers(total_vulns, max_workers)
        if optimal_workers != max_workers:
            console.print(
                f"[*] Adjusted worker count from {max_workers} to {optimal_workers} "
                f"based on collection size ({total_vulns} items)"
            )
            max_workers = optimal_workers

        console.print(f"[*] Found {total_vulns} vulnerability IDs to process.")
        console.print(f"[*] Using {max_workers} worker threads.")
        console.print(f"[*] Saving graphs to: {output_dir}")
        if force:
            console.print("[*] Force mode: will overwrite existing local files.")

        def process_vuln(item):
            vuln_id = item["vuln_id"]
            cve_id = item.get("cve_id")

            result = {
                "vuln_id": vuln_id,
                "cve_id": cve_id,
                "status": "processed",
                "error": None,
                "file_path": None,
            }

            try:
                # Determine filename
                if use_vuln_id_filename:
                    filename = f"{vuln_id}.json"
                else:
                    if not cve_id:
                        # Resolve CVE ID from API if not in collection
                        try:
                            vuln_response = retry_with_backoff(
                                lambda: api_client.get(
                                    f"/vulnerability_records/{vuln_id}"
                                )
                            )
                            vuln_data = vuln_response.json()
                            cve_id = vuln_data.get("cve_id")
                            result["cve_id"] = cve_id
                        except Exception:
                            pass

                    if cve_id:
                        filename = f"{cve_id}.json"
                    else:
                        # Fall back to UUID if CVE ID unavailable
                        filename = f"{vuln_id}.json"

                file_path = output_dir / filename
                result["file_path"] = str(file_path)

                # Check if file already exists locally
                if file_path.exists() and not force:
                    result["status"] = "skipped"
                    result["error"] = "File already exists locally"
                    return result

                # Fetch exploit graph from API
                response = retry_with_backoff(
                    lambda: api_client.get(
                        f"/vulnerability_records/{vuln_id}/exploit-graph"
                    )
                )

                if response.status_code == 404:
                    result["status"] = "no_graph"
                    result["error"] = "No exploit graph exists for this vulnerability"
                    return result

                response.raise_for_status()
                graph_data = response.json()

                # Verify the response contains actual graph data
                exploit_graph = graph_data.get("exploitGraph")
                if exploit_graph is None or len(exploit_graph) == 0:
                    result["status"] = "no_graph"
                    result["error"] = "Exploit graph response is empty"
                    return result

                # Write to file
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(graph_data, f, indent=2)

                result["status"] = "success"
                return result

            except Exception as e:
                if isinstance(e, AuthenticationError):
                    raise
                result["status"] = "failed"
                result["error"] = str(e)
                if verbose:
                    console.print(
                        f"[red]Exception for {vuln_id}: {e}[/red]"
                    )
                return result

        all_results = []
        total_success = 0
        total_failed = 0
        total_skipped = 0
        total_no_graph = 0

        start_time = time.time()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("*"),
            TimeRemainingColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(
                f"[green]Downloading {total_vulns} exploit graphs...",
                total=total_vulns,
            )
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers
            ) as executor:
                future_to_item = {
                    executor.submit(process_vuln, item): item
                    for item in identifiers_list
                }
                for future in concurrent.futures.as_completed(future_to_item):
                    item = future_to_item[future]
                    try:
                        result = future.result()
                        all_results.append(result)
                        if result["status"] == "success":
                            total_success += 1
                        elif result["status"] == "skipped":
                            total_skipped += 1
                        elif result["status"] == "no_graph":
                            total_no_graph += 1
                        else:
                            total_failed += 1
                    except AuthenticationError:
                        raise
                    except Exception as exc:
                        all_results.append(
                            {
                                "vuln_id": item["vuln_id"],
                                "cve_id": item.get("cve_id"),
                                "status": "failed",
                                "error": str(exc),
                                "file_path": None,
                            }
                        )
                        total_failed += 1
                    progress.advance(task)

        end_time = time.time()
        duration = end_time - start_time
        processed = len(all_results)
        rate = processed / duration if duration > 0 else 0

        console.print("\n--- Download Summary ---")
        console.print(f"Processed {processed}/{total_vulns} vulnerabilities.")
        console.print(f"Downloaded:          {total_success}")
        console.print(f"Skipped (exists):    {total_skipped}")
        console.print(f"No graph available:  {total_no_graph}")
        console.print(f"Failed:              {total_failed}")
        console.print(
            f"Total time: {duration:.2f} seconds ({rate:.2f} items/sec)"
        )

        if total_failed > 0:
            console.print(
                "\n[bold yellow]Some downloads failed. Details:[/bold yellow]"
            )
            for r in all_results:
                if r["status"] == "failed":
                    label = r.get("cve_id") or r["vuln_id"]
                    console.print(f"  [red]{label}: {r['error']}[/red]")

    except AuthenticationError as e:
        console.print(f"\n[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("get-controls")
def get_controls(
    vulnid: Optional[str] = typer.Option(
        None, "--vulnid", help="A specific vulnerability ID."
    ),
    cve_id: Optional[str] = typer.Option(None, "--cve-id", help="A specific CVE ID."),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="The directory to save the downloaded controls.",
        file_okay=False,
        dir_okay=True,
        writable=True,
        resolve_path=True,
    ),
):
    """
    Download security controls for a vulnerability.
    """
    console = Console()
    if (vulnid is None) == (cve_id is None):
        console.print(
            "[bold red]Error:[/bold red] Please provide exactly one of --vulnid or "
            "--cve-id."
        )
        raise typer.Exit(code=1)

    console.print(
        f"Placeholder for 'data get-controls' with vulnid: {vulnid}, cve_id: {cve_id}"
    )
