import sys
import time
from pathlib import Path
from typing import List, Optional

import httpx
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

# In the actual application, these would be imported from the real core modules
from wafrunner_cli.core.api_client import ApiClient
from wafrunner_cli.core.config_manager import ConfigManager
from wafrunner_cli.core.exceptions import AuthenticationError

# --- Typer App and Rich Console Initialization ---
app = typer.Typer(
    name="research",
    help="Commands for initiating research and analysis tasks.",
    no_args_is_help=True
)
console = Console(stderr=True)  # For logging to stderr

# --- Helper Functions & Logic for 'github' command ---

def get_vuln_ids_from_collection(collection_name: str, config_manager: ConfigManager) -> List[str]:
    """Reads vulnerability IDs from a collection file using the configured data directory."""
    data_dir = config_manager.get_data_dir()
    # Assume collection files can have .txt or no extension for flexibility
    collection_path_txt = data_dir / f"{collection_name}.txt"
    collection_path = data_dir / collection_name

    target_path = None
    if collection_path.is_file():
        target_path = collection_path
    elif collection_path_txt.is_file():
        target_path = collection_path_txt
    else:
        console.print(f"[bold red]Error:[/bold red] Collection '[bold yellow]{collection_name}[/bold yellow]' not found in data directory: {data_dir}")
        raise typer.Exit(code=1)

    try:
        with open(target_path, "r", encoding='utf-8') as f:
            vuln_ids = [line.strip() for line in f if line.strip()]
            if not vuln_ids:
                console.print(f"[bold yellow]Warning:[/bold yellow] The collection '{collection_name}' is empty.")
                raise typer.Exit()
            return vuln_ids
    except IOError as e:
        console.print(f"[bold red]File Error:[/bold red] Could not read file {target_path}: {e}")
        raise typer.Exit(code=1)

@app.command()
def github(
    collection: Optional[str] = typer.Option(
        None, "--collection", "-c",
        help="Name of the collection file in the data directory containing vulnerability IDs."
    ),
    vulnid: Optional[str] = typer.Option(
        None, "--vulnid", "-id",
        help="A single vulnerability ID to process."
    ),
    force: bool = typer.Option(
        False, "--force", "-f",
        help="Force a new search even if a completed search already exists."
    )
):
    """
    Trigger GitHub searches for vulnerabilities from a collection or a single ID.
    """
    if not collection and not vulnid:
        console.print("[bold red]Error:[/bold red] Please provide either a --collection or a --vulnid.")
        raise typer.Exit(code=1)
    if collection and vulnid:
        console.print("[bold red]Error:[/bold red] Options --collection and --vulnid are mutually exclusive.")
        raise typer.Exit(code=1)

    try:
        config = ConfigManager()
        api_client = ApiClient()
        
        vuln_ids = []
        if vulnid:
            vuln_ids = [vulnid]
        else:
            vuln_ids = get_vuln_ids_from_collection(collection, config)

        console.print(f"Found {len(vuln_ids)} vulnerability ID(s) to process.")
        if force:
            console.print("[bold yellow]Running in force mode: all vulnerabilities will be searched.[/bold yellow]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("[green]Processing...", total=len(vuln_ids))

            for current_vuln_id in vuln_ids:
                progress.update(task, description=f"[green]Processing {current_vuln_id}[/green]")
                
                record = api_client.get_vulnerability_record(current_vuln_id)
                if record is None:
                    console.print(f"Info: Record not found for {current_vuln_id}. Skipping.")
                    progress.advance(task)
                    continue

                if not force:
                    github_searches = record.get("github_searches", [])
                    skip_search = False
                    if isinstance(github_searches, list):
                        for entry in github_searches:
                            if isinstance(entry, dict) and entry.get("status", "").lower() == "complete":
                                skip_search = True
                                break
                    if skip_search:
                        console.print(f"Skipping {current_vuln_id}: Found existing completed search.")
                        progress.advance(task)
                        continue

                console.print(f"Triggering GitHub search for {current_vuln_id}...")
                success = api_client.trigger_github_search(current_vuln_id)
                if not success:
                    console.print(f"[bold red]Failed to trigger search for {current_vuln_id}.[/bold red]")
                
                progress.advance(task)
        
        console.print("\n[bold green]✔ Finished processing all vulnerability IDs.[/bold green]")

    except AuthenticationError as e:
        console.print(f"\n[bold red]API Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except httpx.RequestError:
        console.print("\n[bold red]Network Error:[/bold red] A network error occurred while communicating with the API.")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred:[/bold red] {e}")
        raise typer.Exit(code=1)

# --- Other Research Commands (Placeholders) ---
# These can be fleshed out later using the same pattern.

@app.command()
def scrape(vulnid: Optional[str] = typer.Option(None, "--vulnid")):
    """Trigger a scrape for a vulnerability."""
    print(f"Placeholder for 'research scrape' with vulnid: {vulnid}")

@app.command()
def classify(vulnid: Optional[str] = typer.Option(None, "--vulnid")):
    """Trigger classification for a vulnerability."""
    print(f"Placeholder for 'research classify' with vulnid: {vulnid}")

@app.command("init-graph")
def init_graph(vulnid: Optional[str] = typer.Option(None, "--vulnid")):
    """Initialize an exploit graph for a vulnerability."""
    print(f"Placeholder for 'research init-graph' with vulnid: {vulnid}")

# Add other placeholder commands as needed...
