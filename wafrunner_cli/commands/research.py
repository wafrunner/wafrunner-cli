import sys
import time
from pathlib import Path
from typing import List, Optional, Any
from decimal import Decimal

import httpx
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

# In the actual application, these would be imported from the real core modules
# NOTE: The placeholder classes below have been expanded to support all implemented commands
from wafrunner_cli.core.exceptions import AuthenticationError

# --- Placeholder Core Components ---
# In the actual application, these would be imported from wafrunner.core.
# They are included here to make the example runnable and demonstrate interaction.

def _convert_decimals(obj: Any) -> Any:
    """Helper to recursively convert Decimal objects to int or float."""
    if isinstance(obj, list):
        return [_convert_decimals(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: _convert_decimals(value) for key, value in obj.items()}
    elif isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    return obj

class ConfigManager:
    """
    Manages reading configuration from ~/.wafrunner/config.
    (Placeholder Implementation)
    """
    def __init__(self):
        self._config = {
            "api_key": "dummy_api_key_12345",
            "api_base_url": "https://api.wafrunner.com/v1",
            "data_dir": Path.home() / ".wafrunner" / "data"
        }
        self.get_data_dir().mkdir(parents=True, exist_ok=True)

    def get_api_key(self) -> str:
        return self._config["api_key"]

    def get_api_base_url(self) -> str:
        return self._config["api_base_url"]

    def get_data_dir(self) -> Path:
        return Path(self._config["data_dir"]).expanduser()

class ApiClient:
    """
    Handles all HTTP requests to the vulnerability API.
    (Placeholder Implementation)
    """
    def __init__(self, api_key: str, base_url: str):
        self.api_key = api_key
        self.base_url = base_url
        self.console = Console(style="bold magenta")

    def get_vulnerability_record(self, vuln_id: str) -> Optional[dict]:
        """(For github command) Retrieves the full vulnerability record."""
        self.console.print(f"API_CALL: GET {self.base_url}/vulnerability_records/{vuln_id}")
        time.sleep(0.05)
        if "notfound" in vuln_id: return None
        if "complete" in vuln_id: return {"github_searches": [{"status": "complete"}]}
        return {"github_searches": []}

    def trigger_github_search(self, vuln_id: str) -> bool:
        """(For github command) Triggers a GitHub search."""
        self.console.print(f"API_CALL: POST {self.base_url}/vulnerability_records/{vuln_id}/actions/search")
        time.sleep(0.1)
        return False if "fail" in vuln_id else True

    def get_data_sources(self, vuln_id: str) -> Optional[List[dict]]:
        """(For scrape command) Retrieves data sources for a vulnerability."""
        self.console.print(f"API_CALL: GET {self.base_url}/vulnerability_records/{vuln_id}/data_sources")
        time.sleep(0.05)
        if "no-sources" in vuln_id: return []
        if "notfound" in vuln_id: return None
        mock_data = [
            {"linkID": {"S": "link-1"}, "scrapedStatus": {"S": "new"}},
            {"linkID": "link-2", "scrapedStatus": "complete"},
            {"linkID": {"S": "link-3"}, "scrapedStatus": {"S": "error"}},
            {"linkID": {"S": "link-4-fail"}, "scrapedStatus": "pending"},
        ]
        return _convert_decimals(mock_data)

    def trigger_scrape(self, vuln_id: str, link_id: str) -> bool:
        """(For scrape command) Triggers a scrape for a data source."""
        self.console.print(f"API_CALL: POST {self.base_url}/vulnerability_records/{vuln_id}/data_sources/{link_id}/actions/scrape")
        time.sleep(0.1)
        return False if "fail" in link_id else True

# --- Typer App and Rich Console Initialization ---
app = typer.Typer(
    name="research",
    help="Commands for initiating research and analysis tasks.",
    no_args_is_help=True
)

# --- Helper Function for Collections ---
def get_vuln_ids_from_collection(collection_name: str, config_manager: ConfigManager) -> List[str]:
    """Reads vulnerability IDs from a collection file."""
    data_dir = config_manager.get_data_dir()
    console = Console()
    collection_path = data_dir / collection_name
    collection_path_txt = data_dir / f"{collection_name}.txt"
    target_path = collection_path if collection_path.is_file() else collection_path_txt
    if not target_path.is_file():
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

# --- CLI Commands ---

@app.command()
def github(
    collection: Optional[str] = typer.Option(None, "--collection", "-c", help="Name of the collection file containing vulnerability IDs."),
    vulnid: Optional[str] = typer.Option(None, "--vulnid", "-id", help="A single vulnerability ID to process."),
    force: bool = typer.Option(False, "--force", "-f", help="Force a new search even if a completed search already exists.")
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
        api_client = ApiClient(config_mgr.get_api_key(), config_mgr.get_api_base_url())
        
        vuln_ids = [vulnid] if vulnid else get_vuln_ids_from_collection(collection, config_mgr)

        console.print(f"Found {len(vuln_ids)} vulnerability ID(s) to process.")
        if force:
            console.print("[bold yellow]Running in force mode: all vulnerabilities will be searched.[/bold yellow]")

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), console=console) as progress:
            task = progress.add_task("[green]Processing VulnIDs...", total=len(vuln_ids))

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
        api_client = ApiClient(config_mgr.get_api_key(), config_mgr.get_api_base_url())
        
        vuln_ids = [vulnid] if vulnid else get_vuln_ids_from_collection(collection, config_mgr)

        console.print(f"Found {len(vuln_ids)} vulnerability ID(s) to process for scraping.")

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), console=console) as progress:
            task = progress.add_task("[green]Processing VulnIDs...", total=len(vuln_ids))

            for current_vuln_id in vuln_ids:
                progress.update(task, description=f"[green]Processing {current_vuln_id}[/green]")
                
                data_sources = api_client.get_data_sources(current_vuln_id)

                if data_sources is None:
                    console.print(f"Info: No data sources found for {current_vuln_id} (or record not found).")
                    progress.advance(task)
                    continue
                
                triggered_count = 0
                skipped_count = 0
                for record in data_sources:
                    if not isinstance(record, dict):
                        console.print(f"[yellow]Warning:[/yellow] Skipping invalid data source record (not a dict) for {current_vuln_id}.")
                        continue

                    link_id = record.get("linkID")
                    scraped_status = record.get("scrapedStatus", "").lower()

                    if not link_id:
                        console.print(f"[yellow]Warning:[/yellow] Skipping record for {current_vuln_id} due to missing linkID.")
                        skipped_count += 1
                        continue

                    if scraped_status in ("complete", "error"):
                        skipped_count += 1
                        continue
                    
                    console.print(f"Triggering scrape for {current_vuln_id}, linkID: {link_id}")
                    success = api_client.trigger_scrape(current_vuln_id, link_id)
                    if success:
                        triggered_count += 1
                    else:
                        console.print(f"[red]Failed[/red] to trigger scrape for linkID: {link_id}")

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
def classify(vulnid: Optional[str] = typer.Option(None, "--vulnid")):
    """Trigger classification for a vulnerability."""
    print(f"Placeholder for 'research classify' with vulnid: {vulnid}")

@app.command("init-graph")
def init_graph(vulnid: Optional[str] = typer.Option(None, "--vulnid")):
    """Initialize an exploit graph for a vulnerability."""
    print(f"Placeholder for 'research init-graph' with vulnid: {vulnid}")

if __name__ == "__main__":
    # This allows the file to be run directly for testing.
    app()
