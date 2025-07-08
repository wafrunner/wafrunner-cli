import typer
from rich import print
from pathlib import Path
import httpx
import glob
import os

from wafrunner_cli.core.config_manager import ConfigManager
from wafrunner_cli.core.api_client import ApiClient

app = typer.Typer(
    name="update",
    help="Downloads the latest CVE ID to vulnID lookup file or reverts to the previous version.",
    no_args_is_help=True
)

@app.command()
def update(
    revert: bool = typer.Option(False, "--revert", help="Revert to the previous version of the lookup file.")
):
    """
    Downloads the latest CVE ID to vulnID lookup file or reverts to the previous version.
    """
    lookup_dir = get_lookup_dir()
    
    if revert:
        handle_revert(lookup_dir)
    else:
        handle_update(lookup_dir)

def get_lookup_dir() -> Path:
    """Returns the directory where lookup files are stored."""
    config_manager = ConfigManager()
    lookup_dir = config_manager.get_data_dir() / "cve-lookup"
    lookup_dir.mkdir(parents=True, exist_ok=True)
    return lookup_dir

def handle_update(lookup_dir: Path):
    """Handles the download and cleanup of the lookup file."""
    print("[cyan]Fetching download link for the latest CVE lookup file...[/cyan]")
    try:
        api_client = ApiClient()
        response = api_client.get_cve_lookup_download_url()
        response.raise_for_status()
        data = response.json()
        file_name = data.get("fileName")
        download_url = data.get("downloadUrl")

        if not file_name or not download_url:
            print("[bold red]Error: Invalid response from the API.[/bold red]")
            raise typer.Exit(code=1)

        output_file = lookup_dir / file_name
        print(f"[cyan]Downloading {file_name}...[/cyan]")
        with httpx.stream("GET", download_url) as r:
            r.raise_for_status()
            with open(output_file, 'wb') as f:
                for chunk in r.iter_bytes():
                    f.write(chunk)
        
        print(f"[green]Successfully downloaded {file_name}.[/green]")

        # Cleanup old files
        cleanup_old_files(lookup_dir)

    except httpx.HTTPStatusError as e:
        print(f"[bold red]Error downloading file: {e.response.status_code} - {e.response.text}[/bold red]")
        raise typer.Exit(code=1)
    except Exception as e:
        print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        raise typer.Exit(code=1)

def handle_revert(lookup_dir: Path):
    """Handles reverting to the previous version of the lookup file."""
    print("[cyan]Reverting to the previous lookup file...[/cyan]")
    files = sorted(glob.glob(str(lookup_dir / "*.json")), key=os.path.getmtime, reverse=True)

    if len(files) < 2:
        print("[bold red]Error: Not enough files to revert.[/bold red]")
        raise typer.Exit(code=1)

    latest_file = Path(files[0])
    previous_file = Path(files[1])

    print(f"[yellow]Deleting current version: {latest_file.name}[/yellow]")
    os.remove(latest_file)
    print(f"[green]Successfully reverted to {previous_file.name}.[/green]")

def cleanup_old_files(lookup_dir: Path):
    """Deletes all but the two most recent lookup files."""
    files = sorted(glob.glob(str(lookup_dir / "*.json")), key=os.path.getmtime, reverse=True)
    if len(files) > 2:
        print("[cyan]Cleaning up old lookup files...[/cyan]")
        for file_to_delete in files[2:]:
            print(f"[yellow]Deleting old file: {Path(file_to_delete).name}[/yellow]")
            os.remove(file_to_delete)
