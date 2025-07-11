import typer
from rich import print
import httpx
import json
from typing import Optional
from pathlib import Path
from datetime import datetime, timezone

from wafrunner_cli.core.api_client import ApiClient
from wafrunner_cli.core.database import Database

app = typer.Typer(
    name="update",
    help="Downloads the latest CVE ID to vulnID lookup data.",
    no_args_is_help=True,
)

# --- Constants and Configuration ---

DEFAULT_DATA_DIR = Path.home() / ".wafrunner"

COLLECTIONS_DIR = DEFAULT_DATA_DIR / "data" / "collections"


@app.command()
def update(
    verbose: bool = typer.Option(
        False,
        "-v",
        "--verbose",
        help="Output all new CVEs to stdout.",
    ),
    save_to_collection: bool = typer.Option(
        False,
        "-s",
        "--save-to-collection",
        help="Save all new CVEs to a new collection.",
    ),
    collection_name: Optional[str] = typer.Option(
        None,
        "-n",
        "--name",
        help="Name for the new collection. Defaults to a timestamped name.",
    ),
):
    """
    Downloads the latest CVE ID to vulnID lookup data.
    """
    if collection_name and not save_to_collection:
        print(
            "[bold red]Error:[/bold red] --name can only be used with "
            "--save-to-collection."
        )
        raise typer.Exit(code=1)

    print("[cyan]Fetching download link for the latest CVE lookup data...[/cyan]")
    try:
        api_client = ApiClient()
        response = api_client.get_cve_lookup_download_url()
        response.raise_for_status()
        data = response.json()
        download_url = data.get("downloadUrl")

        if not download_url:
            print("[bold red]Error: Invalid response from the API.[/bold red]")
            raise typer.Exit(code=1)

        print("[cyan]Downloading CVE data...[/cyan]")
        response = httpx.get(download_url)
        response.raise_for_status()
        cve_data = response.json()

        print("[cyan]Updating the local database...[/cyan]")
        db = Database()

        db.cursor.execute("SELECT cve_id FROM cve_lookup")
        existing_cves = {row[0] for row in db.cursor.fetchall()}
        initial_count = len(existing_cves)

        db.clear_cve_lookup()
        insert_data = [
            {
                "cve_id": cve,
                "vuln_id": info["vulnID"],
                "last_modified": info["lastModified"],
            }
            for cve, info in cve_data.items()
        ]
        db.insert_cve_data(insert_data)

        db.cursor.execute("SELECT COUNT(*) FROM cve_lookup")
        new_count = db.cursor.fetchone()[0]
        db.close()

        added_count = new_count - initial_count
        print(
            f"[green]Successfully updated CVE data. Added {added_count} new "
            f"vulnerabilities.[/green]"
        )

        new_cves = {cve["cve_id"] for cve in insert_data} - existing_cves

        if verbose and new_cves:
            print("\n[bold cyan]New CVEs:[/bold cyan]")
            for cve_id in sorted(list(new_cves)):
                print(cve_id)

        if save_to_collection and new_cves:
            name = (
                collection_name
                if collection_name
                else f"new_cves_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
            )
            _save_new_cves_to_collection(name, new_cves, cve_data)

    except httpx.HTTPStatusError as e:
        print(
            f"[bold red]Error downloading data: {e.response.status_code} - "
            f"{e.response.text}[/bold red]"
        )
        raise typer.Exit(code=1)
    except json.JSONDecodeError:
        print("[bold red]Error: Failed to parse downloaded JSON data.[/bold red]")
        raise typer.Exit(code=1)
    except Exception as e:
        print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        raise typer.Exit(code=1)


def _save_new_cves_to_collection(name: str, new_cves: set, cve_data: dict):
    """Saves a set of new CVEs to a JSON collection file."""
    collection_file = COLLECTIONS_DIR / f"{name}.json"
    if collection_file.exists():
        print(
            f"[bold red]Error:[/bold red] Collection '{name}' already exists. "
            f"Please choose a different name."
        )
        raise typer.Exit(code=1)

    vulnerabilities = [
        {"cve_id": cve_id, "vuln_id": cve_data[cve_id]["vulnID"]}
        for cve_id in sorted(list(new_cves))
    ]

    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    collection_data = {
        "name": name,
        "creation_date": now_iso,
        "last_updated": now_iso,
        "vulnerabilities": vulnerabilities,
    }

    COLLECTIONS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(collection_file, "w", encoding="utf-8") as f:
            json.dump(collection_data, f, indent=2)
        print(
            f"\n[bold green]✔ Collection '{name}' created with "
            f"{len(vulnerabilities)} new CVEs.[/bold green]"
        )
        print(f"Saved to {collection_file}")
    except IOError as e:
        print(f"[bold red]Error saving collection file: {e}[/red]")
        raise typer.Exit(code=1)
