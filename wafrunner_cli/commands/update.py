
import typer
from rich import print
import httpx
import json

from wafrunner_cli.core.api_client import ApiClient
from wafrunner_cli.core.database import Database

app = typer.Typer(
    name="update",
    help="Downloads the latest CVE ID to vulnID lookup data.",
    no_args_is_help=True
)

@app.command()
def update():
    """
    Downloads the latest CVE ID to vulnID lookup data.
    """
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

        print(f"[cyan]Downloading CVE data...[/cyan]")
        response = httpx.get(download_url)
        response.raise_for_status()
        cve_data = response.json()

        print("[cyan]Updating the local database...[/cyan]")
        db = Database()
        
        # Get the number of existing vulnerabilities
        db.cursor.execute("SELECT COUNT(*) FROM cve_lookup")
        initial_count = db.cursor.fetchone()[0]

        db.clear_cve_lookup()
        
        # Transform data for insertion
        insert_data = [
            {"cve_id": cve, "vuln_id": info["vulnID"], "last_modified": info["lastModified"]}
            for cve, info in cve_data.items()
        ]
        
        db.insert_cve_data(insert_data)

        # Get the new total
        db.cursor.execute("SELECT COUNT(*) FROM cve_lookup")
        new_count = db.cursor.fetchone()[0]
        db.close()
        
        added_count = new_count - initial_count
        print(f"[green]Successfully updated the CVE lookup data. Added {added_count} new vulnerabilities.[/green]")

    except httpx.HTTPStatusError as e:
        print(f"[bold red]Error downloading data: {e.response.status_code} - {e.response.text}[/bold red]")
        raise typer.Exit(code=1)
    except json.JSONDecodeError:
        print("[bold red]Error: Failed to parse downloaded JSON data.[/bold red]")
        raise typer.Exit(code=1)
    except Exception as e:
        print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        raise typer.Exit(code=1)

