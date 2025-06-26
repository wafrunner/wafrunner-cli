import typer
from rich import print
from typing import Optional
from pathlib import Path
import json
from rich.table import Table
import httpx

from wafrunner_cli.core.api_client import ApiClient
from wafrunner_cli.core.exceptions import AuthenticationError

app = typer.Typer(help="Commands for managing CVE data.")


@app.command()
def download(
    year: int = typer.Option(
        ...,  # ... makes this a required option
        "--year",
        "-y",
        help="The year of the CVEs to download.",
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="The directory to save the downloaded CVE files. Defaults to printing to console.",
        file_okay=False,
        dir_okay=True,
        writable=True,
        resolve_path=True,
    ),
    replace: bool = typer.Option(
        False, "--replace", help="Replace existing files if they are found."
    ),
):
    """
    Download CVEs for a specific year from the API.
    """
    print(f"Initializing CVE download for the year [bold cyan]{year}[/bold cyan]...")
    try:
        api_client = ApiClient()

        # This is a placeholder endpoint. Update it to match your actual API.
        cve_data = api_client.get("/cves", params={"year": year})

        if output_dir:
            # In a real implementation, you would write the cve_data to one or more files.
            print(f"Simulating save to directory [green]{output_dir}[/green]. Replace flag is set to {replace}.")
        else:
            print("[bold green]Downloaded CVE Data (preview):[/bold green]")
            print(cve_data)

        print("\n[bold green]✔ Download command executed successfully.[/bold green]")

    except AuthenticationError as e:
        print(f"[bold red]Authentication Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except httpx.RequestError:
        # The ApiClient already prints a detailed error message. We just need to exit.
        raise typer.Exit(code=1)


@app.command()
def upload(
    input_dir: Path = typer.Option(
        ...,
        "--input-dir",
        "-i",
        help="The directory containing CVE files to upload.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
    replace: bool = typer.Option(
        False, "--replace", help="Replace existing CVEs on the server."
    ),
):
    """
    Upload CVEs to the research system.
    """
    print(f"Placeholder for 'wafrunner cve upload' from directory: {input_dir}")


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

        # Placeholder endpoint, update to match your actual API
        results = api_client.get("/cves/search", params={"keyword": keyword})

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

    except (AuthenticationError, httpx.RequestError, IOError) as e:
        # ApiClient and other blocks print detailed error messages. We just need to exit.
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