import typer
from rich import print
from typing import Optional
from pathlib import Path
import httpx
import json

from wafrunner_cli.core.api_client import ApiClient
from wafrunner_cli.core.exceptions import AuthenticationError

app = typer.Typer(help="Commands for downloading and managing research artifacts.")


@app.command("get-graph")
def get_graph(
    vulnid: Optional[str] = typer.Option(None, "--vulnid", help="A specific vulnerability ID."),
    cve_id: Optional[str] = typer.Option(None, "--cve-id", help="A specific CVE ID."),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="The directory to save the downloaded graph.",
        file_okay=False,
        dir_okay=True,
        writable=True,
        resolve_path=True,
    ),
):
    """
    Download a vulnerability graph.
    """
    if (vulnid is None) == (cve_id is None):
        print("[bold red]Error:[/bold red] Please provide exactly one of --vulnid or --cve-id.")
        raise typer.Exit(code=1)

    try:
        api_client = ApiClient()
        params = {}
        identifier = ""

        if vulnid:
            params["vulnid"] = vulnid
            identifier = vulnid
        else:
            params["cve_id"] = cve_id
            identifier = cve_id

        print(f"Fetching graph for identifier: [bold cyan]{identifier}[/bold cyan]...")
        # Placeholder endpoint, update to match your actual API
        graph_data = api_client.get("/data/graph", params=params)

        if output_dir:
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
                file_path = output_dir / f"{identifier}_graph.json"
                with open(file_path, "w") as f:
                    json.dump(graph_data, f, indent=2)
                print(f"[green]✔ Graph saved successfully to {file_path}[/green]")
            except IOError as e:
                print(f"[bold red]File Error:[/bold red] Could not write to file. {e}")
                raise typer.Exit(code=1)
        else:
            print("[bold green]Downloaded Graph Data:[/bold green]")
            print(graph_data)

    except AuthenticationError as e:
        print(f"[bold red]API Error:[/bold red] {e}")
        if "403" in str(e):
            print(
                "[bold yellow]Hint:[/bold yellow] A '403 Forbidden' error means the server understands your request but refuses to authorize it. "
                "Please check if your API token has the required permissions (scopes) to access this endpoint."
            )
        raise typer.Exit(code=1)
    except httpx.RequestError:
        # ApiClient prints detailed network errors, so we just exit.
        raise typer.Exit(code=1)


@app.command("get-controls")
def get_controls(
    vulnid: Optional[str] = typer.Option(None, "--vulnid", help="A specific vulnerability ID."),
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
    if (vulnid is None) == (cve_id is None):
        print("[bold red]Error:[/bold red] Please provide exactly one of --vulnid or --cve-id.")
        raise typer.Exit(code=1)

    print(f"Placeholder for 'data get-controls' with vulnid: {vulnid}, cve_id: {cve_id}")