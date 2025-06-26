import typer
from rich import print
from typing import Optional
from pathlib import Path
from functools import wraps
import httpx

from wafrunner_cli.core.api_client import ApiClient
from wafrunner_cli.core.exceptions import AuthenticationError

app = typer.Typer(help="Commands for initiating research and analysis tasks.")


def require_one_identifier(func):
    """Decorator to ensure exactly one of --vulnid or --vulnid-file is provided."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        if (kwargs.get("vulnid") is None) == (kwargs.get("vulnid_file") is None):
            print("[bold red]Error:[/bold red] Please provide exactly one of --vulnid or --vulnid-file.")
            raise typer.Exit(code=1)
        return func(*args, **kwargs)

    return wrapper

# Define common options to reduce repetition and ensure consistency
VulnIdOption = typer.Option(None, "--vulnid", help="A specific vulnerability ID.")
VulnIdFileOption = typer.Option(
    None,
    "--vulnid-file",
    help="A file containing one or more vulnerability IDs.",
    exists=True,
    file_okay=True,
    dir_okay=False,
    readable=True,
    resolve_path=True,
)


@app.command()
@require_one_identifier
def github(
    vulnid: Optional[str] = VulnIdOption,
    vulnid_file: Optional[Path] = VulnIdFileOption,
):
    """
    Search Github for a vulnerability.
    """
    try:
        api_client = ApiClient()
        identifiers = []
        if vulnid_file:
            try:
                with open(vulnid_file, "r") as f:
                    identifiers = [line.strip() for line in f if line.strip()]
                if not identifiers:
                    print(f"[bold yellow]Warning:[/bold yellow] The file {vulnid_file} is empty.")
                    raise typer.Exit()
            except IOError as e:
                print(f"[bold red]File Error:[/bold red] Could not read file {vulnid_file}. {e}")
                raise typer.Exit(code=1)
        else:
            # The decorator ensures vulnid is not None if vulnid_file is None
            identifiers = [vulnid]

        with typer.progressbar(identifiers, label="Triggering GitHub searches") as progress:
            for identifier in progress:
                # Placeholder endpoint, update to match your actual API
                api_client.post("/research/github", json={"vulnid": identifier})

        print(f"\n[bold green]✔ Successfully triggered GitHub search for {len(identifiers)} identifier(s).[/bold green]")

    except (AuthenticationError, httpx.RequestError) as e:
        # ApiClient prints detailed error messages for these exceptions.
        raise typer.Exit(code=1)


@app.command()
@require_one_identifier
def scrape(
    vulnid: Optional[str] = VulnIdOption,
    vulnid_file: Optional[Path] = VulnIdFileOption,
):
    """
    Trigger a scrape for a vulnerability.
    """
    print(f"Placeholder for 'research scrape' with vulnid: {vulnid}, file: {vulnid_file}")


@app.command()
@require_one_identifier
def classify(
    vulnid: Optional[str] = VulnIdOption,
    vulnid_file: Optional[Path] = VulnIdFileOption,
):
    """
    Trigger classification for a vulnerability.
    """
    print(f"Placeholder for 'research classify' with vulnid: {vulnid}, file: {vulnid_file}")


@app.command("init-graph")
@require_one_identifier
def init_graph(
    vulnid: Optional[str] = VulnIdOption,
    vulnid_file: Optional[Path] = VulnIdFileOption,
):
    """
    Initialize an exploit graph for a vulnerability.
    """
    print(f"Placeholder for 'research init-graph' with vulnid: {vulnid}, file: {vulnid_file}")


@app.command("refine-graph")
@require_one_identifier
def refine_graph(
    vulnid: Optional[str] = VulnIdOption,
    vulnid_file: Optional[Path] = VulnIdFileOption,
):
    """
    Refine an exploit graph for a vulnerability.
    """
    print(f"Placeholder for 'research refine-graph' with vulnid: {vulnid}, file: {vulnid_file}")


@app.command("gen-exploits")
@require_one_identifier
def gen_exploits(
    vulnid: Optional[str] = VulnIdOption,
    vulnid_file: Optional[Path] = VulnIdFileOption,
    output_file: Optional[Path] = typer.Option(
        None, "--output-file", help="File to save the generated exploits to."
    ),
):
    """
    Generate exploits for a vulnerability.
    """
    print(f"Placeholder for 'research gen-exploits' with vulnid: {vulnid}, file: {vulnid_file}")


@app.command("init-scd")
@require_one_identifier
def init_scd(
    vulnid: Optional[str] = VulnIdOption,
    vulnid_file: Optional[Path] = VulnIdFileOption,
):
    """
    Initialize a Security Control Definition (SCD).
    """
    print(f"Placeholder for 'research init-scd' with vulnid: {vulnid}, file: {vulnid_file}")


@app.command("refine-scd")
@require_one_identifier
def refine_scd(
    vulnid: Optional[str] = VulnIdOption,
    vulnid_file: Optional[Path] = VulnIdFileOption,
):
    """
    Refine a Security Control Definition (SCD).
    """
    print(f"Placeholder for 'research refine-scd' with vulnid: {vulnid}, file: {vulnid_file}")


@app.command("init-sc-declare")
@require_one_identifier
def init_sc_declare(
    vulnid: Optional[str] = VulnIdOption,
    vulnid_file: Optional[Path] = VulnIdFileOption,
):
    """
    Initialize a Security Control Declare.
    """
    print(f"Placeholder for 'research init-sc-declare' with vulnid: {vulnid}, file: {vulnid_file}")


@app.command("refine-sc-declare")
@require_one_identifier
def refine_sc_declare(
    vulnid: Optional[str] = VulnIdOption,
    vulnid_file: Optional[Path] = VulnIdFileOption,
):
    """
    Refine a Security Control Declare.
    """
    print(f"Placeholder for 'research refine-sc-declare' with vulnid: {vulnid}, file: {vulnid_file}")