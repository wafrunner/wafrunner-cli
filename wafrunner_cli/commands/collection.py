import typer
from rich import print
from rich.table import Table
from typing import Any, List, Optional
from pathlib import Path
import json
import glob
from datetime import datetime, timezone

from wafrunner_cli.core.lookup_service import lookup_ids

# --- Constants and Configuration ---
DEFAULT_DATA_DIR = Path.home() / ".wafrunner"
COLLECTIONS_DIR = DEFAULT_DATA_DIR / "data" / "collections"

app = typer.Typer(help="Commands for managing local collections of vulnerabilities.")


# --- Helper Functions ---
def validate_collection_data(data: Any, file_path: Path) -> (bool, Optional[str]):
    """
    Validates the basic schema of a collection data object.
    Returns (is_valid, error_message).
    """
    if not isinstance(data, dict):
        return False, "Root object is not a dictionary."

    if "name" not in data or not isinstance(data["name"], str):
        return False, "Missing or invalid 'name' field (must be a string)."

    if "vulnerabilities" not in data or not isinstance(data["vulnerabilities"], list):
        return False, "Missing or invalid 'vulnerabilities' field (must be a list)."

    for i, vuln in enumerate(data["vulnerabilities"]):
        if not isinstance(vuln, dict):
            return False, f"Item at index {i} in 'vulnerabilities' is not a dictionary."
        if "cve_id" not in vuln or "vuln_id" not in vuln:
            return (
                False,
                (
                    f"Item at index {i} in 'vulnerabilities' is missing 'cve_id' or "
                    f"'vuln_id'."
                ),
            )

    return True, None


# --- CLI Commands ---


@app.command(name="list")
def list_collections():
    """
    Lists all available local collections.
    """
    COLLECTIONS_DIR.mkdir(parents=True, exist_ok=True)
    collection_files = glob.glob(str(COLLECTIONS_DIR / "*.json"))

    if not collection_files:
        print("[yellow]No collections found.[/yellow]")
        raise typer.Exit()

    table = Table(title="Available Collections")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Items", justify="right", style="magenta")
    table.add_column("File Path", style="blue")
    table.add_column("Status", style="green")

    for file_path_str in sorted(collection_files):
        file_path = Path(file_path_str)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            is_valid, error_msg = validate_collection_data(data, file_path)

            if is_valid:
                table.add_row(
                    data.get("name", file_path.stem),
                    str(len(data.get("vulnerabilities", []))),
                    str(file_path),
                    "[green]OK[/green]",
                )
            else:
                table.add_row(
                    file_path.stem,
                    "-",
                    str(file_path),
                    f"[bold red]Invalid: {error_msg}[/bold red]",
                )
        except (json.JSONDecodeError, IOError):
            table.add_row(
                file_path.stem, "-", str(file_path), "[bold red]Read Error[/bold red]"
            )

    print(table)


@app.command()
def show(name: str = typer.Argument(..., help="The name of the collection to show.")):
    """Shows the contents of a specific collection."""
    collection_file = COLLECTIONS_DIR / f"{name}.json"
    if not collection_file.exists():
        print(f"[bold red]Error:[/bold red] Collection '{name}' not found.")
        raise typer.Exit(code=1)

    try:
        with open(collection_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        is_valid, error_msg = validate_collection_data(data, collection_file)
        if not is_valid:
            print(f"[bold red]Error:[/bold red] Collection '{name}' is invalid.")
            print(f"Reason: {error_msg}")
            raise typer.Exit(code=1)

        print(f"[bold cyan]Collection Details for '{data.get('name')}'[/bold cyan]")
        print(f"  [yellow]Last Updated:[/yellow] {data.get('last_updated', 'N/A')}")
        print("-" * 30)

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print("[yellow]Collection is empty.[/yellow]")
            raise typer.Exit()

        table = Table(title="Vulnerabilities")
        table.add_column("CVE ID", style="cyan")
        table.add_column("VulnID", style="magenta")
        for vuln in vulns:
            table.add_row(vuln.get("cve_id", "N/A"), vuln.get("vuln_id", "N/A"))
        print(table)

    except (json.JSONDecodeError, IOError) as e:
        print(
            f"[bold red]Error reading collection file {collection_file.name}: {e}[/red]"
        )
        raise typer.Exit(code=1)


@app.command()
def delete(
    name: str = typer.Argument(..., help="The name of the collection to delete."),
    force: bool = typer.Option(
        False, "--force", "-f", help="Bypass confirmation prompt."
    ),
):
    """Deletes a local collection."""
    collection_file = COLLECTIONS_DIR / f"{name}.json"
    if not collection_file.exists():
        print(f"[bold red]Error:[/bold red] Collection '{name}' not found.")
        raise typer.Exit(code=1)

    if not force:
        typer.confirm(
            f"Are you sure you want to delete the collection '{name}'?", abort=True
        )

    try:
        collection_file.unlink()
        print(f"[green]✔ Collection '{name}' deleted successfully.[/green]")
    except IOError as e:
        print(
            f"[bold red]Error deleting collection file "
            f"{collection_file.name}: {e}[/red]"
        )
        raise typer.Exit(code=1)


@app.command(name="create")
def create_collection(
    name: str = typer.Argument(..., help="The name of the new collection."),
    identifier: Optional[List[str]] = typer.Option(
        None,
        "--id",
        "-i",
        help="A CVE ID or VulnID to add. Can be used multiple times.",
    ),
    file: Optional[Path] = typer.Option(
        None,
        "--file",
        help="A file containing a list of CVE IDs or VulnIDs, one per line.",
    ),
):
    """Creates a new collection from a list of identifiers."""
    if not any([identifier, file]):
        print(
            "[bold red]Error:[/bold red] You must provide at least one source: "
            "--id or --file."
        )
        raise typer.Exit(code=1)

    collection_file = COLLECTIONS_DIR / f"{name}.json"
    if collection_file.exists():
        print(
            f"[bold red]Error:[/bold red] Collection '{name}' already exists. "
            f"Use 'collection delete' to remove it first."
        )
        raise typer.Exit(code=1)

    input_ids = set()
    if file:
        if not file.exists():
            print(f"[bold red]Error:[/bold red] Input file not found at {file}")
            raise typer.Exit(code=1)
        input_ids.update(
            line.strip() for line in file.read_text().splitlines() if line.strip()
        )

    if identifier:
        input_ids.update(identifier)

    vulnerabilities = []
    print(f"Processing {len(input_ids)} unique identifiers...")
    for item_id in sorted(list(input_ids)):
        resolved_ids = lookup_ids(item_id)
        if resolved_ids:
            vulnerabilities.append(resolved_ids)
        else:
            print(
                f"[bold yellow]Warning:[/bold yellow] Could not resolve identifier: "
                f"{item_id}"
            )

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
            f"\n[bold green]✔ Collection '{name}' created successfully with "
            f"{len(vulnerabilities)} items.[/bold green]"
        )
        print(f"Saved to {collection_file}")
    except IOError as e:
        print(f"[bold red]Error saving collection file: {e}[/red]")
        raise typer.Exit(code=1)
