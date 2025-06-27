import typer
from rich import print
from rich.table import Table
from typing import List, Optional
from pathlib import Path
import json
import glob
from datetime import datetime, timezone
import concurrent.futures

# Assumes local project structure contains these modules.
# In a real app, these would be managed by a central config manager.
from wafrunner_cli.core.api_client import ApiClient
from wafrunner_cli.core.exceptions import AuthenticationError

# --- Constants and Configuration ---
DEFAULT_DATA_DIR = Path.home() / ".wafrunner"
COLLECTIONS_DIR = DEFAULT_DATA_DIR / "data" / "collections"
CVE_SOURCES_DIR = DEFAULT_DATA_DIR / "data" / "cve-sources"
TRACKING_FILE_PATH = DEFAULT_DATA_DIR / "data" / "uploaded_cves.json"

app = typer.Typer(help="Commands for managing local collections of vulnerabilities.")

# --- Helper Functions ---

def load_tracking_file() -> dict:
    """Loads the main CVE tracking file which maps cveID to vulnID."""
    if not TRACKING_FILE_PATH.exists():
        return {}
    try:
        with open(TRACKING_FILE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}

def build_id_lookup_maps(tracking_data: dict) -> (dict, dict):
    """Builds lookup dictionaries for cveID -> vulnID and vulnID -> cveID."""
    cve_to_vuln = {}
    vuln_to_cve = {}
    for cve_id, data in tracking_data.items():
        vuln_id = data.get("vulnID")
        if vuln_id:
            cve_to_vuln[cve_id] = vuln_id
            vuln_to_cve[vuln_id] = cve_id
    return cve_to_vuln, vuln_to_cve


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
    table.add_column("Keywords", style="green")
    table.add_column("Last Updated", style="yellow")

    for file_path in sorted(collection_files):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            table.add_row(
                data.get("name", Path(file_path).stem),
                str(len(data.get("vulnerabilities", []))),
                ", ".join(data.get("keywords", ["N/A"])),
                data.get("last_updated", "N/A"),
            )
        except (json.JSONDecodeError, IOError) as e:
            print(f"[red]Error reading collection file {Path(file_path).name}: {e}[/red]")

    print(table)


@app.command()
def show(name: str = typer.Argument(..., help="The name of the collection to show.")):
    """Shows the contents of a specific collection."""
    collection_file = COLLECTIONS_DIR / f"{name}.json"
    if not collection_file.exists():
        print(f"[bold red]Error:[/bold red] Collection '{name}' not found.")
        raise typer.Exit(code=1)

    try:
        with open(collection_file, "r", encoding="utf-8") as f: data = json.load(f)

        print(f"[bold cyan]Collection Details for '{data.get('name')}'[/bold cyan]")
        print(f"  [green]Keywords:[/green] {', '.join(data.get('keywords', ['N/A']))}")
        print(f"  [yellow]Last Updated:[/yellow] {data.get('last_updated', 'N/A')}")
        print("-" * 30)

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print("[yellow]Collection is empty.[/yellow]")
            raise typer.Exit()

        table = Table(title="Vulnerabilities")
        table.add_column("CVE ID", style="cyan"); table.add_column("VulnID", style="magenta")
        for vuln in vulns:
            table.add_row(vuln.get("cve_id", "N/A"), vuln.get("vuln_id", "N/A"))
        print(table)

    except (json.JSONDecodeError, IOError) as e:
        print(f"[bold red]Error reading collection file {collection_file.name}: {e}[/red]")
        raise typer.Exit(code=1)


@app.command()
def delete(name: str = typer.Argument(..., help="The name of the collection to delete."), force: bool = typer.Option(False, "--force", "-f", help="Bypass confirmation prompt.")):
    """Deletes a local collection."""
    collection_file = COLLECTIONS_DIR / f"{name}.json"
    if not collection_file.exists():
        print(f"[bold red]Error:[/bold red] Collection '{name}' not found.")
        raise typer.Exit(code=1)

    if not force:
        typer.confirm(f"Are you sure you want to delete the collection '{name}'?", abort=True)
    
    try:
        collection_file.unlink()
        print(f"[green]✔ Collection '{name}' deleted successfully.[/green]")
    except IOError as e:
        print(f"[bold red]Error deleting collection file {collection_file.name}: {e}[/red]")
        raise typer.Exit(code=1)


@app.command(name="create")
def create_collection(
    name: str = typer.Argument(..., help="The name of the new collection."),
    cve_id: Optional[List[str]] = typer.Option(None, "--cve-id", help="A CVE ID to add. Can be used multiple times."),
    vuln_id: Optional[List[str]] = typer.Option(None, "--vuln-id", help="A VulnID to add. Can be used multiple times."),
    file: Optional[Path] = typer.Option(None, "--file", help="A file containing a list of CVE IDs or VulnIDs, one per line."),
):
    """Creates a new collection from a list of identifiers."""
    if not any([cve_id, vuln_id, file]):
        print("[bold red]Error:[/bold red] You must provide at least one source: --cve-id, --vuln-id, or --file.")
        raise typer.Exit(code=1)
        
    collection_file = COLLECTIONS_DIR / f"{name}.json"
    if collection_file.exists():
        print(f"[bold red]Error:[/bold red] Collection '{name}' already exists. Use 'collection search --append' to add to it or 'collection delete' to remove it.")
        raise typer.Exit(code=1)

    # Load lookup maps from tracking file
    cve_to_vuln, vuln_to_cve = build_id_lookup_maps(load_tracking_file())

    input_ids = set()
    if file:
        if not file.exists():
            print(f"[bold red]Error:[/bold red] Input file not found at {file}")
            raise typer.Exit(code=1)
        input_ids.update(line.strip() for line in file.read_text().splitlines() if line.strip())

    if cve_id: input_ids.update(cve_id)
    if vuln_id: input_ids.update(vuln_id)

    vulnerabilities = []
    print(f"Processing {len(input_ids)} unique identifiers...")
    for item_id in sorted(list(input_ids)):
        if item_id.upper().startswith("CVE-"):
            found_cve = item_id.upper()
            found_vuln = cve_to_vuln.get(found_cve, "Not Found")
        else: # Assume it's a vulnID
            found_vuln = item_id
            found_cve = vuln_to_cve.get(found_vuln, "Not Found")
        
        vulnerabilities.append({"cve_id": found_cve, "vuln_id": found_vuln})
    
    collection_data = {
        "name": name,
        "creation_date": datetime.now(timezone.utc).isoformat(),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "keywords": [], # No keywords for manually created collections
        "vulnerabilities": vulnerabilities
    }

    COLLECTIONS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(collection_file, "w", encoding="utf-8") as f:
            json.dump(collection_data, f, indent=2)
        print(f"\n[bold green]✔ Collection '{name}' created successfully with {len(vulnerabilities)} items.[/bold green]")
        print(f"Saved to {collection_file}")
    except IOError as e:
        print(f"[bold red]Error saving collection file: {e}[/red]")
        raise typer.Exit(code=1)


@app.command(name="search")
def search_collection(
    name: str = typer.Argument(..., help="The name of the collection to create or update."),
    keywords: List[str] = typer.Option(..., "-k", "--keyword", help="Keyword to search for (case-insensitive). Can be used multiple times."),
    append: bool = typer.Option(False, "--append", help="Append results to an existing collection instead of overwriting."),
):
    """Searches local CVE files for keywords and populates a collection."""
    print(f"Searching for keywords: {', '.join(keywords)}")
    COLLECTIONS_DIR.mkdir(parents=True, exist_ok=True)
    cve_files = glob.glob(str(CVE_SOURCES_DIR / "*.json"))
    if not cve_files:
        print(f"[bold red]Error:[/bold red] No CVE source files found in {CVE_SOURCES_DIR}.")
        print("Please run 'wafrunner cve download' first.")
        raise typer.Exit(code=1)

    cve_to_vuln, _ = build_id_lookup_maps(load_tracking_file())
        
    collection_file = COLLECTIONS_DIR / f"{name}.json"
    collection_data = {"vulnerabilities": [], "keywords": keywords}
    
    if append and collection_file.exists():
        print(f"Appending to existing collection '{name}'...")
        try:
            with open(collection_file, 'r', encoding='utf-8') as f: existing_data = json.load(f)
            collection_data['vulnerabilities'] = existing_data.get('vulnerabilities', [])
            collection_data['keywords'].extend(existing_data.get('keywords', []))
            collection_data['keywords'] = sorted(list(set(collection_data['keywords'])))
        except (json.JSONDecodeError, IOError):
            print(f"[red]Could not load existing collection file. A new one will be created.[/red]")
            
    existing_cves_in_collection = {v['cve_id'] for v in collection_data['vulnerabilities']}
    found_count = 0

    print("Searching local CVE source files...")
    for cve_file in cve_files:
        with open(cve_file, "r", encoding="utf-8") as f: data = json.load(f)
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cve", {}).get("id")
            if not cve_id or cve_id in existing_cves_in_collection: continue

            description = next((d.get("value", "").lower() for d in vuln.get("cve",{}).get("descriptions",[]) if d.get("lang")=="en"), "")
            
            for keyword in keywords:
                if keyword.lower() in description:
                    collection_data["vulnerabilities"].append({
                        "cve_id": cve_id,
                        "vuln_id": cve_to_vuln.get(cve_id, "Not Found"),
                        "matched_keyword": keyword
                    })
                    existing_cves_in_collection.add(cve_id)
                    found_count += 1
                    break 

    collection_data["name"] = name
    collection_data["last_updated"] = datetime.now(timezone.utc).isoformat()
    if 'creation_date' not in collection_data:
        collection_data['creation_date'] = datetime.now(timezone.utc).isoformat()

    try:
        with open(collection_file, "w", encoding="utf-8") as f:
            json.dump(collection_data, f, indent=2)
        print(f"\n[bold green]✔ Search complete.[/bold green]")
        print(f"Found {found_count} new matching vulnerabilities.")
        print(f"Collection '{name}' saved to {collection_file}")
    except IOError as e:
        print(f"[bold red]Error saving collection file: {e}[/red]")
        raise typer.Exit(code=1)
