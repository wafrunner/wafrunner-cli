
from pathlib import Path
import json
import glob
import os
from rich import print

from wafrunner_cli.core.config_manager import ConfigManager

_cache = {
    "lookup_data": None,
    "file_path": None
}

def get_lookup_dir() -> Path:
    """Returns the directory where lookup files are stored."""
    config_manager = ConfigManager()
    lookup_dir = config_manager.get_data_dir() / "cve-lookup"
    lookup_dir.mkdir(parents=True, exist_ok=True)
    return lookup_dir

def get_vuln_id(cve_id: str) -> str | None:
    """Gets the vulnID for a given CVE ID."""
    lookup_dir = get_lookup_dir()
    files = sorted(glob.glob(str(lookup_dir / "*.json")), key=os.path.getmtime, reverse=True)

    if not files:
        print("[bold red]Error: No CVE lookup file found. Please run 'wafrunner update'.[/bold red]")
        return None

    latest_file = Path(files[0])

    if _cache["file_path"] != latest_file:
        try:
            with open(latest_file, "r", encoding="utf-8") as f:
                _cache["lookup_data"] = json.load(f)
                _cache["file_path"] = latest_file
        except (json.JSONDecodeError, IOError) as e:
            print(f"[bold red]Error reading lookup file: {e}[/bold red]")
            return None

    return _cache["lookup_data"].get(cve_id)
