import pytest
from typer.testing import CliRunner
from pathlib import Path
import json
from unittest.mock import MagicMock

# The application object from the script being tested.
from wafrunner_cli.commands import collection as collection_app

# Use a fixed runner instance for all tests.
runner = CliRunner()

# --- Fixtures ---

@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    """Creates a temporary data directory structure for tests."""
    dir_path = tmp_path / ".wafrunner" / "data"
    dir_path.mkdir(parents=True)
    (dir_path / "collections").mkdir()
    (dir_path / "cve-sources").mkdir()
    return dir_path

@pytest.fixture(autouse=True)
def mock_default_dirs(mocker, data_dir):
    """Automatically mocks the default directory constants for all tests."""
    mocker.patch("wafrunner_cli.commands.collection.COLLECTIONS_DIR", data_dir / "collections")
    mocker.patch("wafrunner_cli.commands.collection.CVE_SOURCES_DIR", data_dir / "cve-sources")
    mocker.patch("wafrunner_cli.commands.collection.TRACKING_FILE_PATH", data_dir / "uploaded_cves.json")

# --- Helper Functions ---

def create_mock_tracking_file(data_dir: Path, cve_map: dict):
    """Helper to create the uploaded_cves.json tracking file."""
    tracking_file = data_dir / "uploaded_cves.json"
    tracking_file.write_text(json.dumps(cve_map))

def create_mock_cve_source_file(data_dir: Path, file_name: str, vulns: list):
    """Helper to create a mock NIST CVE source file."""
    source_file = data_dir / "cve-sources" / file_name
    content = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": v["id"],
                    "descriptions": [{"lang": "en", "value": v["desc"]}]
                }
            } for v in vulns
        ]
    }
    source_file.write_text(json.dumps(content))

def create_mock_collection_file(data_dir: Path, name: str, data: dict):
    """Helper to create a collection file."""
    collection_file = data_dir / "collections" / f"{name}.json"
    collection_file.write_text(json.dumps(data))

# --- Test Cases for `collection create` ---

def test_collection_create_from_cve_ids(data_dir):
    """Tests creating a collection by providing --cve-id options."""
    create_mock_tracking_file(data_dir, {
        "CVE-2024-0001": {"vulnID": "VULN-1111"},
        "CVE-2024-0002": {"vulnID": "VULN-2222"}
    })
    
    result = runner.invoke(collection_app.app, ["create", "my-cves", "--cve-id", "CVE-2024-0001", "--cve-id", "CVE-2024-0003"])

    assert result.exit_code == 0
    assert "Collection 'my-cves' created successfully with 2 items" in result.stdout
    
    collection_file = data_dir / "collections" / "my-cves.json"
    assert collection_file.exists()
    data = json.loads(collection_file.read_text())
    assert len(data["vulnerabilities"]) == 2
    assert {"cve_id": "CVE-2024-0001", "vuln_id": "VULN-1111"} in data["vulnerabilities"]
    assert {"cve_id": "CVE-2024-0003", "vuln_id": "Not Found"} in data["vulnerabilities"]

def test_collection_create_from_file(data_dir):
    """Tests creating a collection from an input file."""
    id_file = data_dir / "id-list.txt"
    id_file.write_text("VULN-1111\nCVE-2024-0002\nCVE-2024-0002") # Includes a duplicate
    create_mock_tracking_file(data_dir, {
        "CVE-2024-0001": {"vulnID": "VULN-1111"},
        "CVE-2024-0002": {"vulnID": "VULN-2222"}
    })

    result = runner.invoke(collection_app.app, ["create", "from-file", "--file", str(id_file)])

    assert result.exit_code == 0
    assert "Processing 2 unique identifiers..." in result.stdout
    
    data = json.loads((data_dir / "collections" / "from-file.json").read_text())
    assert len(data["vulnerabilities"]) == 2
    assert {"cve_id": "CVE-2024-0001", "vuln_id": "VULN-1111"} in data["vulnerabilities"]
    assert {"cve_id": "CVE-2024-0002", "vuln_id": "VULN-2222"} in data["vulnerabilities"]

def test_collection_create_fails_if_exists(data_dir):
    """Tests that `create` fails if the collection file already exists."""
    create_mock_collection_file(data_dir, "existing-coll", {"name": "existing-coll"})
    result = runner.invoke(collection_app.app, ["create", "existing-coll", "--cve-id", "CVE-2024-0001"])
    assert result.exit_code == 1
    assert "Error: Collection 'existing-coll' already exists." in result.stdout

# --- Test Cases for `collection search` ---

def test_collection_search_creates_new_collection(data_dir):
    """Tests a basic search that finds matches and creates a new collection."""
    create_mock_cve_source_file(data_dir, "source1.json", [
        {"id": "CVE-2024-1111", "desc": "A vulnerability in Apache Tomcat."},
        {"id": "CVE-2024-2222", "desc": "A different issue entirely."},
        {"id": "CVE-2024-3333", "desc": "Another Apache bug."}
    ])
    create_mock_tracking_file(data_dir, {
        "CVE-2024-1111": {"vulnID": "VULN-APACHE-1"},
        "CVE-2024-3333": {"vulnID": "VULN-APACHE-2"}
    })

    result = runner.invoke(collection_app.app, ["search", "apache-bugs", "-k", "Apache"])

    assert result.exit_code == 0
    assert "Found 2 new matching vulnerabilities" in result.stdout
    data = json.loads((data_dir / "collections" / "apache-bugs.json").read_text())
    assert len(data["vulnerabilities"]) == 2
    assert data["keywords"] == ["Apache"]
    assert {"cve_id": "CVE-2024-1111", "vuln_id": "VULN-APACHE-1", "matched_keyword": "Apache"} in data["vulnerabilities"]

def test_collection_search_appends_to_existing(data_dir):
    """Tests that the --append flag adds new finds to an existing collection."""
    # Existing collection with one item
    create_mock_collection_file(data_dir, "web-server-bugs", {
        "name": "web-server-bugs",
        "keywords": ["nginx"],
        "vulnerabilities": [{"cve_id": "CVE-2024-0001", "vuln_id": "VULN-NGINX", "matched_keyword": "nginx"}]
    })
    # New source data with an apache bug
    create_mock_cve_source_file(data_dir, "source2.json", [{"id": "CVE-2024-0002", "desc": "An issue in Apache."}])
    create_mock_tracking_file(data_dir, {"CVE-2024-0002": {"vulnID": "VULN-APACHE"}})
    
    result = runner.invoke(collection_app.app, ["search", "web-server-bugs", "-k", "Apache", "--append"])

    assert result.exit_code == 0
    assert "Found 1 new matching vulnerabilities" in result.stdout
    data = json.loads((data_dir / "collections" / "web-server-bugs.json").read_text())
    # Should now have 2 items and both keywords
    assert len(data["vulnerabilities"]) == 2
    assert "nginx" in data["keywords"]
    assert "Apache" in data["keywords"]
    assert {"cve_id": "CVE-2024-0002", "vuln_id": "VULN-APACHE", "matched_keyword": "Apache"} in data["vulnerabilities"]


# --- Test Cases for `list`, `show`, `delete` ---

def test_collection_list(data_dir):
    """Tests the list command output."""
    create_mock_collection_file(data_dir, "coll-1", {"name": "coll-1", "vulnerabilities": [1,2,3], "keywords": ["kw1"], "last_updated": "date1"})
    create_mock_collection_file(data_dir, "coll-2", {"name": "coll-2", "vulnerabilities": [1], "keywords": ["kw2"], "last_updated": "date2"})
    
    result = runner.invoke(collection_app.app, ["list"])

    assert result.exit_code == 0
    assert "coll-1" in result.stdout
    assert "coll-2" in result.stdout
    assert "3" in result.stdout # item count
    assert "kw1" in result.stdout

def test_collection_show(data_dir):
    """Tests the show command output."""
    create_mock_collection_file(data_dir, "show-me", {
        "name": "show-me",
        "keywords": ["test"],
        "last_updated": "test_date",
        "vulnerabilities": [
            {"cve_id": "CVE-2024-SHOW", "vuln_id": "VULN-SHOW"}
        ]
    })

    result = runner.invoke(collection_app.app, ["show", "show-me"])

    assert result.exit_code == 0
    assert "Collection Details for 'show-me'" in result.stdout
    assert "CVE-2024-SHOW" in result.stdout
    assert "VULN-SHOW" in result.stdout

def test_collection_delete(data_dir):
    """Tests the delete command."""
    collection_file = data_dir / "collections" / "to-delete.json"
    collection_file.touch()
    assert collection_file.exists()

    result = runner.invoke(collection_app.app, ["delete", "to-delete", "--force"])
    
    assert result.exit_code == 0
    assert "Collection 'to-delete' deleted successfully" in result.stdout
    assert not collection_file.exists()

def test_collection_delete_not_found(data_dir):
    """Tests that delete fails if the collection does not exist."""
    result = runner.invoke(collection_app.app, ["delete", "non-existent", "--force"])
    assert result.exit_code == 1
    assert "Error: Collection 'non-existent' not found." in result.stdout
