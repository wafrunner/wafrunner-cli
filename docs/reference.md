# Command Reference

Quick reference for all `wafrunner` commands.

## Top-level Commands

| Command | Description |
|---|---|
| `wafrunner configure` | Set API token, forge path, and log directory |
| `wafrunner update` | Download latest CVE-to-vulnID lookup data |
| `wafrunner shell` | Enter interactive shell with tab completion |

## `collection` — Manage Vulnerability Collections

| Command | Description |
|---|---|
| `collection create <name>` | Create a new collection from `--id` flags or `--file` |
| `collection list` | List all local collections |
| `collection show <name>` | Display contents of a collection |
| `collection delete <name>` | Remove a collection |

## `research` — Run Research Tasks

All commands accept `--collection/-c` or `--id/-i`.

| Command | Description |
|---|---|
| `research github` | Search GitHub for related repositories |
| `research scrape` | Scrape data source links |
| `research classify` | Run classifier on scraped data |
| `research init-graph` | Initialize exploit graphs (skips existing) |
| `research refine-graph` | Refine existing exploit graphs |
| `research init-scdef` | Initialize security control definitions |
| `research update-source` | Update vulnerability data from NIST |
| `research links` | View data source links and statuses |
| `research show` | View exploit graph, SCDEF, and link status |

## `data` — Download Artifacts

| Command | Description |
|---|---|
| `data get-graph` | Download exploit graphs to local JSON files |
| `data get-schema` | Fetch the exploit graph JSON schema |
| `data get-controls` | Download security controls *(placeholder)* |

## `test` — Forge Test Execution

| Command | Description |
|---|---|
| `test run` | Execute a Forge test run |
| `test status` | Check status of a test run |
| `test list` | List test runs |
| `test stop` | Stop a running test |
| `test logs` | View test run logs |

## `update` — CVE Data

```sh
wafrunner update                    # Download latest CVE lookup data
wafrunner update -v                 # Show new CVEs
wafrunner update -s                 # Save new CVEs to a collection
wafrunner update -s -n my-new-cves  # Save with a custom collection name
```
