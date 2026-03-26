# Research Commands

The `research` command group triggers research and analysis tasks against vulnerabilities. All commands accept either `--collection/-c` (a collection name) or `--id/-i` (a single CVE ID or vulnerability UUID), but not both.

## Common Options

Most research commands share these options:

| Option | Short | Description |
|---|---|---|
| `--collection` | `-c` | Collection name to process |
| `--id` | `-i` | Single CVE ID or vulnerability UUID |
| `--max-workers` | `-t` | Thread count (default: 4, auto-adjusted by collection size) |
| `--verbose` | `-V` | Show detailed per-vulnerability output |
| `--log-dir` | | Custom directory for JSON log files |

## `github` — Search GitHub

Searches GitHub for public repositories related to each vulnerability. Skips vulnerabilities that already have a completed search unless `--force` is set.

```sh
wafrunner research github -i CVE-2021-44228
wafrunner research github -c my-collection
wafrunner research github -c my-collection --force
```

Additional option: `--force/-f` forces a new search even if one is already complete.

## `scrape` — Scrape Data Sources

Triggers a scrape of all data source links associated with each vulnerability.

```sh
wafrunner research scrape -i CVE-2021-44228
wafrunner research scrape -c my-collection
```

## `classify` — Run Classifier

Triggers the classifier on scraped data for each vulnerability. By default, skips vulnerabilities where classification is already complete.

```sh
wafrunner research classify -i CVE-2021-44228
wafrunner research classify -c my-collection
```

Additional options:

| Option | Short | Description |
|---|---|---|
| `--update` | `-u` | Re-run even if status is "complete" or "error" |
| `--retry` | `-r` | Re-run only if status is "error" |

`--update` and `--retry` are mutually exclusive.

## `init-graph` — Initialize Exploit Graphs

Creates exploit graphs for vulnerabilities that don't already have one. Checks for an existing graph first and skips if found.

```sh
wafrunner research init-graph -i CVE-2021-44228
wafrunner research init-graph -c my-collection
```

## `refine-graph` — Refine Exploit Graphs

Triggers refinement on existing exploit graphs to improve their quality.

```sh
wafrunner research refine-graph -i CVE-2021-44228
wafrunner research refine-graph -c my-collection
```

## `init-scdef` — Initialize Security Control Definitions

Creates security control definitions (SCDEFs) for vulnerabilities. Optionally specify which exploit graph to use.

```sh
wafrunner research init-scdef -i CVE-2021-44228
wafrunner research init-scdef -i CVE-2021-44228 --graph <graph-id>
wafrunner research init-scdef -c my-collection
```

Additional option: `--graph/-g` specifies a graph ID to use (defaults to API-selected graph).

## `update-source` — Update from NIST Source

Triggers an update of vulnerability data from the NIST API source.

```sh
wafrunner research update-source -i CVE-2024-1234
wafrunner research update-source -c my-collection
```

## `links` — View Data Source Links

Displays a table of data source links and their processing statuses (scraped, classified, analysed, test category) for each vulnerability.

```sh
wafrunner research links -i CVE-2021-44228
wafrunner research links -c my-collection
```

This command does not support `--max-workers` or `--verbose` — it processes sequentially and always shows output.

## `show` — View Research Status

Displays the current state of exploit graphs, security control definitions, and data source links for each vulnerability. Useful for checking what work has been done.

```sh
wafrunner research show -i CVE-2021-44228
wafrunner research show -c my-collection
```

Shows:
- Exploit graph ID, creation/update timestamps, and vector count
- SCDEF IDs, timestamps, and associated exploit vector IDs
- Data source link table with scrape/classify/analyse statuses

This command does not support `--max-workers` or `--verbose` — it processes sequentially and always shows output.

## Typical Workflow

```sh
# 1. Update local CVE database
wafrunner update

# 2. Create a collection
wafrunner collection create my-vulns --id CVE-2021-44228 --id CVE-2024-1234

# 3. Search for related GitHub repos
wafrunner research github -c my-vulns

# 4. Scrape all data sources
wafrunner research scrape -c my-vulns

# 5. Classify scraped content
wafrunner research classify -c my-vulns

# 6. Initialize exploit graphs
wafrunner research init-graph -c my-vulns

# 7. Refine graphs
wafrunner research refine-graph -c my-vulns

# 8. Initialize security control definitions
wafrunner research init-scdef -c my-vulns

# 9. Check progress
wafrunner research show -c my-vulns
```
