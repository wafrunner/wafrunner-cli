# Data Commands

The `data` command group downloads research artifacts from the wafrunner platform to your local machine. This is useful when you want to inspect, diff, or process exploit graphs and security controls locally rather than viewing them through `research show`.

## `get-graph` — Download Exploit Graphs

Downloads the exploit graph for one or more vulnerabilities and saves each as a JSON file on disk.

### How it works

1. Resolves each identifier (CVE ID or UUID) to a vulnerability record
2. For each vulnerability, calls `GET /vulnerability_records/{vulnID}/exploit-graph`
3. If the API returns a graph with at least one exploit vector, saves it as a JSON file
4. If the graph doesn't exist yet (404) or is empty, reports it as "no graph available" and moves on
5. If the file already exists locally, skips it (unless `--force` is set)

For collections, requests run concurrently using a thread pool. The worker count auto-scales based on collection size (2-8 threads) but can be overridden with `-t`.

### Usage

Download a single graph:

```sh
wafrunner data get-graph -i CVE-2021-44228
```

Download graphs for an entire collection:

```sh
wafrunner data get-graph -c my-collection
```

Re-download graphs that already exist locally:

```sh
wafrunner data get-graph -c my-collection --force
```

### Output files

By default, graphs are saved to `./exploit-graphs/` with the CVE ID as the filename:

```
./exploit-graphs/
  CVE-2021-44228.json
  CVE-2024-1234.json
  CVE-2023-5678.json
```

Each file contains the full API response including the `exploitGraphInstanceID`, timestamps, and the `exploitGraph` array of exploit vectors.

Use `--uuid` to name files by the vulnerability UUID instead (e.g. `a1ddadd4-1b9d-4fab-90fe-64c1c763cd58.json`). Use `-o` to change the output directory.

### Options

| Option | Short | Description |
|---|---|---|
| `--collection` | `-c` | Name of a collection to process |
| `--id` | `-i` | A single CVE ID or vulnerability UUID |
| `--output-dir` | `-o` | Where to save files (default: `./exploit-graphs`) |
| `--force` | `-f` | Overwrite files that already exist locally |
| `--uuid` | | Use vulnerability UUID as filename instead of CVE ID |
| `--max-workers` | `-t` | Thread count (default: 4, auto-adjusted by collection size) |
| `--verbose` | `-V` | Show per-vulnerability progress and errors |

You must provide either `--collection` or `--id`, but not both.

### Summary output

After processing, you'll see a breakdown:

```
--- Download Summary ---
Processed 10/10 vulnerabilities.
Downloaded:          6    # New graphs fetched and saved
Skipped (exists):    2    # Local file already present, use --force to re-download
No graph available:  1    # API returned 404 or empty graph — run init-graph first
Failed:              1    # API error or network failure
Total time: 4.32 seconds (2.31 items/sec)
```

If any downloads failed, the specific errors are listed below the summary.

### Typical workflow

```sh
# 1. Create a collection
wafrunner collection create log4j-vulns --id CVE-2021-44228 --id CVE-2021-45046

# 2. Initialize exploit graphs for anything that doesn't have one yet
wafrunner research init-graph -c log4j-vulns

# 3. Download the graphs locally
wafrunner data get-graph -c log4j-vulns

# 4. Inspect a graph
cat ./exploit-graphs/CVE-2021-44228.json | jq '.exploitGraph | length'
```

---

## `get-controls` — Download Security Controls

```sh
wafrunner data get-controls --vulnid <vuln-id>
wafrunner data get-controls --cve-id <cve-id>
```

*This command is a placeholder and will be implemented in a future release.*
