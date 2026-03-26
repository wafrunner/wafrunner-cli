# Data Commands

The `data` command group provides tools for downloading and managing research artifacts from the wafrunner platform.

## Downloading Exploit Graphs

Use `get-graph` to download exploit graphs to local JSON files.

### Single Vulnerability

Download a graph for a single CVE or vulnerability ID:

```sh
wafrunner data get-graph -i CVE-2021-44228
wafrunner data get-graph -i a1ddadd4-1b9d-4fab-90fe-64c1c763cd58
```

This saves the graph to `./exploit-graphs/CVE-2021-44228.json` by default.

### Collection

Download graphs for all vulnerabilities in a collection:

```sh
wafrunner data get-graph -c my-collection
```

### Options

| Option | Short | Description |
|---|---|---|
| `--collection` | `-c` | Collection name to process |
| `--id` | `-i` | Single CVE ID or vulnerability UUID |
| `--output-dir` | `-o` | Output directory (default: `./exploit-graphs`) |
| `--force` | `-f` | Overwrite existing local files |
| `--uuid` | | Save files using vulnerability UUID instead of CVE ID |
| `--max-workers` | `-t` | Number of worker threads (default: 4, auto-adjusted) |
| `--verbose` | `-V` | Show verbose output |

### Skipping Existing Files

By default, `get-graph` skips any vulnerability whose graph file already exists locally. Use `--force` to re-download and overwrite:

```sh
wafrunner data get-graph -c my-collection --force
```

### UUID Filenames

By default, files are named by CVE ID (e.g. `CVE-2021-44228.json`). Use `--uuid` to name them by vulnerability UUID instead:

```sh
wafrunner data get-graph -c my-collection --uuid
```

### Custom Output Directory

```sh
wafrunner data get-graph -c my-collection -o ./my-graphs
```

### Summary Output

After processing, a summary is displayed:

```
--- Download Summary ---
Processed 10/10 vulnerabilities.
Downloaded:          6
Skipped (exists):    2
No graph available:  1
Failed:              1
Total time: 4.32 seconds (2.31 items/sec)
```

## Downloading Security Controls

```sh
wafrunner data get-controls --vulnid <vuln-id>
wafrunner data get-controls --cve-id <cve-id>
```

*This command is a placeholder and will be implemented in a future release.*
