# Basic Usage

This guide covers the basic commands to get started with `wafrunner-cli`.

## Configuring the CLI

Before you can use the tool, you need to set your API token. Run configure with no arguments to be prompted securely:

```sh
wafrunner configure
```

See [Configuring the CLI](configure-cli.md) for more options.

## Updating CVE Lookup Data

The CLI maintains a local database mapping CVE IDs to vulnerability UUIDs. You should update this before working with new vulnerabilities:

```sh
wafrunner update
```

Use `--verbose` to see which CVEs were added, and `--save-to-collection` to automatically create a collection from any new CVEs:

```sh
wafrunner update --verbose --save-to-collection
```

## Creating a Collection

Collections are groups of vulnerabilities you want to work with together. Create one by specifying CVE IDs or vulnerability UUIDs:

```sh
wafrunner collection create my-vulns --id CVE-2021-44228 --id CVE-2024-1234
```

You can also create a collection from a file with one identifier per line:

```sh
wafrunner collection create my-vulns --file cve-list.txt
```

## Running Research

Once you have a collection (or a single identifier), you can run research tasks against it. A typical workflow:

```sh
# Search GitHub for related repositories
wafrunner research github -c my-vulns

# Scrape data sources
wafrunner research scrape -c my-vulns

# Classify scraped data
wafrunner research classify -c my-vulns

# Initialize exploit graphs
wafrunner research init-graph -c my-vulns

# Refine exploit graphs
wafrunner research refine-graph -c my-vulns
```

All research commands accept either `-c <collection>` or `-i <identifier>`.

## Downloading Artifacts

Download exploit graphs to inspect locally:

```sh
wafrunner data get-graph -c my-vulns
```

This saves each graph as a JSON file in `./exploit-graphs/`.

## Viewing Status

Check the current state of a vulnerability's research:

```sh
wafrunner research show -i CVE-2021-44228
```

View data source links and their statuses:

```sh
wafrunner research links -i CVE-2021-44228
```

## Getting Help

Every command and subcommand supports `--help`:

```sh
wafrunner --help
wafrunner research --help
wafrunner research init-graph --help
```

Running a command group without a subcommand also shows help.
