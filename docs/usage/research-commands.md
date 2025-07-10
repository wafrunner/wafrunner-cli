
# Research Commands

The `research` command group helps you initiate research tasks against vulnerability identifiers.

## GitHub Repository Search

You can trigger a search for public GitHub repositories related to a specific vulnerability.

### By Single Identifier

To search for a single vulnerability, provide either a CVE ID or a vulnerability ID using the `--id` option:

```sh
wafrunner research github --id CVE-2021-44228
```

```sh
wafrunner research github --id a1ddadd4-1b9d-4fab-90fe-64c1c763cd58
```

### From a Collection

If you have a collection of vulnerability identifiers, you can process them in bulk:

```sh
wafrunner research github --collection my-collection
```

The tool requires that you provide either `--id` or `--collection`, but not both.

## Scrape Data Sources

You can also trigger a scrape of all data sources associated with a vulnerability:

```sh
wafrunner research scrape --id CVE-2021-44228
```

This command will fetch all related links and initiate a data scrape for each one.
