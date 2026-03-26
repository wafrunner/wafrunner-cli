# wafrunner-cli

Command-line interface for the wafrunner vulnerability research platform.

## Quick Start

```sh
# Configure your API token
wafrunner configure

# Download CVE lookup data
wafrunner update

# Create a collection of vulnerabilities to work with
wafrunner collection create my-vulns --id CVE-2021-44228 --id CVE-2024-1234

# Run research tasks
wafrunner research github -c my-vulns
wafrunner research scrape -c my-vulns
wafrunner research classify -c my-vulns
wafrunner research init-graph -c my-vulns

# Download exploit graphs locally
wafrunner data get-graph -c my-vulns

# Check status
wafrunner research show -c my-vulns
```

## Documentation

- [Basic Usage](usage/basic-commands.md) — Getting started
- [Configure CLI](usage/configure-cli.md) — API token and path settings
- [Collection Commands](usage/collection-commands.md) — Managing vulnerability collections
- [Research Commands](usage/research-commands.md) — Running research tasks
- [Data Commands](usage/data-commands.md) — Downloading artifacts
- [Command Reference](reference.md) — All commands at a glance
