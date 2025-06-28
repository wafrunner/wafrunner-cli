# Basic Usage

This guide covers the basic commands to get started with `wafrunner-cli`.

## Configuring the CLI

Before you can use the tool, you need to set your API key. You can do this interactively:

```sh
wafrunner configure set-api-key
```

## Searching for Data

To perform a basic search, use the `data search` command:

```sh
wafrunner data search "log4j" --limit 5
```