# Configuring the CLI

The `configure` command sets up credentials and paths used by `wafrunner-cli`.

## Setting Your API Token

Run `configure` with no arguments to be prompted for your API token:

```sh
wafrunner configure
```

The token is stored locally and used to authenticate all API requests.

## Setting the Forge Path

If you have the Forge test framework installed locally, point the CLI to it:

```sh
wafrunner configure --forge-path /path/to/forge
```

This is required for `wafrunner test` commands.

## Setting the Log Directory

Research commands write detailed JSON logs after each run. By default these go to `~/.wafrunner/logs`, but you can change the location:

```sh
wafrunner configure --log-dir /path/to/logs
```

## Options

| Option | Description |
|---|---|
| *(no options)* | Prompts for API token |
| `--forge-path` | Path to the Forge repository |
| `--log-dir` | Directory for log files (default: `~/.wafrunner/logs`) |

You can set multiple options at once:

```sh
wafrunner configure --forge-path /opt/forge --log-dir /var/log/wafrunner
```

When options are provided, the API token prompt is skipped.
