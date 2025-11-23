import typer

# Import the Typer apps from your command modules
from .commands import collection, research, data, configure, shell, update, test

# Create the main Typer app
app = typer.Typer(
    name="wafrunner",
    help="A CLI for interacting with the wafrunner platform.",
    add_completion=False,
    no_args_is_help=True,
)

# Add the command groups (sub-typers) to the main app
app.add_typer(
    collection.app,
    name="collection",
    help="Commands for managing local collections of vulnerabilities.",
)
app.add_typer(
    research.app,
    name="research",
    help="Commands for initiating research and analysis tasks.",
)
app.add_typer(
    data.app,
    name="data",
    help="Commands for downloading and managing research artifacts.",
)
app.add_typer(
    test.app,
    name="test",
    help="Commands for executing and managing Forge test runs.",
)
app.command(
    "update",
    help="Downloads the latest CVE ID to vulnID lookup file or reverts to the previous version.",
)(update.update)

# Add standalone commands to the main app
app.command("configure")(configure.configure)
app.command("shell", help="Enter an interactive shell with tab completion.")(
    shell.run_shell
)


def main():
    """Main entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
