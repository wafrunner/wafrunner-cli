import typer
from rich import print

from wafrunner_cli.commands import cve, data, research, configure as configure_module

app = typer.Typer(
    name="wafrunner",
    help="A CLI for interacting with the wafrunner vulnerability research system.",
    add_completion=False,
)

app.add_typer(cve.app, name="cve")
app.add_typer(data.app, name="data")
app.add_typer(research.app, name="research")

# Register the top-level configure command
app.command()(configure_module.configure)