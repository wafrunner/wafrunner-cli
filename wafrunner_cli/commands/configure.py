import typer
from rich import print

from wafrunner_cli.core.config_manager import ConfigManager


def configure():
    """
    Configure the CLI with your API token.
    """
    print("[bold cyan]wafrunner Configuration[/bold cyan]")
    api_token = typer.prompt("Enter your API Token", hide_input=True)

    config_manager = ConfigManager()
    try:
        config_manager.save_token(api_token)
        print(
            f"[green]✔ Configuration saved successfully to "
            f"{config_manager.config_file}[/green]"
        )
    except IOError as e:
        print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)
