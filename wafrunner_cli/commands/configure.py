import typer
from rich import print
from pathlib import Path

from wafrunner_cli.core.config_manager import ConfigManager


def configure(
    forge_path: str = typer.Option(
        None, "--forge-path", help="Path to forge repository"
    ),
    log_dir: str = typer.Option(
        None, "--log-dir", help="Directory for log files (default: ~/.wafrunner/logs)"
    ),
):
    """
    Configure the CLI with your API token and optional paths.
    """
    print("[bold cyan]wafrunner Configuration[/bold cyan]")

    config_manager = ConfigManager()

    # Configure forge path if provided
    if forge_path:
        try:
            path = Path(forge_path)
            if not path.exists():
                print(f"[yellow]Warning: Path does not exist: {path}[/yellow]")
                confirm = typer.confirm("Continue anyway?")
                if not confirm:
                    raise typer.Exit(code=1)
            config_manager.set_forge_path(str(path.resolve()))
            print(f"[green]✔ Forge path set to: {path.resolve()}[/green]")
        except Exception as e:
            print(f"[bold red]Error setting forge path:[/bold red] {e}")
            raise typer.Exit(code=1)

    # Configure log directory if provided
    if log_dir:
        try:
            path = Path(log_dir)
            path.mkdir(parents=True, exist_ok=True)
            config_manager.set_log_dir(str(path.resolve()))
            print(f"[green]✔ Log directory set to: {path.resolve()}[/green]")
        except Exception as e:
            print(f"[bold red]Error setting log directory:[/bold red] {e}")
            raise typer.Exit(code=1)

    # Configure API token (always prompt if not setting paths only)
    if not forge_path and not log_dir:
        api_token = typer.prompt("Enter your API Token", hide_input=True)
        try:
            config_manager.save_token(api_token)
            print(
                f"[green]✔ Configuration saved successfully to "
                f"{config_manager.config_file}[/green]"
            )
        except IOError as e:
            print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(code=1)
    elif forge_path or log_dir:
        # If only setting paths, show current config location
        print(f"[green]✔ Configuration saved to {config_manager.config_file}[/green]")
