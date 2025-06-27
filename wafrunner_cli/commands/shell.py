import shlex
import typer
import inspect
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from typer import main as typer_main
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import NestedCompleter, FuzzyWordCompleter
from rich import print
from pathlib import Path

# This is a bit of a circular import, but necessary to get the app object
# to inspect for commands. We'll import it inside the function to avoid
# issues at module load time.


def _get_typer_completions(app: typer.Typer) -> dict:
    """Recursively build a completion dictionary from a Typer app."""
    completions = {}

    # Get command groups (sub-typers)
    for group in app.registered_groups:
        # group.typer_instance is the actual Typer app for the subcommand
        completions[group.name] = _get_typer_completions(group.typer_instance)

    # Get standalone commands and their options
    for command_info in app.registered_commands:
        if command_info.name == "shell":
            continue

        if not command_info.callback:
            continue
        # Get all option names for the command (e.g., '--force', '--year')
        opts = []
        signature = inspect.signature(command_info.callback)
        for param in signature.parameters.values():
            # This function converts a function parameter to a click.Parameter
            click_param, _ = typer_main.get_click_param(param)
            # We are only interested in options, not arguments
            if isinstance(click_param, (typer_main.click.Option)):
                opts.extend(opt for opt in click_param.opts if opt.startswith('--'))

        # If a command has options, use a completer for them, otherwise, it's the end of the path.
        completions[command_info.name] = FuzzyWordCompleter(opts) if opts else {}

    return completions


def run_shell():
    """
    Starts an interactive shell session for wafrunner.
    """
    # Import here to avoid circular dependency issues at startup
    from wafrunner_cli.main import app

    print("[bold green]Welcome to the wafrunner interactive shell.[/bold green]")
    print("Type 'exit' or 'quit' to leave.")

    completions = _get_typer_completions(app)
    completer = NestedCompleter.from_nested_dict(completions)

    history_file = Path.home() / ".wafrunner" / "shell_history"
    history_file.parent.mkdir(parents=True, exist_ok=True)
    session = PromptSession(
        history=FileHistory(str(history_file)),
        auto_suggest=AutoSuggestFromHistory(),
        completer=completer,
    )

    while True:
        try:
            text = session.prompt("wafrunner> ")
            if text.strip().lower() in ["exit", "quit"]:
                break
            if not text.strip():
                continue

            args = shlex.split(text)
            app(args, prog_name="wafrunner", standalone_mode=False)
        except SystemExit:
            # Typer/Click raises SystemExit on --help or errors, which we want to ignore to keep the shell running.
            pass
        except Exception as e:
            print(f"[bold red]An unexpected error occurred: {e}[/bold red]")

    print("\n[bold green]Exiting wafrunner shell. Goodbye![/bold green]")