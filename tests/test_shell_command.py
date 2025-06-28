import pytest
import typer
from unittest.mock import MagicMock

from prompt_toolkit.completion import FuzzyWordCompleter

# Functions and objects to test
from wafrunner_cli.commands.shell import _get_typer_completions, run_shell

# --- Fixtures ---

@pytest.fixture
def mock_prompt_session(mocker):
    """Mocks the prompt_toolkit.PromptSession."""
    mock_session_instance = MagicMock()
    # Configure the prompt method to return a sequence of inputs
    mock_session_class = mocker.patch("wafrunner_cli.commands.shell.PromptSession", return_value=mock_session_instance)
    return mock_session_instance, mock_session_class

@pytest.fixture
def mock_main_app(mocker):
    """Mocks the main Typer application object."""
    # The 'app' is imported from 'wafrunner_cli.main' inside run_shell,
    # so we must patch it at its source.
    mock_app = mocker.patch("wafrunner_cli.main.app")
    # The function under test (_get_typer_completions) iterates over these attributes.
    # We must ensure the mock has them defined as iterables.
    mock_app.registered_commands = []
    mock_app.registered_groups = []
    return mock_app

@pytest.fixture
def mock_rich_print(mocker):
    """Mocks rich.print."""
    return mocker.patch("wafrunner_cli.commands.shell.print")

@pytest.fixture
def mock_path_methods(mocker, tmp_path):
    """Mocks Path.home() to use a temporary directory."""
    # Mock Path.home() to control where the history file is written
    mocker.patch("pathlib.Path.home", return_value=tmp_path)
    # Also mock mkdir on the Path object to avoid actual file system operations if needed
    mocker.patch("pathlib.Path.mkdir")


# --- Test for _get_typer_completions ---

def test_get_typer_completions():
    """
    Tests that the completion dictionary is built correctly, handles commands
    with and without options, and excludes the 'shell' command.
    """
    # --- Arrange: Create a complex, nested Typer app structure ---
    sub_group_app = typer.Typer()
    @sub_group_app.command("subcmd2")
    def subcmd2(): pass  # Command with no options

    group_app = typer.Typer()
    @group_app.command("subcmd1")
    def subcmd1(force: bool = typer.Option(False, "--force")): pass  # Command with an option
    group_app.add_typer(sub_group_app, name="group2")

    main_app = typer.Typer()
    @main_app.command("cmd1")
    def cmd1(): pass  # Command with no options
    @main_app.command("shell")
    def shell(): pass  # This command should be excluded
    main_app.add_typer(group_app, name="group1")

    # --- Act ---
    completions = _get_typer_completions(main_app)

    # --- Assert ---
    # 1. Check structure for command groups
    assert isinstance(completions["group1"], dict)
    assert isinstance(completions["group1"]["group2"], dict)

    # 2. Check commands without options return an empty dict
    assert completions["cmd1"] == {}
    assert completions["group1"]["group2"]["subcmd2"] == {}

    # 3. Check command with an option returns a completer instance
    assert isinstance(completions["group1"]["subcmd1"], FuzzyWordCompleter)

    # 4. Check that the shell command is excluded
    assert "shell" not in completions


# --- Tests for run_shell ---

def test_run_shell_initialization(mock_prompt_session, mock_main_app, mock_rich_print, mock_path_methods, tmp_path):
    """
    Tests that the shell initializes correctly, setting up history and the completer.
    """
    mock_session_instance, mock_session_class = mock_prompt_session
    mock_session_instance.prompt.return_value = "exit" # Exit immediately

    run_shell()

    mock_rich_print.assert_any_call("[bold green]Welcome to the wafrunner interactive shell.[/bold green]")
    history_file_path = tmp_path / ".wafrunner" / "shell_history"
    mock_session_class.assert_called_once()
    assert str(mock_session_class.call_args.kwargs['history'].filename) == str(history_file_path)


def test_run_shell_exit_command(mock_prompt_session, mock_main_app, mock_rich_print, mock_path_methods):
    """
    Tests that the shell exits cleanly when 'exit' or 'quit' is entered.
    """
    mock_session_instance, _ = mock_prompt_session
    
    mock_session_instance.prompt.return_value = "exit"
    run_shell()
    mock_rich_print.assert_any_call("\n[bold green]Exiting wafrunner shell. Goodbye![/bold green]")


def test_run_shell_executes_command(mock_prompt_session, mock_main_app, mock_path_methods):
    """
    Tests that a command entered in the shell is correctly parsed and executed.
    """
    mock_session_instance, _ = mock_prompt_session
    mock_session_instance.prompt.side_effect = ["cve upload --force", "exit"]

    run_shell()

    mock_main_app.assert_called_once_with(['cve', 'upload', '--force'], prog_name="wafrunner", standalone_mode=False)


def test_run_shell_handles_system_exit(mock_prompt_session, mock_main_app, mock_path_methods):
    """
    Tests that the shell catches SystemExit (e.g., from --help) and continues running.
    """
    mock_session_instance, _ = mock_prompt_session
    mock_session_instance.prompt.side_effect = ["cve --help", "exit"]
    mock_main_app.side_effect = SystemExit(0)

    run_shell()

    assert mock_session_instance.prompt.call_count == 2
    mock_main_app.assert_called_once_with(['cve', '--help'], prog_name="wafrunner", standalone_mode=False)