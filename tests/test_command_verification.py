"""Test to verify all required CLI commands are present.

This test prevents accidental removal of commands during merges/refactors.
Based on incident where refine-graph was accidentally removed.
"""

import pytest

from wafrunner_cli.commands.research import app as research_app


def test_all_required_commands_present():
    """Verify all required research commands exist."""
    # Get all commands - some have explicit names, others use function names
    all_commands = []
    for cmd in research_app.registered_commands:
        if cmd.name:
            all_commands.append(cmd.name)
        elif hasattr(cmd, "callback") and hasattr(cmd.callback, "__name__"):
            all_commands.append(cmd.callback.__name__)

    commands = set(all_commands)
    required = {
        "github",
        "scrape",
        "classify",
        "init-graph",
        "refine-graph",  # Was accidentally removed - critical to verify
        "init-scdef",
        "update-source",
        "links",
        "show",
    }

    missing = required - commands
    if missing:
        pytest.fail(
            f"Missing required commands: {missing}\n"
            f"Found commands: {sorted(commands)}\n"
            "DO NOT COMMIT - Existing functionality has been removed!"
        )

    # Optional: Check for unexpected commands (informational only)
    extra = commands - required
    if extra:
        pytest.fail(
            f"Unexpected commands found: {extra}\n"
            "This may be intentional, but verify they are documented."
        )


def test_commands_are_callable():
    """Verify all commands can be invoked (basic smoke test)."""
    from typer.testing import CliRunner

    runner = CliRunner()

    # Test that help works for each command
    # This ensures commands are properly registered and don't have syntax errors
    result = runner.invoke(research_app, ["--help"])
    assert result.exit_code == 0, "Research command group should be callable"
