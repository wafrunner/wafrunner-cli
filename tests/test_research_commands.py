import pytest
import typer
from pathlib import Path

from wafrunner_cli.commands.research import require_one_identifier


# Create a dummy command that will be decorated for testing purposes
@require_one_identifier
def dummy_command(vulnid: str | None = None, vulnid_file: Path | None = None):
    """A dummy command for testing the decorator's logic."""
    return "success"


def test_decorator_with_vulnid_only():
    """Verify the command runs when only --vulnid is provided."""
    result = dummy_command(vulnid="VULN-123", vulnid_file=None)
    assert result == "success"


def test_decorator_with_file_only(tmp_path: Path):
    """Verify the command runs when only --vulnid-file is provided."""
    p = tmp_path / "vuln.txt"
    p.touch()
    result = dummy_command(vulnid=None, vulnid_file=p)
    assert result == "success"


def test_decorator_with_both_identifiers_fails(tmp_path: Path):
    """Verify the command exits when both identifiers are provided."""
    p = tmp_path / "vuln.txt"
    p.touch()
    with pytest.raises(typer.Exit) as excinfo:
        dummy_command(vulnid="VULN-123", vulnid_file=p)
    assert excinfo.value.exit_code == 1


def test_decorator_with_no_identifiers_fails():
    """Verify the command exits when no identifiers are provided."""
    with pytest.raises(typer.Exit) as excinfo:
        dummy_command(vulnid=None, vulnid_file=None)
    assert excinfo.value.exit_code == 1