# Testing Guide for wafrunner-cli

This guide documents the standard testing practices for this CLI application.

## Testing Stack

- **pytest**: Primary testing framework
- **typer.testing.CliRunner**: For testing CLI commands
- **flake8**: Code linting
- **black**: Code formatting
- **pre-commit**: Git hooks for automated checks

## Test Types

### 1. Unit Tests

Test individual functions and components in isolation.

**Location**: `tests/test_*.py`
**Run**: `pytest tests/` or `make test`

Example:

```python
def test_api_client_initialization():
    # Test specific functionality
    pass
```

### 2. CLI Command Tests

Test that commands are properly registered and work correctly.

**Location**: `tests/test_*_commands.py`
**Run**: `pytest tests/ -k "commands"` or `make test-cli`

Example:

```python
from typer.testing import CliRunner
from wafrunner_cli.main import app

def test_command_success():
    runner = CliRunner()
    result = runner.invoke(app, ["research", "github", "--id", "CVE-2024-1234"])
    assert result.exit_code == 0
```

### 3. Command Verification Tests

Ensures all required commands are present (prevents accidental removal).

**Location**: `tests/test_command_verification.py`
**Run**: `pytest tests/test_command_verification.py`

This test is critical - it verifies that no commands were accidentally removed during merges.

## Running Tests

### All Tests

```bash
make test
# or
pytest tests/
```

### Unit Tests Only

```bash
make test-unit
# or
pytest tests/ -m "not integration"
```

### CLI Tests Only

```bash
make test-cli
# or
pytest tests/ -k "command"
```

### With Coverage

```bash
pytest tests/ --cov=wafrunner_cli --cov-report=html
```

## Pre-Commit Hooks

Pre-commit hooks automatically run before each commit:

1. **YAML validation**
2. **End of file fixing**
3. **Trailing whitespace removal**
4. **Black formatting** (auto-fixes)
5. **Flake8 linting**
6. **Command verification** (ensures all commands exist)

To set up:

```bash
make install-dev
```

## Code Quality Checks

### Linting

```bash
make lint
# or
flake8 wafrunner_cli tests scripts
```

### Formatting

```bash
make format
# or
black wafrunner_cli tests scripts
```

### Check (read-only)

```bash
make check
# Runs both lint and format checks without modifying files
```

## Command Verification

The command verification ensures all 8 required commands exist:

```bash
make verify-commands
# or
./scripts/verify-commands.sh
# or
pytest tests/test_command_verification.py
```

**Required commands**:

- `github`
- `scrape`
- `classify`
- `init-graph`
- `refine-graph` (critical - was accidentally removed before)
- `init-scdef`
- `update-source`
- `links`

## Best Practices

### 1. Test Structure

- Use `unittest.TestCase` or plain `pytest` functions
- Group related tests in classes
- Mock external dependencies (API calls, file system)

### 2. CLI Testing

- Always use `CliRunner` from `typer.testing`
- Test both success and failure cases
- Verify exit codes and output messages
- Mock API clients to avoid real network calls

### 3. Test Naming

- Files: `test_*.py`
- Functions: `test_*`
- Classes: `Test*`

### 4. Before Committing

Always run:

```bash
make check        # Lint and format check
make test         # All tests
make verify-commands  # Command verification
```

Or let pre-commit hooks handle it automatically.

## Continuous Integration

In CI/CD pipelines, run:

```bash
# Install dependencies
pip install -e ".[test]"

# Run checks
make check
make verify-commands

# Run tests
pytest tests/ --cov=wafrunner_cli --cov-report=xml
```

## Troubleshooting

### Pre-commit hooks not running

```bash
pre-commit install
```

### Tests failing after merge

```bash
# Check if commands are missing
make verify-commands

# Check for import errors
python -c "from wafrunner_cli.main import app"

# Run specific test
pytest tests/test_specific.py -v
```

### Command not found in tests

```bash
# Verify command registration
python -c "from wafrunner_cli.commands.research import app; print([c.name for c in app.registered_commands])"
```

## Test Coverage Goals

- **Aim for**: >80% coverage
- **Critical paths**: 100% coverage
- **CLI commands**: All commands should have tests
- **Error handling**: Test error paths

## Additional Resources

- [pytest documentation](https://docs.pytest.org/)
- [typer testing guide](https://typer.tiangolo.com/tutorial/testing/)
- [Pre-commit hooks](https://pre-commit.com/)
