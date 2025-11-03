.PHONY: help test test-unit test-integration lint format check verify-commands clean install-dev

help:
	@echo "Available commands:"
	@echo "  make test           - Run all tests"
	@echo "  make test-unit      - Run unit tests only"
	@echo "  make test-cli       - Run CLI tests"
	@echo "  make lint           - Run flake8 and other linters"
	@echo "  make format         - Format code with black"
	@echo "  make check          - Run lint and format checks (read-only)"
	@echo "  make verify-commands - Verify all CLI commands are present"
	@echo "  make clean          - Clean up generated files"
	@echo "  make install-dev    - Install development dependencies"

test:
	@pytest tests/

test-unit:
	@pytest tests/ -m "not integration"

test-cli:
	@pytest tests/ -k "test_command_verification or test_research_commands or test_collection_commands"

lint:
	@flake8 wafrunner_cli tests scripts
	@echo "✓ Linting passed"

format:
	@black wafrunner_cli tests scripts
	@echo "✓ Code formatted"

check:
	@echo "Running format check..."
	@black --check wafrunner_cli tests scripts
	@echo "Running lint check..."
	@flake8 wafrunner_cli tests scripts
	@echo "✓ All checks passed"

verify-commands:
	@./scripts/verify-commands.sh

clean:
	@find . -type d -name __pycache__ -exec rm -r {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@find . -type f -name "*.pyo" -delete 2>/dev/null || true
	@find . -type d -name "*.egg-info" -exec rm -r {} + 2>/dev/null || true
	@echo "✓ Cleaned up generated files"

install-dev:
	@pip install -r requirements-dev.txt
	@pre-commit install
	@echo "✓ Development environment set up"
