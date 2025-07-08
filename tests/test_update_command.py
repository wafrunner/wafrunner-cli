import pytest
from typer.testing import CliRunner
from unittest.mock import MagicMock, patch
from pathlib import Path

from wafrunner_cli.main import app

runner = CliRunner()

@pytest.fixture
def mock_config_manager():
    with patch('wafrunner_cli.commands.update.ConfigManager') as mock:
        instance = mock.return_value
        instance.get_data_dir.return_value = Path('/tmp/wafrunner_test_data')
        yield mock

@pytest.fixture
def mock_api_client():
    with patch('wafrunner_cli.commands.update.ApiClient') as mock:
        instance = mock.return_value
        instance.get_cve_lookup_download_url.return_value = MagicMock(
            json=lambda: {'fileName': 'test.json', 'downloadUrl': 'http://test.com/test.json'}
        )
        yield mock

@pytest.fixture
def mock_httpx_stream():
    with patch('wafrunner_cli.commands.update.httpx.stream') as mock:
        mock.return_value.__enter__.return_value.iter_bytes.return_value = [b'test data']
        yield mock

def test_update_command(mock_config_manager, mock_api_client, mock_httpx_stream):
    result = runner.invoke(app, ["update"])
    assert result.exit_code == 0
    assert "Successfully downloaded test.json" in result.stdout

def test_update_command_revert(mock_config_manager):
    lookup_dir = Path('/tmp/wafrunner_test_data/cve-lookup')
    lookup_dir.mkdir(parents=True, exist_ok=True)
    (lookup_dir / 'file1.json').touch()
    (lookup_dir / 'file2.json').touch()

    result = runner.invoke(app, ["update", "--revert"])
    assert result.exit_code == 0
    assert "Successfully reverted to" in result.stdout
