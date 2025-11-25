from pathlib import Path
from wafrunner_cli.core.config_manager import ConfigManager


def test_save_and_load_token(monkeypatch, tmp_path: Path):
    """
    Verify that a token can be saved and then loaded correctly.
    """
    # Arrange: Redirect Path.home() to a temporary directory for this test
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    config_manager = ConfigManager()
    test_token = "my-secret-test-token-123"

    # Act: Save the token
    config_manager.save_token(test_token)

    # Assert: Verify the token can be loaded by a new instance
    new_config_manager = ConfigManager()
    loaded_token = new_config_manager.load_token()

    assert loaded_token == test_token
    assert new_config_manager.config_file.exists()


def test_load_token_not_found(monkeypatch, tmp_path: Path):
    """
    Verify that loading a token returns None when the config file does not exist.
    """
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    config_manager = ConfigManager()
    assert config_manager.load_token() is None


def test_get_forge_path_from_env(monkeypatch, tmp_path: Path):
    """Test that forge path is read from environment variable."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    test_forge_path = "/test/forge/path"
    monkeypatch.setenv("WAFRUNNER_FORGE_PATH", test_forge_path)

    config_manager = ConfigManager()
    forge_path = config_manager.get_forge_path()

    assert forge_path == Path(test_forge_path)


def test_get_forge_path_from_config(monkeypatch, tmp_path: Path):
    """Test that forge path is read from config file."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    # Clear env var if set
    monkeypatch.delenv("WAFRUNNER_FORGE_PATH", raising=False)

    config_manager = ConfigManager()
    test_forge_path = "/test/forge/path"
    config_manager.set_forge_path(test_forge_path)

    # Create new instance to test loading
    new_config_manager = ConfigManager()
    forge_path = new_config_manager.get_forge_path()

    assert forge_path == Path(test_forge_path)


def test_get_forge_path_none(monkeypatch, tmp_path: Path):
    """Test that forge path returns None when not configured."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("WAFRUNNER_FORGE_PATH", raising=False)

    config_manager = ConfigManager()
    forge_path = config_manager.get_forge_path()

    assert forge_path is None


def test_get_log_dir_from_env(monkeypatch, tmp_path: Path):
    """Test that log directory is read from environment variable."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    test_log_dir = str(tmp_path / "test_logs")
    monkeypatch.setenv("WAFRUNNER_LOG_DIR", test_log_dir)

    config_manager = ConfigManager()
    log_dir = config_manager.get_log_dir()

    assert log_dir == Path(test_log_dir)
    assert log_dir.exists()


def test_get_log_dir_from_config(monkeypatch, tmp_path: Path):
    """Test that log directory is read from config file."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("WAFRUNNER_LOG_DIR", raising=False)

    config_manager = ConfigManager()
    test_log_dir = str(tmp_path / "custom_logs")
    config_manager.set_log_dir(test_log_dir)

    # Create new instance to test loading
    new_config_manager = ConfigManager()
    log_dir = new_config_manager.get_log_dir()

    assert log_dir == Path(test_log_dir)
    assert log_dir.exists()


def test_get_log_dir_default(monkeypatch, tmp_path: Path):
    """Test that log directory defaults to ~/.wafrunner/logs."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("WAFRUNNER_LOG_DIR", raising=False)

    config_manager = ConfigManager()
    log_dir = config_manager.get_log_dir()

    expected_dir = tmp_path / ".wafrunner" / "logs"
    assert log_dir == expected_dir
    assert log_dir.exists()


def test_set_forge_path(monkeypatch, tmp_path: Path):
    """Test setting forge path in config."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("WAFRUNNER_FORGE_PATH", raising=False)

    config_manager = ConfigManager()
    test_path = "/test/forge/path"
    config_manager.set_forge_path(test_path)

    # Verify it's saved
    new_config_manager = ConfigManager()
    assert new_config_manager.get_forge_path() == Path(test_path)


def test_set_log_dir(monkeypatch, tmp_path: Path):
    """Test setting log directory in config."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("WAFRUNNER_LOG_DIR", raising=False)

    config_manager = ConfigManager()
    test_log_dir = str(tmp_path / "custom_logs")
    config_manager.set_log_dir(test_log_dir)

    # Verify it's saved and directory is created
    new_config_manager = ConfigManager()
    log_dir = new_config_manager.get_log_dir()
    assert log_dir == Path(test_log_dir)
    assert log_dir.exists()
