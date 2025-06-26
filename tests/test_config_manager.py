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