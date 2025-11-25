import configparser
import os
from pathlib import Path
from typing import Optional


class ConfigManager:
    """Manages reading/writing to ~/.wafrunner/config."""

    def __init__(self):
        self.config_dir = Path.home() / ".wafrunner"
        self.config_file = self.config_dir / "config"
        self._config = configparser.ConfigParser()
        # Load existing config if it exists
        if self.config_file.is_file():
            self._config.read(self.config_file)

    def _save_config(self):
        """Save config to file."""
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, "w") as f:
                self._config.write(f)
        except IOError as e:
            raise IOError(
                f"Could not write configuration to {self.config_file}."
            ) from e

    def save_token(self, token: str):
        """Saves the API token to the config file."""
        if not self._config.has_section("auth"):
            self._config.add_section("auth")
        self._config.set("auth", "api_token", token)
        self._save_config()

    def load_token(self) -> str | None:
        """Loads the API token from the config file."""
        if not self.config_file.is_file():
            return None
        try:
            self._config.read(self.config_file)
            token = self._config.get("auth", "api_token", fallback=None)
            if token:
                return token.strip()
            return None
        except (configparser.Error, IOError):
            return None

    def get_data_dir(self) -> Path:
        """Returns the path to the data directory."""
        data_dir = self.config_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir

    def get_forge_path(self) -> Optional[Path]:
        """
        Get forge path from environment variable, config file, or None.

        Priority:
        1. Environment variable WAFRUNNER_FORGE_PATH
        2. Config file [paths] forge_path
        3. None (caller should use fallback)
        """
        # Check environment variable first
        env_path = os.getenv("WAFRUNNER_FORGE_PATH")
        if env_path:
            path = Path(env_path)
            if path.exists():
                return path
            return path  # Return even if doesn't exist, let caller handle

        # Check config file
        if self.config_file.is_file():
            try:
                self._config.read(self.config_file)
                config_path = self._config.get("paths", "forge_path", fallback=None)
                if config_path:
                    return Path(config_path)
            except (configparser.Error, KeyError):
                pass

        return None

    def set_forge_path(self, path: str):
        """Set forge path in config file."""
        if not self._config.has_section("paths"):
            self._config.add_section("paths")
        self._config.set("paths", "forge_path", path)
        self._save_config()

    def get_log_dir(self) -> Path:
        """
        Get log directory from environment variable, config file, or default.

        Priority:
        1. Environment variable WAFRUNNER_LOG_DIR
        2. Config file [paths] log_dir
        3. Default: ~/.wafrunner/logs
        """
        # Check environment variable first
        env_path = os.getenv("WAFRUNNER_LOG_DIR")
        if env_path:
            log_dir = Path(env_path)
            log_dir.mkdir(parents=True, exist_ok=True)
            return log_dir

        # Check config file
        if self.config_file.is_file():
            try:
                self._config.read(self.config_file)
                config_path = self._config.get("paths", "log_dir", fallback=None)
                if config_path:
                    log_dir = Path(config_path)
                    log_dir.mkdir(parents=True, exist_ok=True)
                    return log_dir
            except (configparser.Error, KeyError):
                pass

        # Default
        log_dir = self.config_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        return log_dir

    def set_log_dir(self, path: str):
        """Set log directory in config file."""
        if not self._config.has_section("paths"):
            self._config.add_section("paths")
        self._config.set("paths", "log_dir", path)
        self._save_config()
