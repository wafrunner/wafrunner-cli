import configparser
from pathlib import Path


class ConfigManager:
    """Manages reading/writing to ~/.wafrunner/config."""

    def __init__(self):
        self.config_dir = Path.home() / ".wafrunner"
        self.config_file = self.config_dir / "config"
        self._config = configparser.ConfigParser()

    def save_token(self, token: str):
        """Saves the API token to the config file."""
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            self._config["auth"] = {"api_token": token}
            with open(self.config_file, "w") as f:
                self._config.write(f)
        except IOError as e:
            raise IOError(f"Could not write configuration to {self.config_file}.") from e

    def load_token(self) -> str | None:
        """Loads the API token from the config file."""
        if not self.config_file.is_file():
            return None
        try:
            self._config.read(self.config_file)
            return self._config.get("auth", "api_token", fallback=None)
        except (configparser.Error, IOError):
            return None