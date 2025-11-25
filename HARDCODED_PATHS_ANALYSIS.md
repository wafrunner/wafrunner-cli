# Hardcoded Paths Analysis

## Summary
This document identifies all hardcoded paths in the wafrunner-cli codebase and the fixes that have been implemented.

## Status: ✅ FIXED
All hardcoded paths have been made configurable as of the latest changes.

## Problematic Hardcoded Paths

### 1. **Forge Path in `test.py` (CRITICAL)**
**Location:** `wafrunner_cli/commands/test.py:21`
```python
forge_path = Path(__file__).parent.parent.parent.parent / "forge"
```

**Problem:**
- Assumes forge is in a sibling directory to wafrunner-cli
- Won't work if CLI is installed as a package (e.g., via pip)
- Not configurable by users
- Breaks if directory structure changes

**Recommendation:**
- Add `forge_path` to config file (`~/.wafrunner/config`)
- Support environment variable `WAFRUNNER_FORGE_PATH`
- Fallback to relative path only for development
- Make it configurable via `wafrunner configure` command

### 2. **Relative Log Directory in `research.py` (MODERATE)**
**Location:** `wafrunner_cli/commands/research.py:708, 1001, 1247, 1463, 1688`
```python
log_dir = Path("./run_logs")
```

**Problem:**
- Relative to current working directory
- Could create logs in unexpected locations
- Not configurable

**Recommendation:**
- Use configurable log directory (default: `~/.wafrunner/logs`)
- Or use absolute path based on config

## Acceptable Paths (Using Path.home())

These paths use `Path.home()` which is portable and standard practice:

### User Config/Data Directories (OK)
- `~/.wafrunner/config` - ConfigManager
- `~/.wafrunner/data` - Data directory
- `~/.wafrunner/test-status` - Test status files
- `~/.wafrunner/shell_history` - Shell history
- `~/.wafrunner/data/collections` - Collections directory

**Status:** ✅ These are fine - they use `Path.home()` which is cross-platform and standard.

## Recommended Fixes

### 1. Extend ConfigManager
Add methods to `ConfigManager` to handle forge path and other configurable paths:

```python
def get_forge_path(self) -> Optional[Path]:
    """Get forge path from config or environment."""
    # Check environment variable first
    env_path = os.getenv("WAFRUNNER_FORGE_PATH")
    if env_path:
        return Path(env_path)

    # Check config file
    self._config.read(self.config_file)
    config_path = self._config.get("paths", "forge_path", fallback=None)
    if config_path:
        return Path(config_path)

    # Fallback to relative path for development
    return None

def set_forge_path(self, path: str):
    """Set forge path in config."""
    if not self._config.has_section("paths"):
        self._config.add_section("paths")
    self._config.set("paths", "forge_path", path)
    with open(self.config_file, "w") as f:
        self._config.write(f)
```

### 2. Update test.py
Replace hardcoded forge path with config-based lookup:

```python
from wafrunner_cli.core.config_manager import ConfigManager

config_manager = ConfigManager()
forge_path = config_manager.get_forge_path()

# Fallback to relative path for development
if not forge_path:
    forge_path = Path(__file__).parent.parent.parent.parent / "forge"

if forge_path and forge_path.exists():
    sys.path.insert(0, str(forge_path))
```

### 3. Update research.py
Use configurable log directory:

```python
from wafrunner_cli.core.config_manager import ConfigManager

config_manager = ConfigManager()
log_dir = config_manager.get_log_dir()  # Default: ~/.wafrunner/logs
```

### 4. Update configure command
Add option to set forge path:

```python
@app.command()
def configure(
    forge_path: Optional[str] = typer.Option(None, "--forge-path", help="Path to forge repository")
):
    """Configure wafrunner CLI settings."""
    config_manager = ConfigManager()

    if forge_path:
        config_manager.set_forge_path(forge_path)
        print(f"✅ Forge path set to: {forge_path}")
```

## Files Requiring Changes

1. `wafrunner_cli/core/config_manager.py` - Add path configuration methods
2. `wafrunner_cli/commands/test.py` - Use config-based forge path
3. `wafrunner_cli/commands/research.py` - Use configurable log directory
4. `wafrunner_cli/commands/configure.py` - Add forge path configuration option

## Environment Variables

Support these environment variables as overrides:
- `WAFRUNNER_FORGE_PATH` - Path to forge repository
- `WAFRUNNER_LOG_DIR` - Log directory (default: `~/.wafrunner/logs`)
- `WAFRUNNER_DATA_DIR` - Data directory (default: `~/.wafrunner/data`)
