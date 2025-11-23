"""
Prerequisites checking module for wafrunner test execution.

Checks for Docker installation, Docker daemon, system resources, and platform compatibility.
"""

import os
import platform
import subprocess
import logging
from typing import Dict, Optional, Tuple, Any

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


logger = logging.getLogger(__name__)


def check_docker_installed() -> Tuple[bool, Optional[str]]:
    """
    Check if Docker is installed.

    Returns:
        Tuple of (is_installed, version_string)
    """
    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        version = result.stdout.strip()
        return True, version
    except (
        subprocess.CalledProcessError,
        FileNotFoundError,
        subprocess.TimeoutExpired,
    ):
        return False, None


def check_docker_running() -> Tuple[bool, Optional[str]]:
    """
    Check if Docker daemon is running.

    Returns:
        Tuple of (is_running, error_message)
    """
    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return True, None
        else:
            return False, result.stderr.strip() or "Docker daemon not responding"
    except FileNotFoundError:
        return False, "Docker command not found"
    except subprocess.TimeoutExpired:
        return False, "Docker daemon check timed out"
    except Exception as e:
        return False, str(e)


def check_docker_compose_available() -> Tuple[bool, Optional[str]]:
    """
    Check if Docker Compose is available.

    Returns:
        Tuple of (is_available, version_string)
    """
    # Try docker compose (v2)
    try:
        result = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        version = result.stdout.strip()
        return True, version
    except (
        subprocess.CalledProcessError,
        FileNotFoundError,
        subprocess.TimeoutExpired,
    ):
        pass

    # Try docker-compose (v1)
    try:
        result = subprocess.run(
            ["docker-compose", "--version"], capture_output=True, text=True, timeout=5
        )
        version = result.stdout.strip()
        return True, version
    except (
        subprocess.CalledProcessError,
        FileNotFoundError,
        subprocess.TimeoutExpired,
    ):
        return False, None


def check_platform_compatibility() -> Tuple[bool, Optional[str]]:
    """
    Check if the platform is supported.

    Returns:
        Tuple of (is_compatible, platform_info)
    """
    system = platform.system()
    machine = platform.machine()

    # Normalize machine names
    machine_normalized = machine.lower()
    if machine_normalized in ["x86_64", "amd64"]:
        machine_normalized = "x86_64"
    elif machine_normalized in ["arm64", "aarch64"]:
        machine_normalized = "arm64"

    platform_info = f"{system} {machine}"

    # Check compatibility
    is_compatible = (
        system == "Linux" and machine_normalized in ["x86_64", "arm64"]
    ) or (system == "Darwin" and machine_normalized in ["arm64", "x86_64"])

    return is_compatible, platform_info


def detect_system_resources() -> Dict[str, Any]:
    """
    Detect system CPU and memory resources.

    Returns:
        Dictionary with 'cpu_cores', 'memory_gb', 'architecture', and 'sufficient' keys
    """
    if not PSUTIL_AVAILABLE:
        # Fallback to basic detection
        try:
            cpu_count = os.cpu_count() or 2
        except (AttributeError, TypeError):
            cpu_count = 2

        # Try to get memory from /proc/meminfo on Linux
        memory_gb = 4.0  # Default assumption
        if platform.system() == "Linux":
            try:
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            memory_kb = int(line.split()[1])
                            memory_gb = memory_kb / (1024 * 1024)
                            break
            except (OSError, ValueError, IndexError):
                pass

        architecture = platform.machine()
        return {
            "cpu_cores": cpu_count,
            "memory_gb": round(memory_gb, 2),
            "architecture": architecture,
            "sufficient": cpu_count >= 2 and memory_gb >= 4.0,
        }

    # Use psutil for accurate detection
    cpu_count = psutil.cpu_count(logical=True)
    memory = psutil.virtual_memory()
    memory_gb = memory.total / (1024**3)
    architecture = platform.machine()

    return {
        "cpu_cores": cpu_count,
        "memory_gb": round(memory_gb, 2),
        "architecture": architecture,
        "sufficient": cpu_count >= 2 and memory_gb >= 4.0,
    }


def check_system_resources() -> Tuple[bool, Dict[str, any]]:
    """
    Check if system has sufficient resources.

    Returns:
        Tuple of (is_sufficient, resources_dict)
    """
    resources = detect_system_resources()
    is_sufficient = resources["sufficient"]
    return is_sufficient, resources


def check_all_prerequisites() -> Dict[str, Any]:
    """
    Check all prerequisites for test execution.

    Returns:
        Dictionary with check results and overall status
    """
    results = {
        "docker_installed": False,
        "docker_version": None,
        "docker_running": False,
        "docker_error": None,
        "docker_compose_available": False,
        "docker_compose_version": None,
        "platform_compatible": False,
        "platform_info": None,
        "resources_sufficient": False,
        "resources": {},
        "all_passed": False,
    }

    # Check Docker installation
    installed, version = check_docker_installed()
    results["docker_installed"] = installed
    results["docker_version"] = version

    # Check Docker daemon
    if installed:
        running, error = check_docker_running()
        results["docker_running"] = running
        results["docker_error"] = error

    # Check Docker Compose
    compose_available, compose_version = check_docker_compose_available()
    results["docker_compose_available"] = compose_available
    results["docker_compose_version"] = compose_version

    # Check platform
    compatible, platform_info = check_platform_compatibility()
    results["platform_compatible"] = compatible
    results["platform_info"] = platform_info

    # Check resources
    sufficient, resources = check_system_resources()
    results["resources_sufficient"] = sufficient
    results["resources"] = resources

    # Overall status
    results["all_passed"] = (
        installed and running and compose_available and compatible and sufficient
    )

    return results


def get_docker_installation_instructions() -> str:
    """
    Get platform-specific Docker installation instructions.

    Returns:
        Instructions string
    """
    system = platform.system()

    if system == "Linux":
        return """
Install Docker on Linux:
  1. Ubuntu/Debian:
     sudo apt-get update
     sudo apt-get install -y docker.io docker-compose
     sudo systemctl start docker
     sudo systemctl enable docker
     sudo usermod -aG docker $USER
     # Log out and back in for group changes to take effect

  2. Or use Docker's official installation script:
     curl -fsSL https://get.docker.com -o get-docker.sh
     sudo sh get-docker.sh
"""
    elif system == "Darwin":
        return """
Install Docker on macOS:
  1. Download Docker Desktop from: https://www.docker.com/products/docker-desktop
  2. Install and launch Docker Desktop
  3. Ensure Docker Desktop is running (check menu bar icon)
"""
    else:
        return """
Install Docker:
  Visit https://www.docker.com/get-started for installation instructions
  for your platform.
"""
