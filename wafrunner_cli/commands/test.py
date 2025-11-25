"""
Test execution commands for wafrunner CLI.

Provides commands for running, monitoring, and managing Forge test executions.
"""

import os
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

import typer
from rich import print
from rich.table import Table
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from wafrunner_cli.core.config_manager import ConfigManager  # noqa: E402

# Get forge path from config or environment
config_manager = ConfigManager()
forge_path = config_manager.get_forge_path()

# Fallback to relative path for development (if not configured)
if not forge_path:
    forge_path = Path(__file__).parent.parent.parent.parent / "forge"

# Add forge to path for imports if it exists
if forge_path and forge_path.exists():
    sys.path.insert(0, str(forge_path))

from wafrunner_cli.core.api_client import ApiClient  # noqa: E402
from wafrunner_cli.core.prerequisites import (  # noqa: E402
    check_all_prerequisites,
    detect_system_resources,
    get_docker_installation_instructions,
)

# Try to import Forge loader
try:
    from app.test_instance.loader import TestBundleLoader

    FORGE_AVAILABLE = True
except ImportError as e:
    FORGE_AVAILABLE = False
    IMPORT_ERROR = str(e)

app = typer.Typer(help="Commands for executing and managing Forge test runs.")

# Status tracking directory
STATUS_DIR = Path.home() / ".wafrunner" / "test-status"
STATUS_DIR.mkdir(parents=True, exist_ok=True)


def _check_forge_available():
    """Check if Forge modules are available."""
    if not FORGE_AVAILABLE:
        print("[bold red]Error:[/bold red] Forge modules not available.")
        print(f"Import error: {IMPORT_ERROR}")
        print("\nMake sure the forge repository is available.")
        if forge_path:
            print(f"Configured path: {forge_path}")
            if not forge_path.exists():
                print("[yellow]Warning: Path does not exist[/yellow]")
        else:
            print("No forge path configured.")
            print("Set it using: wafrunner configure --forge-path <path>")
            print("Or set environment variable: WAFRUNNER_FORGE_PATH=<path>")
        raise typer.Exit(1)


def _get_api_key() -> str:
    """Get API key from config or environment."""
    # Try environment variable
    api_key = os.getenv("FORGE_API_KEY")
    if api_key:
        return api_key

    # Try wafrunner CLI config
    try:
        import configparser

        config_path = Path.home() / ".wafrunner" / "config"
        if config_path.exists():
            config = configparser.ConfigParser()
            config.read(config_path)
            api_key = config.get("auth", "api_token", fallback=None)
            if api_key:
                return api_key
    except Exception:
        pass

    raise typer.BadParameter(
        "API key not found. Set FORGE_API_KEY env var or run 'wafrunner configure'"
    )


def _save_test_status(test_id: str, status: Dict[str, Any]):
    """Save test status to local file."""
    status_file = STATUS_DIR / f"{test_id}.json"
    status["updated_at"] = datetime.utcnow().isoformat()
    with open(status_file, "w") as f:
        json.dump(status, f, indent=2)


def _load_test_status(test_id: str) -> Optional[Dict[str, Any]]:
    """Load test status from local file."""
    status_file = STATUS_DIR / f"{test_id}.json"
    if not status_file.exists():
        return None
    with open(status_file, "r") as f:
        return json.load(f)


def _display_enhanced_analysis(console: Console, analysis: Dict[str, Any]) -> None:
    """
    Display enhanced analysis answering key questions about test execution.

    Generic display that works for any vulnerability type and control.

    Args:
        console: Rich console instance
        analysis: Analysis dictionary from generate_comprehensive_analysis
    """
    console.print("\n[bold cyan]Test Analysis Report[/bold cyan]")
    console.print("=" * 70)

    # Question 1: Vulnerability Detection
    vuln_det = analysis.get("vulnerability_detection", {})
    console.print(
        "\n[bold]1. Is the test endpoint adequately functioning to "
        "simulate the vulnerability?[/bold]"
    )
    if vuln_det.get("vulnerability_detected"):
        console.print(
            f"  ✅ [green]YES[/green] - {vuln_det.get('message', 'Vulnerability detected')}"
        )
        console.print(
            f"     Confidence: {vuln_det.get('confidence', 'unknown').upper()}"
        )
        details = vuln_det.get("details", {})
        if details:
            vuln_detected = details.get("vulnerabilities_detected", 0)
            vuln_total = details.get("total_tests", 0)
            console.print(
                f"     • Vulnerabilities detected: {vuln_detected}/{vuln_total}"
            )
            console.print(
                f"     • Detection rate: {vuln_det.get('detection_rate', 0)}%"
            )

        # Show breakdown by vulnerability type
        by_type = vuln_det.get("by_type", {})
        if by_type:
            console.print("     • By type:")
            for vuln_type, type_data in by_type.items():
                detected = type_data.get("detected", 0)
                total = type_data.get("total", 0)
                console.print(f"       - {vuln_type}: {detected}/{total} detected")
    else:
        console.print(
            f"  ❌ [red]NO[/red] - {vuln_det.get('message', 'Vulnerability not detected')}"
        )
        console.print(
            f"     Confidence: {vuln_det.get('confidence', 'unknown').upper()}"
        )

    # Question 2: Control Effectiveness
    control_eff = analysis.get("control_effectiveness", {})
    console.print(
        "\n[bold]2. With controls active, is the vulnerability adequately addressed?[/bold]"
    )

    # Determine control mode (blocking vs detection)
    control_mode = control_eff.get("control_mode", "blocking")
    waf_mode = control_eff.get("waf_mode", "unknown")
    is_detection_mode = control_mode == "detection" or waf_mode == "detection"

    if control_eff.get("controls_effective"):
        console.print(
            f"  ✅ [green]YES[/green] - {control_eff.get('message', 'Controls effective')}"
        )
        console.print(
            f"     Confidence: {control_eff.get('confidence', 'unknown').upper()}"
        )
        details = control_eff.get("details", {})
        if details:
            controls_detected = details.get("controls_detected", [])
            if controls_detected:
                console.print(
                    f"     • Controls detected: {', '.join(controls_detected)}"
                )

            # Show WAF mode if applicable
            if waf_mode != "unknown":
                mode_display = (
                    "🔍 Detection/Logging" if waf_mode == "detection" else "🛡️ Blocking"
                )
                console.print(f"     • WAF mode: {mode_display}")

            if is_detection_mode:
                # In detection mode, show detections instead of blocks
                waf_detections = control_eff.get("waf_detections", 0)
                console.print(
                    f"     • Attacks detected: {waf_detections} detections logged"
                )
                if control_eff.get("waf_detections", 0) > 0:
                    console.print(
                        "     • Note: WAF is in detection mode (logging, not blocking)"
                    )
            else:
                # In blocking mode, show blocks
                blocked = control_eff.get("blocked_count", 0)
                total_vuln = control_eff.get("total_vuln_tests", 0)
                block_rate = control_eff.get("block_rate", 0)
                console.print(
                    f"     • Attacks blocked: {blocked}/{total_vuln} ({block_rate}%)"
                )
                bypassed = control_eff.get("bypassed_count", 0)
                bypass_rate = control_eff.get("bypass_rate", 0)
                console.print(f"     • Attacks bypassed: {bypassed} ({bypass_rate}%)")
    else:
        msg = control_eff.get("message", "Controls partially effective")
        console.print(f"  ⚠️  [yellow]PARTIAL[/yellow] - {msg}")
        console.print(
            f"     Confidence: {control_eff.get('confidence', 'unknown').upper()}"
        )
        details = control_eff.get("details", {})
        if details:
            controls_detected = details.get("controls_detected", [])
            if controls_detected:
                console.print(
                    f"     • Controls detected: {', '.join(controls_detected)}"
                )

            # Show WAF mode if applicable
            if waf_mode != "unknown":
                mode_display = (
                    "🔍 Detection/Logging" if waf_mode == "detection" else "🛡️ Blocking"
                )
                console.print(f"     • WAF mode: {mode_display}")

            if is_detection_mode:
                waf_det = control_eff.get("waf_detections", 0)
                console.print(f"     • Attacks detected: {waf_det} detections logged")
            else:
                console.print(f"     • Block rate: {control_eff.get('block_rate', 0)}%")
                console.print(
                    f"     • Bypass rate: {control_eff.get('bypass_rate', 0)}%"
                )

    # Question 3: Baseline Requests
    baseline = analysis.get("baseline_requests", {})
    console.print(
        "\n[bold]3. Do non-malicious requests all get through with no problems?[/bold]"
    )
    if baseline.get("all_passed"):
        console.print(
            f"  ✅ [green]YES[/green] - {baseline.get('message', 'All requests passed')}"
        )
        console.print(
            f"     Confidence: {baseline.get('confidence', 'unknown').upper()}"
        )
    else:
        console.print(
            f"  ⚠️  [yellow]PARTIAL[/yellow] - {baseline.get('message', 'Some requests failed')}"
        )
        console.print(
            f"     Confidence: {baseline.get('confidence', 'unknown').upper()}"
        )
        details = baseline.get("details", {})
        if details:
            console.print(f"     • Pass rate: {baseline.get('pass_rate', 0)}%")
            successful = details.get("successful_requests", 0)
            total_req = details.get("total_requests", 0)
            console.print(f"     • Passed: {successful}/{total_req}")
            if details.get("blocked_requests", 0) > 0:
                console.print(f"     • Blocked: {details.get('blocked_requests', 0)}")
            if details.get("error_requests", 0) > 0:
                console.print(f"     • Errors: {details.get('error_requests', 0)}")

    # Question 4: System Health
    sys_health = analysis.get("system_health", {})
    console.print(
        "\n[bold]4. Do controls, client tests, and test endpoints all function correctly?[/bold]"
    )
    if sys_health.get("system_healthy"):
        console.print(
            f"  ✅ [green]YES[/green] - {sys_health.get('message', 'System healthy')}"
        )
        console.print(
            f"     Confidence: {sys_health.get('confidence', 'unknown').upper()}"
        )
    else:
        console.print(
            f"  ❌ [red]NO[/red] - {sys_health.get('message', 'System issues detected')}"
        )
        console.print(
            f"     Confidence: {sys_health.get('confidence', 'unknown').upper()}"
        )
        if sys_health.get("errors"):
            console.print("     Errors:")
            for error in sys_health["errors"]:
                console.print(f"       • {error}")
        if sys_health.get("warnings"):
            console.print("     Warnings:")
            for warning in sys_health["warnings"][:5]:  # Limit to 5 warnings
                console.print(f"       • {warning}")

    # Overall Assessment
    console.print("\n[bold]Overall Assessment:[/bold]")
    if analysis.get("overall_success"):
        console.print("  ✅ [bold green]TEST PASSED - All criteria met[/bold green]")
    else:
        console.print(
            "  ⚠️  [bold yellow]TEST PARTIAL - Some criteria not met[/bold yellow]"
        )

    # Categories summary
    categories = analysis.get("categories", {})
    if categories:
        console.print("\n[dim]Test Categories:[/dim]")
        console.print(
            f"  • Vulnerability Detection: {categories.get('vulnerability_detection_count', 0)}"
        )
        console.print(
            f"  • Control Verification: {categories.get('control_verification_count', 0)}"
        )
        console.print(f"  • Baseline: {categories.get('baseline_count', 0)}")
        if categories.get("other_count", 0) > 0:
            console.print(f"  • Other: {categories.get('other_count', 0)}")


@app.command()
def run(
    vuln_id: str = typer.Argument(..., help="Vulnerability record ID"),
    test_bundle_id: Optional[str] = typer.Option(
        None,
        "--test-bundle-id",
        help="Specific test bundle ID (default: latest active)",
    ),
    work_dir: Optional[str] = typer.Option(
        None, "--work-dir", help="Working directory for test execution"
    ),
    keep_containers: bool = typer.Option(
        False, "--keep-containers", help="Keep containers running after test"
    ),
    no_upload: bool = typer.Option(
        False, "--no-upload", help="Skip uploading results to API"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable verbose logging"
    ),
):
    """
    Run a test execution for a vulnerability record.

    Fetches a test bundle, assembles workspace, executes docker-compose test,
    and uploads results.
    """
    _check_forge_available()

    console = Console()

    # Check prerequisites
    console.print("\n[bold cyan]Checking prerequisites...[/bold cyan]")
    prereqs = check_all_prerequisites()

    if not prereqs["all_passed"]:
        console.print("[bold red]Prerequisites check failed:[/bold red]")
        if not prereqs["docker_installed"]:
            console.print("  ❌ Docker not installed")
            console.print(get_docker_installation_instructions())
        if not prereqs["docker_running"]:
            console.print(f"  ❌ Docker daemon not running: {prereqs['docker_error']}")
        if not prereqs["docker_compose_available"]:
            console.print("  ❌ Docker Compose not available")
        if not prereqs["platform_compatible"]:
            console.print(f"  ❌ Platform not compatible: {prereqs['platform_info']}")
        if not prereqs["resources_sufficient"]:
            console.print(f"  ❌ Insufficient resources: {prereqs['resources']}")
        raise typer.Exit(1)

    console.print("  ✅ All prerequisites met")

    # Display system resources
    resources = detect_system_resources()
    console.print("\n[bold cyan]System Resources:[/bold cyan]")
    console.print(f"  CPU Cores: {resources['cpu_cores']}")
    console.print(f"  Memory: {resources['memory_gb']} GB")
    console.print(f"  Architecture: {resources['architecture']}")

    # Get API key and base URL
    api_key = _get_api_key()
    api_client = ApiClient()
    base_url = api_client.base_url

    # Initialize loader
    console.print("\n[bold cyan]Initializing test execution...[/bold cyan]")
    loader = TestBundleLoader(
        api_base_url=base_url, api_key=api_key, work_dir=work_dir, timeout=300.0
    )

    try:
        # Run test
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Executing test...", total=None)

            result = loader.run_full_test(
                vuln_id=vuln_id,
                test_bundle_id=test_bundle_id,
                resource_limits=resources,
                keep_containers=keep_containers,
                upload_results=not no_upload,
            )

            progress.update(task, completed=True)

        # Save status
        _save_test_status(result["test_id"], result)

        # Display results
        console.print("\n[bold green]Test execution completed![/bold green]")
        console.print(f"  Test ID: {result['test_id']}")
        console.print(f"  Status: {result['status']}")
        console.print(f"  Exit Code: {result['exit_code']}")
        console.print(f"  Duration: {result['duration_seconds']} seconds")
        console.print(f"  Results: {result['results_count']} findings")
        console.print(f"  Workspace: {result['workspace']}")

        if result.get("upload_success"):
            console.print("  ✅ Results uploaded to API")
        else:
            console.print("  ⚠️  Results not uploaded")

        # Display enhanced analysis if available
        if result.get("analysis"):
            _display_enhanced_analysis(console, result["analysis"])

        # Exit with appropriate code
        if result["status"] == "completed" and result["exit_code"] == 0:
            raise typer.Exit(0)
        else:
            raise typer.Exit(1)

    except Exception as e:
        console.print(f"\n[bold red]Test execution failed:[/bold red] {e}")
        if verbose:
            import traceback

            traceback.print_exc()
        raise typer.Exit(1)
    finally:
        loader.close()


@app.command()
def status(
    test_id: Optional[str] = typer.Option(None, "--test-id", help="Test execution ID"),
    follow: bool = typer.Option(False, "--follow", "-f", help="Follow status updates"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """
    Check status of a test execution.

    If --test-id is not provided, shows status of the most recent test.
    """
    console = Console()

    # Find test_id if not provided
    if not test_id:
        # Get most recent status file
        status_files = sorted(
            STATUS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True
        )
        if not status_files:
            console.print("[yellow]No test executions found.[/yellow]")
            raise typer.Exit(1)
        test_id = status_files[0].stem

    # Load status
    status_data = _load_test_status(test_id)
    if not status_data:
        console.print(f"[yellow]Test status not found: {test_id}[/yellow]")
        raise typer.Exit(1)

    if json_output:
        print(json.dumps(status_data, indent=2))
        return

    # Display status
    table = Table(title=f"Test Status: {test_id}")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    for key, value in status_data.items():
        if key != "workspace":  # Skip workspace in table
            table.add_row(key, str(value))

    console.print(table)

    if status_data.get("workspace"):
        console.print(f"\n[dim]Workspace: {status_data['workspace']}[/dim]")


@app.command()
def list(
    vuln_id: Optional[str] = typer.Option(
        None, "--vuln-id", help="Filter by vulnerability ID"
    ),
    status_filter: Optional[str] = typer.Option(
        None, "--status", help="Filter by status (completed, failed)"
    ),
    limit: int = typer.Option(10, "--limit", help="Maximum number of results"),
    all_tests: bool = typer.Option(
        False, "--all", help="Show all tests (including from API)"
    ),
):
    """
    List test executions.

    By default, shows local test executions. Use --all to include API results.
    """
    console = Console()

    # Get local status files
    status_files = sorted(
        STATUS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True
    )

    tests = []
    for status_file in status_files[:limit]:
        with open(status_file, "r") as f:
            test_data = json.load(f)

        # Apply filters
        if vuln_id and test_data.get("vuln_id") != vuln_id:
            continue
        if status_filter and test_data.get("status") != status_filter:
            continue

        tests.append(test_data)

    if not tests:
        console.print("[yellow]No test executions found.[/yellow]")
        return

    # Display table
    table = Table(title="Test Executions")
    table.add_column("Test ID", style="cyan")
    table.add_column("Vuln ID", style="blue")
    table.add_column("Status", style="green")
    table.add_column("Exit Code", justify="right")
    table.add_column("Duration", justify="right")
    table.add_column("Results", justify="right")
    table.add_column("Created", style="dim")

    for test in tests:
        created = test.get("started_at", test.get("updated_at", ""))
        if created:
            try:
                dt = datetime.fromtimestamp(int(created))
                created = dt.strftime("%Y-%m-%d %H:%M")
            except (ValueError, OSError):
                pass

        table.add_row(
            test.get("test_id", "unknown")[:16] + "...",
            test.get("vuln_id", "unknown")[:16] + "...",
            test.get("status", "unknown"),
            str(test.get("exit_code", "")),
            f"{test.get('duration_seconds', 0)}s",
            str(test.get("results_count", 0)),
            created or "unknown",
        )

    console.print(table)

    if all_tests:
        console.print(
            "\n[yellow]Note: --all flag not yet implemented (API integration pending)[/yellow]"
        )


@app.command()
def stop(
    test_id: Optional[str] = typer.Option(
        None, "--test-id", "-t", help="Test execution ID (defaults to most recent)"
    ),
):
    """
    Stop a running test execution.

    Stops Docker containers and updates status.

    If --test-id is not provided, stops the most recent test.
    """
    _check_forge_available()
    console = Console()

    # Find test_id if not provided
    if not test_id:
        # Get most recent status file
        status_files = sorted(
            STATUS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True
        )
        if not status_files:
            console.print("[yellow]No test executions found.[/yellow]")
            raise typer.Exit(1)
        test_id = status_files[0].stem
        console.print(f"[dim]Stopping most recent test: {test_id}[/dim]\n")

    # Load status
    status_data = _load_test_status(test_id)
    if not status_data:
        console.print(f"[yellow]Test status not found: {test_id}[/yellow]")
        raise typer.Exit(1)

    workspace = status_data.get("workspace")
    if not workspace:
        console.print(f"[yellow]No workspace found for test: {test_id}[/yellow]")
        raise typer.Exit(1)

    # Stop containers
    try:
        from app.test_instance.docker_executor import stop_containers

        console.print(f"[cyan]Stopping containers for test {test_id}...[/cyan]")
        stop_containers(workspace)
        console.print("[green]✅ Containers stopped[/green]")

        # Update status
        status_data["status"] = "stopped"
        status_data["stopped_at"] = datetime.utcnow().isoformat()
        _save_test_status(test_id, status_data)

    except Exception as e:
        console.print(f"[red]Error stopping containers: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def logs(
    test_id: Optional[str] = typer.Option(
        None, "--test-id", "-t", help="Test execution ID (defaults to most recent)"
    ),
    component: Optional[str] = typer.Option(
        None,
        "--component",
        help="Specific component (forge-endpoint, edge, waf, nuclei)",
    ),
    follow: bool = typer.Option(False, "--follow", "-f", help="Follow log output"),
    tail: Optional[int] = typer.Option(
        50,
        "--tail",
        help="Number of lines to show (default: 50). Omit value to use default.",
    ),
):
    """
    View logs from a test execution.

    Shows logs from Docker containers or from workspace if test is completed.

    If --test-id is not provided, shows logs from the most recent test.
    """
    _check_forge_available()
    console = Console()

    # Find test_id if not provided
    if not test_id:
        # Get most recent status file
        status_files = sorted(
            STATUS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True
        )
        if not status_files:
            console.print("[yellow]No test executions found.[/yellow]")
            raise typer.Exit(1)
        test_id = status_files[0].stem
        console.print(f"[dim]Using most recent test: {test_id}[/dim]\n")

    # Load status
    status_data = _load_test_status(test_id)
    if not status_data:
        console.print(f"[yellow]Test status not found: {test_id}[/yellow]")
        raise typer.Exit(1)

    workspace = status_data.get("workspace")
    if not workspace:
        console.print(f"[yellow]No workspace found for test: {test_id}[/yellow]")
        raise typer.Exit(1)

    try:
        from app.test_instance.docker_executor import get_container_logs

        # Get logs
        logs = get_container_logs(test_id, component)

        if not logs:
            console.print(f"[yellow]No logs found for test {test_id}[/yellow]")
            return

        # Display logs
        for comp, log_content in logs.items():
            if component and comp != component:
                continue

            console.print(f"\n[bold cyan]=== {comp} logs ===[/bold cyan]")
            lines = log_content.split("\n")
            tail_lines = tail if tail is not None else 50  # Use default if None
            if len(lines) > tail_lines:
                lines = lines[-tail_lines:]
            console.print("\n".join(lines))

    except Exception as e:
        console.print(f"[red]Error retrieving logs: {e}[/red]")
        raise typer.Exit(1)
