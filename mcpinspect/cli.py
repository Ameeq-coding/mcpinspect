"""CLI entry-point — three commands: scan, audit, diff."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import anyio
import typer
from rich.console import Console
from rich.table import Table

from mcpinspect import __version__
from mcpinspect.protocol.client import MCPClient
from mcpinspect.scanner.drift import DriftDetector
from mcpinspect.scanner.engine import ScanConfig, ScanEngine
from mcpinspect.transport import TransportError, get_transport

app = typer.Typer(
    name="mcpinspect",
    help=(
        "Offline-first MCP security scanner.\n\n"
        "Scans tool descriptions, tool RESPONSES, and manifest drift — "
        "all in one offline pass, with zero LLM API dependency."
    ),
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"mcpinspect {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable debug logging.",
    ),
) -> None:
    """mcpinspect — offline-first, CI-native MCP security scanner."""
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(name)s %(levelname)s: %(message)s",
        )


# ======================================================================
# scan
# ======================================================================

@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="MCP server URL (http+sse) or command (stdio).",
    ),
    probe: bool = typer.Option(
        True,
        "--probe/--no-probe",
        help="Call tools with canary inputs to inspect responses.",
    ),
    drift: bool = typer.Option(
        True,
        "--drift/--no-drift",
        help="Perform two-pass manifest comparison for rug-pull detection.",
    ),
    timeout: float = typer.Option(
        30.0,
        "--timeout",
        help="Timeout in seconds for probes and requests.",
    ),
    output_format: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal | json | sarif",
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write results to file instead of stdout.",
    ),
    headers: Optional[list[str]] = typer.Option(
        None,
        "--header",
        "-H",
        help="Custom header in format 'Key: Value'.",
    ),
) -> None:
    """Scan a live MCP server for security issues.

    Inspects tool descriptions, probes tool responses, and detects
    manifest drift — all offline, no LLM required.
    """
    header_dict = {}
    if headers:
        for h in headers:
            if ":" in h:
                k, v = h.split(":", 1)
                header_dict[k.strip()] = v.strip()

    config = ScanConfig(
        target=target,
        probe=probe,
        drift_check=drift,
        timeout=timeout,
        output_format=output_format,
        headers=header_dict,
    )
    anyio.run(_scan_async, config, output_file)


async def _scan_async(
    config: ScanConfig,
    output_file: Path | None,
) -> None:
    engine = ScanEngine(config)

    console.print(f"\n[bold cyan]mcpinspect[/bold cyan] scanning [yellow]{config.target}[/yellow]\n")

    try:
        with console.status("[bold green]Running scan engine…"):
            results, diffs, score = await engine.run()
    except TransportError as exc:
        console.print(f"[bold red]Connection failed:[/bold red] {exc}")
        raise typer.Exit(code=2)
    except Exception as exc:
        console.print(f"[bold red]Scan failed:[/bold red] {exc}")
        raise typer.Exit(code=2)

    if config.output_format == "json" or output_file:
        output_data = {
            "score": score.score,
            "verdict": score.verdict,
            "total_checks": score.total_checks_run,
            "findings": {k.value: v for k, v in score.findings.items()},
            "drift_detected": score.drift_detected,
            "diffs": [
                {
                    "tool_name": d.tool_name,
                    "field": d.field,
                    "before": d.before,
                    "after": d.after,
                    "severity": d.severity.value,
                }
                for d in diffs
            ],
            "results": [
                {
                    "check_id": r.check_id,
                    "title": r.title,
                    "severity": r.severity.value,
                    "passed": r.passed,
                    "finding": r.finding,
                    "evidence": r.evidence,
                    "location": r.location,
                    "remediation": r.remediation,
                }
                for r in results
            ],
        }
        json_str = json.dumps(output_data, indent=2, ensure_ascii=False)
        if output_file:
            output_file.write_text(json_str + "\n", encoding="utf-8")
            console.print(f"  [green]✓[/green] Written to {output_file}")
        else:
            console.print_json(data=output_data)
    else:
        # Terminal format
        console.print(f"  [bold]Verdict:[/bold] {score.verdict} (Score: {score.score})")
        console.print(f"  [bold]Checks run:[/bold] {score.total_checks_run}")
        
        if score.drift_detected:
            console.print("\n[bold red]DRIFT DETECTED![/bold red]")
            for d in diffs:
                console.print(f"  • {d.tool_name} ({d.field} changed)")
        
        failed_results = [r for r in results if not r.passed]
        if failed_results:
            table = Table(title="\nFindings", show_header=True, header_style="bold magenta")
            table.add_column("Severity")
            table.add_column("ID")
            table.add_column("Location")
            table.add_column("Finding")

            for r in failed_results:
                sev_color = "red" if r.severity.value == "critical" else "yellow" if r.severity.value == "high" else "blue"
                table.add_row(
                    f"[{sev_color}]{r.severity.value.upper()}[/{sev_color}]",
                    r.check_id,
                    r.location,
                    r.finding,
                )
            console.print(table)
        else:
            console.print("\n[bold green]No issues found![/bold green]")

    console.print()
    if score.verdict == "CRITICAL":
        raise typer.Exit(code=2)
    elif score.verdict == "WARN":
        raise typer.Exit(code=1)
    else:
        raise typer.Exit(code=0)


# ======================================================================
# audit
# ======================================================================

@app.command()
def audit(
    config_path: Path = typer.Argument(
        ...,
        help="Path to MCP config file (mcp.json, claude_desktop_config.json, etc.).",
        exists=True,
        readable=True,
    ),
    discover: bool = typer.Option(
        False,
        "--discover",
        help="Auto-discover config files.",
    ),
    output_format: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal | json | sarif",
    ),
) -> None:
    """Audit a local MCP config file (no network required).

    Checks for shell injection in commands, hardcoded secrets,
    and over-privileged flags — purely static analysis.
    """
    console.print("[bold red]audit: not implemented[/bold red]")
    raise typer.Exit(code=1)


# ======================================================================
# diff
# ======================================================================

@app.command()
def diff(
    target: str = typer.Argument(
        ...,
        help="MCP server URL (http+sse) or command (stdio).",
    ),
    interval: float = typer.Option(
        60.0,
        "--interval",
        help="Seconds to wait between fetches.",
    ),
) -> None:
    """Diff two manifest snapshots for rug-pull / drift detection.

    Fetches manifest, waits, fetches again, and reports drift.
    """
    anyio.run(_diff_async, target, interval)


async def _diff_async(target: str, interval: float) -> None:
    transport = get_transport(target)
    try:
        await transport.connect()
        client = MCPClient(transport)
        detector = DriftDetector(client, interval_seconds=interval)
        
        console.print(f"Fetching first manifest for {target}...")
        diffs = await detector.detect()
        
        if diffs:
            console.print("[bold red]Drift detected![/bold red]")
            for d in diffs:
                console.print(f"Tool: {d.tool_name}, Field: {d.field}")
                console.print(f"Before: {d.before}")
                console.print(f"After: {d.after}")
                console.print("---")
            raise typer.Exit(code=2)
        else:
            console.print("[bold green]No drift detected.[/bold green]")
            raise typer.Exit(code=0)
            
    except TransportError as exc:
        console.print(f"[bold red]Connection failed:[/bold red] {exc}")
        raise typer.Exit(code=2)
    finally:
        await transport.disconnect()
