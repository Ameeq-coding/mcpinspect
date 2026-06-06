"""CLI entry-point — three commands: scan, audit, diff."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from mcpinspect import __version__

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
) -> None:
    """mcpinspect — offline-first, CI-native MCP security scanner."""


@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="MCP server URL (http+sse) or command (stdio).",
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
    probe: bool = typer.Option(
        True,
        help="Call tools with canary inputs to inspect responses.",
    ),
    drift: bool = typer.Option(
        True,
        help="Perform two-pass manifest comparison for rug-pull detection.",
    ),
) -> None:
    """Scan a live MCP server for security issues.

    Inspects tool descriptions, probes tool responses, and detects
    manifest drift — all offline, no LLM required.
    """
    console.print("[bold red]scan: not implemented[/bold red]")
    raise typer.Exit(code=1)


@app.command()
def audit(
    config_path: Path = typer.Argument(
        ...,
        help="Path to MCP config file (mcp.json, claude_desktop_config.json, etc.).",
        exists=True,
        readable=True,
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
) -> None:
    """Audit a local MCP config file (no network required).

    Checks for shell injection in commands, hardcoded secrets,
    and over-privileged flags — purely static analysis.
    """
    console.print("[bold red]audit: not implemented[/bold red]")
    raise typer.Exit(code=1)


@app.command()
def diff(
    baseline: Path = typer.Argument(
        ...,
        help="Path to baseline manifest snapshot (JSON).",
        exists=True,
        readable=True,
    ),
    current: Path = typer.Argument(
        ...,
        help="Path to current manifest snapshot (JSON).",
        exists=True,
        readable=True,
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
) -> None:
    """Diff two manifest snapshots for rug-pull / drift detection.

    Compares tool descriptions, schemas, and metadata between
    two saved manifests to detect post-deployment changes.
    """
    console.print("[bold red]diff: not implemented[/bold red]")
    raise typer.Exit(code=1)
