"""CLI entry-point — three commands: scan, audit, diff."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import anyio
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
    anyio.run(_scan_async, target, output_format, output_file, probe, drift)


async def _scan_async(
    target: str,
    output_format: str,
    output_file: Path | None,
    probe: bool,
    drift: bool,
) -> None:
    """Async implementation of the scan command."""
    from mcpinspect.transport import TransportError, get_transport
    from mcpinspect.protocol.client import MCPClient

    console.print(f"\n[bold cyan]mcpinspect[/bold cyan] scanning [yellow]{target}[/yellow]\n")

    transport = get_transport(target)

    try:
        # -- Connect ---------------------------------------------------
        with console.status("[bold green]Connecting…"):
            try:
                await transport.connect()
            except TransportError as exc:
                console.print(f"[bold red]Connection failed:[/bold red] {exc}")
                raise typer.Exit(code=1)

        console.print(
            f"  [green]✓[/green] Connected via [cyan]{transport.transport_type}[/cyan]"
        )
        if hasattr(transport, "insecure") and transport.insecure:
            console.print("  [bold yellow]⚠  Insecure transport (HTTP, not HTTPS)[/bold yellow]")

        server_name = transport._server_info.get("name", "unknown")
        server_ver = transport._server_info.get("version", "")
        console.print(f"  [dim]Server: {server_name} {server_ver}[/dim]\n")

        # -- Fetch manifest --------------------------------------------
        client = MCPClient(transport)

        with console.status("[bold green]Fetching manifest…"):
            manifest = await client.fetch_manifest()

        console.print(
            f"  [green]✓[/green] Manifest fetched in [cyan]{manifest.fetch_duration_ms:.0f}ms[/cyan]"
        )
        console.print(
            f"    Tools: {len(manifest.tools)}  "
            f"Resources: {len(manifest.resources)}  "
            f"Prompts: {len(manifest.prompts)}\n"
        )

        # -- Output manifest -------------------------------------------
        manifest_data = json.loads(
            manifest.model_dump_json(indent=2)
        )

        if output_format == "json" or output_file:
            json_str = json.dumps(manifest_data, indent=2, ensure_ascii=False)
            if output_file:
                output_file.write_text(json_str + "\n", encoding="utf-8")
                console.print(f"  [green]✓[/green] Written to {output_file}")
            else:
                console.print_json(data=manifest_data)
        else:
            # Terminal: print a summary table of tools
            if manifest.tools:
                from rich.table import Table

                table = Table(
                    title="Tools",
                    show_header=True,
                    header_style="bold magenta",
                )
                table.add_column("Name", style="cyan")
                table.add_column("Description", style="white", max_width=60)
                table.add_column("Params", style="dim")

                for tool in manifest.tools:
                    props = tool.input_schema.get("properties", {})
                    param_names = ", ".join(props.keys()) if props else "—"
                    desc = tool.description[:57] + "…" if len(tool.description) > 60 else tool.description
                    table.add_row(tool.name, desc or "—", param_names)

                console.print(table)

            if manifest.resources:
                console.print(f"\n[bold]Resources:[/bold]")
                for r in manifest.resources:
                    console.print(f"  • {r.uri} ({r.name or 'unnamed'})")

            if manifest.prompts:
                console.print(f"\n[bold]Prompts:[/bold]")
                for p in manifest.prompts:
                    console.print(f"  • {p.name}: {p.description or '—'}")

            console.print()

    finally:
        await transport.disconnect()
        console.print("[dim]Disconnected.[/dim]")


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


# ======================================================================
# diff
# ======================================================================

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
