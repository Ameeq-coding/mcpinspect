"""Rich terminal output formatting for mcpinspect."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcpinspect import __version__
from mcpinspect.checks.base import CheckResult
from mcpinspect.scanner.drift import DescriptionDiff
from mcpinspect.scanner.scoring import ScanScore

console = Console()


def print_terminal_report(
    target: str,
    timestamp: str,
    score: ScanScore,
    results: list[CheckResult],
    diffs: list[DescriptionDiff],
    run_time_sec: float,
) -> None:
    """Print the final scan report to the terminal in a structured way."""
    
    # 1. Header
    console.print(f"\n[bold cyan]mcpinspect v{__version__}[/bold cyan] | [yellow]{target}[/yellow] | [dim]{timestamp}[/dim]\n")

    # 2. Verdict panel
    if score.verdict == "SAFE":
        color = "green"
    elif score.verdict == "WARN":
        color = "yellow"
    else:
        color = "red"

    verdict_text = f"Verdict: [bold {color}]{score.verdict}[/bold {color}]  |  Score: [bold]{score.score:.1f}[/bold]/100"
    console.print(Panel(verdict_text, title="Scan Result", border_style=color))

    # 3. Drift detected panel
    if diffs:
        console.print("\n[bold red on white] DRIFT DETECTED [/bold red on white]")
        for d in diffs:
            drift_table = Table(title=f"Tool: {d.tool_name} ({d.field})", show_header=True, header_style="bold red")
            drift_table.add_column("Before", style="dim", width=40)
            drift_table.add_column("After", style="red", width=40)
            drift_table.add_row(d.before, d.after)
            console.print(drift_table)

    # 4. Findings table
    failed_results = [r for r in results if not r.passed]
    if failed_results:
        table = Table(title="Findings", show_header=True, header_style="bold magenta")
        table.add_column("ID")
        table.add_column("Sev")
        table.add_column("Location", style="cyan")
        table.add_column("Finding")

        for r in failed_results:
            sev_color = "red" if r.severity.value == "critical" else "yellow" if r.severity.value == "high" else "blue"
            table.add_row(
                r.check_id,
                f"[{sev_color}]{r.severity.value.upper()}[/{sev_color}]",
                r.location,
                r.finding,
            )
        console.print(table)

    # 5. Evidence blocks (for CRITICAL only)
    critical_results = [r for r in failed_results if r.severity.value == "critical"]
    if critical_results:
        console.print("\n[bold red]Critical Evidence:[/bold red]")
        for r in critical_results:
            console.print(f"  [bold]{r.check_id}[/bold] at [cyan]{r.location}[/cyan]:")
            console.print(f"  [dim]{r.evidence}[/dim]\n")

    # 6. Probe status
    console.print()
    if score.probe_enabled:
        console.print("[dim]Probe status: Probes enabled | Response checks ran[/dim]")
    else:
        console.print("[dim]Probe status: Probes disabled (--no-probe)[/dim]")

    # 7. Footer
    from mcpinspect.checks.base import Severity
    c = score.findings.get(Severity.CRITICAL, 0)
    h = score.findings.get(Severity.HIGH, 0)
    m = score.findings.get(Severity.MEDIUM, 0)
    low_count = score.findings.get(Severity.LOW, 0)
    summary = f"{c} Critical | {h} High | {m} Medium | {low_count} Low"
    console.print(f"\n[bold]Summary:[/bold] {summary}  |  [dim]Runtime: {run_time_sec:.1f}s[/dim]\n")
