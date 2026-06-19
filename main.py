"""DomainRadar CLI - scan a domain for subdomains."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from domainradar.scanner import Scanner
from domainradar.sources import (
    AlienVaultSource,
    AnubisSource,
    BruteForceSource,
    CrtShSource,
    HackerTargetSource,
    RapidDNSSource,
)
from domainradar.sources.base import normalize


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "output"
DEFAULT_WORDLIST = PROJECT_ROOT / "wordlists" / "subdomains.txt"


def build_sources(args) -> list:
    sources = []
    if not args.no_passive:
        sources.extend([
            CrtShSource(),
            HackerTargetSource(),
            RapidDNSSource(),
            AnubisSource(),
            AlienVaultSource(),
        ])
    if args.bruteforce:
        sources.append(
            BruteForceSource(
                wordlist=args.wordlist,
                threads=args.brute_threads,
                resolver_timeout=args.timeout,
            )
        )
    return sources


def save_results(result, outdir: Path, console: Console) -> None:
    outdir.mkdir(parents=True, exist_ok=True)

    # Use plain string concatenation - Path.with_suffix() would clobber the
    # TLD (treats ".com" as the existing suffix).
    txt_path = outdir / f"{result.domain}.txt"
    txt_path.write_text(
        "\n".join(result.sorted_subdomains()) + "\n",
        encoding="utf-8",
    )

    alive_path = outdir / f"{result.domain}.alive.txt"
    alive_lines = [f"{h}\t{','.join(ips)}" for h, ips in sorted(result.alive.items())]
    alive_path.write_text("\n".join(alive_lines) + ("\n" if alive_lines else ""), encoding="utf-8")

    json_path = outdir / f"{result.domain}.json"
    payload = {
        "domain": result.domain,
        "total": len(result.subdomains),
        "alive": len(result.alive),
        "subdomains": result.sorted_subdomains(),
        "per_source": {k: sorted(v) for k, v in result.per_source.items()},
        "resolved": result.resolved,
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    console.print(f"\n[bold green]Saved:[/bold green] {txt_path}")
    console.print(f"[bold green]Saved:[/bold green] {alive_path}")
    console.print(f"[bold green]Saved:[/bold green] {json_path}")


def render_summary(result, console: Console, show_list: bool) -> None:
    table = Table(title=f"DomainRadar - {result.domain}", show_header=True, header_style="bold cyan")
    table.add_column("Source", style="cyan")
    table.add_column("Found", justify="right", style="magenta")
    for src_name, hits in sorted(result.per_source.items()):
        table.add_row(src_name, str(len(hits)))
    table.add_row("[bold]Total (unique)[/bold]", f"[bold]{len(result.subdomains)}[/bold]")
    if result.resolved:
        table.add_row("[bold]Alive (A/AAAA)[/bold]", f"[bold]{len(result.alive)}[/bold]")
    console.print(table)

    if show_list and result.subdomains:
        console.print("\n[bold]Subdomains:[/bold]")
        for sub in result.sorted_subdomains():
            ips = result.resolved.get(sub, []) if result.resolved else []
            if ips:
                console.print(f"  [green]+[/green] {sub}  [dim]-> {', '.join(ips)}[/dim]")
            else:
                marker = "[yellow]?[/yellow]" if result.resolved else "[blue]*[/blue]"
                console.print(f"  {marker} {sub}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="domainradar",
        description="DomainRadar - enumerate subdomains from multiple passive + active sources",
    )
    parser.add_argument("domain", nargs="?", help="Root domain to scan, e.g. example.com")
    parser.add_argument(
        "-o", "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help=f"Directory for result files (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument("--no-passive", action="store_true", help="Disable passive sources")
    parser.add_argument("-b", "--bruteforce", action="store_true", help="Enable DNS brute force")
    parser.add_argument(
        "-w", "--wordlist",
        default=str(DEFAULT_WORDLIST),
        help=f"Wordlist for brute force (default: {DEFAULT_WORDLIST})",
    )
    parser.add_argument("--brute-threads", type=int, default=80, help="Threads for brute force (default: 80)")
    parser.add_argument("--no-resolve", action="store_true", help="Skip DNS validation of discovered subdomains")
    parser.add_argument("-t", "--timeout", type=float, default=3.0, help="DNS resolver timeout seconds (default: 3.0)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only print final list")
    parser.add_argument("--no-list", action="store_true", help="Suppress per-subdomain list, only show summary table")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    console = Console()

    if not args.domain:
        try:
            domain_input = console.input("[bold cyan]?[/bold cyan] Enter root domain: ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[red]Cancelled[/red]")
            return 1
    else:
        domain_input = args.domain

    domain = normalize(domain_input)
    if not domain or "." not in domain:
        console.print(f"[red]Invalid domain:[/red] {domain_input!r}")
        return 2

    sources = build_sources(args)
    if not sources:
        console.print("[red]No sources enabled.[/red]")
        return 2

    if not args.quiet:
        console.print(f"[bold]Target:[/bold] [cyan]{domain}[/cyan]")
        console.print(f"[bold]Sources:[/bold] {', '.join(s.name for s in sources)}")
        console.print(f"[bold]Resolve:[/bold] {'no' if args.no_resolve else 'yes'}")
        console.print()

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
        disable=args.quiet,
    )

    task_ids = {}

    def cb(event: str, payload):
        if event == "source_start":
            task_ids[payload["source"]] = progress.add_task(
                f"[cyan]{payload['source']}[/cyan] querying...", total=None
            )
        elif event == "source_done":
            tid = task_ids.get(payload["source"])
            if tid is not None:
                progress.update(
                    tid,
                    description=f"[green]{payload['source']}[/green] -> {payload['count']} hits",
                    completed=1, total=1,
                )
        elif event == "resolve_start":
            task_ids["__resolve__"] = progress.add_task(
                f"[yellow]Resolving {payload['count']} hosts...[/yellow]", total=None
            )
        elif event == "resolve_done":
            tid = task_ids.get("__resolve__")
            if tid is not None:
                progress.update(
                    tid,
                    description=f"[green]Resolved -> {payload['alive']} alive[/green]",
                    completed=1, total=1,
                )

    scanner = Scanner(
        sources=sources,
        resolve=not args.no_resolve,
        resolve_threads=80,
        resolve_timeout=args.timeout,
        progress_cb=cb,
    )

    started = time.time()
    with progress:
        result = scanner.scan(domain)
    elapsed = time.time() - started

    if args.quiet:
        for sub in result.sorted_subdomains():
            print(sub)
    else:
        render_summary(result, console, show_list=not args.no_list)
        console.print(f"\n[bold]Done in {elapsed:.1f}s[/bold]")
        save_results(result, Path(args.output_dir), console)

    return 0 if result.subdomains else 3


if __name__ == "__main__":
    sys.exit(main())
