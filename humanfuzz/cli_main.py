"""
Main entry point for the advanced HumanFuzz CLI.

This module provides the main entry point for the advanced HumanFuzz CLI.
"""

import os
import sys
import argparse
from datetime import datetime
import json
import logging
from rich.console import Console
from rich.logging import RichHandler

# Import the advanced CLI functionality
from humanfuzz.universal_scanner import fuzz_website, generate_html_report
from humanfuzz.cli_advanced import setup_parser, display_banner, VERSION, DESCRIPTION, COPYRIGHT

# Initialize rich console
console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("humanfuzz")

def handle_scan_command(args):
    """Handle the 'scan' command."""
    console.print(f"[bold green]Starting scan on {args.url}[/bold green]")

    # Handle output file
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"humanfuzz_report_{timestamp}.{args.format}"

    try:
        # Run the scan
        console.print("[bold blue]Starting scan...[/bold blue]")
        console.print("[yellow]This may take a while. Press Ctrl+C to cancel.[/yellow]")

        # Run the scan with simulation mode
        results, report_file = fuzz_website(
            url=args.url,
            max_depth=args.depth,
            max_pages=args.pages,
            headless=not args.visible,
            simulation=args.simulate
        )

        # Save raw results if requested
        if args.save_results and results:
            with open(args.save_results, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]Raw results saved to: {args.save_results}[/green]")

        # Show summary
        console.print(f"[bold green]Scan completed![/bold green]")
        console.print(f"Found [bold]{len(results)}[/bold] potential vulnerabilities")
        if report_file is not None:
            try:
                console.print(f"Report saved to: [bold]{os.path.abspath(report_file)}[/bold]")
            except TypeError:
                console.print(f"[bold red]Error: Invalid report file path[/bold red]")

    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user![/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error during scan: {str(e)}[/bold red]")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())

def handle_api_command(args):
    """Handle the 'api' command."""
    console.print(f"[bold green]Starting API scan on {args.url}[/bold green]")
    console.print("[yellow]API scanning functionality is not fully implemented yet.[/yellow]")
    console.print("[yellow]This is a placeholder for future implementation.[/yellow]")

def handle_report_command(args):
    """Handle the 'report' command."""
    console.print(f"[bold green]Generating report from {args.input} to {args.output}[/bold green]")

    # Load input data
    try:
        with open(args.input, 'r') as f:
            results = json.load(f)
    except Exception as e:
        console.print(f"[bold red]Error reading input file: {str(e)}[/bold red]")
        return

    # Generate report
    try:
        # Generate the report based on the format
        if args.format == "html":
            generate_html_report(results, args.output)
            console.print(f"[green]HTML report generated: {args.output}[/green]")
        elif args.format == "json":
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]JSON report generated: {args.output}[/green]")
        elif args.format == "md":
            # Simple markdown report
            with open(args.output, 'w') as f:
                f.write("# HumanFuzz Vulnerability Report\n\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                # Count by severity
                severity_counts = {"high": 0, "medium": 0, "low": 0}
                for finding in results:
                    severity = finding.get("severity", "low")
                    severity_counts[severity] += 1

                f.write("## Summary\n\n")
                f.write(f"- High: {severity_counts['high']}\n")
                f.write(f"- Medium: {severity_counts['medium']}\n")
                f.write(f"- Low: {severity_counts['low']}\n\n")

                f.write("## Findings\n\n")
                for i, finding in enumerate(results, 1):
                    f.write(f"### {i}. {finding.get('type', 'Unknown')} ({finding.get('severity', 'low')})\n\n")
                    f.write(f"- **URL**: {finding.get('url', 'Unknown')}\n")
                    f.write(f"- **Description**: {finding.get('description', 'No description')}\n")
                    f.write(f"- **Payload**: `{finding.get('payload', 'No payload')}`\n\n")

                f.write("\n\n© 2025 Powered By zinzied")

            console.print(f"[green]Markdown report generated: {args.output}[/green]")
    except Exception as e:
        console.print(f"[bold red]Error generating report: {str(e)}[/bold red]")
        import traceback
        console.print(traceback.format_exc())

def handle_version_command():
    """Handle the 'version' command."""
    console.print(f"HumanFuzz v{VERSION}")
    console.print(f"{DESCRIPTION}")
    console.print(f"{COPYRIGHT}")

def main():
    """Main entry point for the CLI."""
    # Display banner
    display_banner()

    # Set up argument parser
    parser = setup_parser()

    # Parse arguments
    args = parser.parse_args()

    # Handle commands
    if args.command == "scan":
        handle_scan_command(args)
    elif args.command == "api":
        handle_api_command(args)
    elif args.command == "report":
        handle_report_command(args)
    elif args.command == "version":
        handle_version_command()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
