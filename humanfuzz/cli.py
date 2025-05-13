"""
Command-line interface for HumanFuzz.

This module provides two CLI interfaces:
1. A simple Click-based CLI for basic usage
2. An advanced argparse-based CLI with more features

The advanced CLI is available through the 'humanfuzz_cli' command.
"""

import logging
import sys
import os
import click
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn

from humanfuzz import HumanFuzzer

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("humanfuzz")

console = Console()

@click.group()
@click.version_option()
def cli():
    """HumanFuzz - A human-like web application fuzzing tool."""
    pass

@cli.command()
@click.argument("url")
@click.option("--output", "-o", default="report.html", help="Output file for the report.")
@click.option("--depth", "-d", default=3, help="Maximum crawl depth.")
@click.option("--max-pages", "-m", default=50, help="Maximum number of pages to crawl.")
@click.option("--headless/--no-headless", default=True, help="Run browser in headless mode.")
@click.option("--browser", "-b", default="chromium", type=click.Choice(["chromium", "firefox", "webkit"]), help="Browser to use.")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
def fuzz(url, output, depth, max_pages, headless, browser, verbose):
    """Fuzz a website starting from the given URL."""
    if verbose:
        logger.setLevel(logging.DEBUG)

    console.print(f"[bold blue]HumanFuzz[/bold blue] - Starting fuzzing session")
    console.print(f"Target URL: [bold]{url}[/bold]")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[green]Initializing fuzzer...", total=None)

            # Initialize the fuzzer
            fuzzer = HumanFuzzer(headless=headless, browser_type=browser)

            # Start the fuzzing session
            progress.update(task, description="[green]Starting browser session...")
            fuzzer.start_session(url)

            # Fuzz the site
            progress.update(task, description=f"[green]Fuzzing site (max depth: {depth})...")
            findings = fuzzer.fuzz_site(max_depth=depth, max_pages=max_pages)

            # Generate the report
            progress.update(task, description="[green]Generating report...")
            fuzzer.generate_report(output)

            # Close the fuzzer
            progress.update(task, description="[green]Cleaning up...")
            fuzzer.close()

        # Print summary
        console.print("\n[bold green]Fuzzing completed![/bold green]")
        console.print(f"Found [bold]{len(findings)}[/bold] potential vulnerabilities")
        console.print(f"Report saved to: [bold]{os.path.abspath(output)}[/bold]")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        if verbose:
            console.print_exception()
        sys.exit(1)

@cli.command()
@click.argument("url")
@click.option("--username", "-u", help="Username for authentication.")
@click.option("--password", "-p", help="Password for authentication.")
@click.option("--username-field", default="username", help="Name or ID of the username field.")
@click.option("--password-field", default="password", help="Name or ID of the password field.")
@click.option("--output", "-o", default="report.html", help="Output file for the report.")
@click.option("--headless/--no-headless", default=True, help="Run browser in headless mode.")
@click.option("--browser", "-b", default="chromium", type=click.Choice(["chromium", "firefox", "webkit"]), help="Browser to use.")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
def authenticated_fuzz(url, username, password, username_field, password_field, output, headless, browser, verbose):
    """Fuzz a website with authentication."""
    if verbose:
        logger.setLevel(logging.DEBUG)

    if not username or not password:
        console.print("[bold red]Error:[/bold red] Username and password are required for authenticated fuzzing.")
        sys.exit(1)

    console.print(f"[bold blue]HumanFuzz[/bold blue] - Starting authenticated fuzzing session")
    console.print(f"Target URL: [bold]{url}[/bold]")
    console.print(f"Username: [bold]{username}[/bold]")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[green]Initializing fuzzer...", total=None)

            # Initialize the fuzzer
            fuzzer = HumanFuzzer(headless=headless, browser_type=browser)

            # Start the fuzzing session
            progress.update(task, description="[green]Starting browser session...")
            fuzzer.start_session(url)

            # Authenticate
            progress.update(task, description="[green]Authenticating...")
            auth_success = fuzzer.authenticate(
                login_url=url,
                username_field=username_field,
                password_field=password_field,
                username=username,
                password=password
            )

            if not auth_success:
                progress.stop()
                console.print("[bold red]Error:[/bold red] Authentication failed.")
                sys.exit(1)

            # Fuzz the site
            progress.update(task, description="[green]Fuzzing authenticated pages...")
            findings = fuzzer.fuzz_site()

            # Generate the report
            progress.update(task, description="[green]Generating report...")
            fuzzer.generate_report(output)

            # Close the fuzzer
            progress.update(task, description="[green]Cleaning up...")
            fuzzer.close()

        # Print summary
        console.print("\n[bold green]Fuzzing completed![/bold green]")
        console.print(f"Found [bold]{len(findings)}[/bold] potential vulnerabilities")
        console.print(f"Report saved to: [bold]{os.path.abspath(output)}[/bold]")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        if verbose:
            console.print_exception()
        sys.exit(1)

def main():
    """Main entry point for the CLI."""
    cli()

if __name__ == "__main__":
    main()
