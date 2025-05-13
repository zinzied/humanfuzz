"""
HumanFuzz CLI - Command Line Interface for the HumanFuzz Library

This script provides a comprehensive command-line interface for using
the HumanFuzz library to scan websites for vulnerabilities.

© 2025 Powered By zinzied
"""

import os
import sys
import argparse
from datetime import datetime
import json
import logging
from rich.console import Console
from rich.table import Table
from rich.logging import RichHandler
from rich.prompt import Prompt, Confirm

# Initialize rich console
console = Console()

# ASCII Art for the banner
BANNER = """
██╗  ██╗██╗   ██╗███╗   ███╗ █████╗ ███╗   ██╗███████╗██╗   ██╗███████╗███████╗
██║  ██║██║   ██║████╗ ████║██╔══██╗████╗  ██║██╔════╝██║   ██║╚══███╔╝╚══███╔╝
███████║██║   ██║██╔████╔██║███████║██╔██╗ ██║█████╗  ██║   ██║  ███╔╝   ███╔╝
██╔══██║██║   ██║██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══╝  ██║   ██║ ███╔╝   ███╔╝
██║  ██║╚██████╔╝██║ ╚═╝ ██║██║  ██║██║ ╚████║██║     ╚██████╔╝███████╗███████╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚══════╝╚══════╝
"""

VERSION = "1.0.0"
DESCRIPTION = "Human-like Web Application Fuzzer"
COPYRIGHT = "© 2025 Powered By zinzied"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("humanfuzz")

def display_banner():
    """Display the HumanFuzz banner."""
    console.print(BANNER, style="bold blue")
    console.print(f"{DESCRIPTION} v{VERSION}", style="bold yellow")
    console.print(f"{COPYRIGHT}\n", style="italic")

def setup_parser():
    """Set up the argument parser with all available options."""
    parser = argparse.ArgumentParser(
        description="HumanFuzz - Human-like Web Application Fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  humanfuzz scan https://example.com
  humanfuzz scan https://example.com --depth 3 --pages 20
  humanfuzz scan https://example.com --auth --username admin --password secret
  humanfuzz api https://api.example.com --endpoints /users,/products
  humanfuzz report --input scan_results.json --output report.html

{COPYRIGHT}
"""
    )

    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a website for vulnerabilities")
    scan_parser.add_argument("url", help="URL of the website to scan")
    scan_parser.add_argument("--depth", "-d", type=int, default=2, help="Maximum crawl depth (default: 2)")
    scan_parser.add_argument("--pages", "-p", type=int, default=10, help="Maximum pages to crawl (default: 10)")
    scan_parser.add_argument("--visible", "-v", action="store_true", help="Show browser window")
    scan_parser.add_argument("--simulate", "-s", action="store_true", help="Run in simulation mode (no actual browser)")
    scan_parser.add_argument("--output", "-o", help="Output file for the report (default: auto-generated)")
    scan_parser.add_argument("--format", "-f", choices=["html", "json", "md"], default="html", help="Report format (default: html)")
    scan_parser.add_argument("--auth", "-a", action="store_true", help="Enable authentication")
    scan_parser.add_argument("--username", "-u", help="Username for authentication")
    scan_parser.add_argument("--password", "-pw", help="Password for authentication")
    scan_parser.add_argument("--login-url", "-l", help="Login URL (if different from main URL)")
    scan_parser.add_argument("--username-field", default="username", help="Username field name/ID (default: username)")
    scan_parser.add_argument("--password-field", default="password", help="Password field name/ID (default: password)")
    scan_parser.add_argument("--submit-button", help="Submit button selector (optional)")
    scan_parser.add_argument("--cookies", "-c", help="Cookies to use (format: name1=value1;name2=value2)")
    scan_parser.add_argument("--headers", help="Custom headers (format: name1=value1;name2=value2)")
    scan_parser.add_argument("--user-agent", help="Custom User-Agent")
    scan_parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    scan_parser.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds (default: 0)")
    scan_parser.add_argument("--bypass-cloudflare", action="store_true", help="Enable Cloudflare bypass using cloudscraper25")
    scan_parser.add_argument("--enhanced-http", action="store_true", help="Use urllib4-enhanced for HTTP requests")
    scan_parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    scan_parser.add_argument("--save-results", help="Save raw results to JSON file")

    # API scan command
    api_parser = subparsers.add_parser("api", help="Scan API endpoints")
    api_parser.add_argument("url", help="Base URL of the API")
    api_parser.add_argument("--endpoints", "-e", help="Comma-separated list of endpoints to scan")
    api_parser.add_argument("--endpoints-file", help="File containing endpoints (one per line)")
    api_parser.add_argument("--methods", "-m", default="GET,POST,PUT,DELETE", help="HTTP methods to use (comma-separated, default: GET,POST,PUT,DELETE)")
    api_parser.add_argument("--auth-type", choices=["none", "basic", "bearer", "api-key"], default="none", help="Authentication type")
    api_parser.add_argument("--auth-user", help="Username for Basic Auth")
    api_parser.add_argument("--auth-pass", help="Password for Basic Auth")
    api_parser.add_argument("--auth-token", help="Token for Bearer Auth")
    api_parser.add_argument("--api-key-name", default="X-API-Key", help="API key header name (default: X-API-Key)")
    api_parser.add_argument("--api-key-value", help="API key value")
    api_parser.add_argument("--headers", help="Custom headers (format: name1=value1;name2=value2)")
    api_parser.add_argument("--output", "-o", help="Output file for the report (default: auto-generated)")
    api_parser.add_argument("--format", "-f", choices=["html", "json", "md"], default="html", help="Report format (default: html)")
    api_parser.add_argument("--simulate", "-s", action="store_true", help="Run in simulation mode")
    api_parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    api_parser.add_argument("--save-results", help="Save raw results to JSON file")

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate a report from saved results")
    report_parser.add_argument("--input", "-i", required=True, help="Input JSON file with scan results")
    report_parser.add_argument("--output", "-o", required=True, help="Output report file")
    report_parser.add_argument("--format", "-f", choices=["html", "json", "md"], default="html", help="Report format (default: html)")
    report_parser.add_argument("--template", "-t", help="Custom template file for the report")

    # Version command
    subparsers.add_parser("version", help="Show version information")

    return parser
