"""
Universal Scanner for HumanFuzz.

This module provides a universal scanner that can be used to scan websites
for vulnerabilities using a headless browser.
"""

import os
import sys
import time
import random
import logging
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich import box

# Initialize rich console
console = Console()

class RichAnimationHandler:
    """Handler for rich animations during scanning."""

    def __init__(self):
        """Initialize the animation handler."""
        self.stats = {
            "Pages Crawled": 0,
            "Forms Fuzzed": 0,
            "Payloads Sent": 0,
            "Vulnerabilities Found": 0,
            "Elapsed Time": "00:00:00"
        }
        self.activity = "Initializing..."
        self.findings = []
        self.callbacks = {}
        self.live = None
        self.start_time = None

    def register_callback(self, event, callback):
        """Register a callback for an event."""
        self.callbacks[event] = callback

    def trigger_event(self, event, **kwargs):
        """Trigger an event."""
        if event in self.callbacks:
            self.callbacks[event](**kwargs)

    def update_stats(self, key, value=1, increment=True):
        """Update a statistic."""
        if key in self.stats:
            if increment:
                if key == "Elapsed Time":
                    # Calculate elapsed time
                    if self.start_time:
                        elapsed = datetime.now() - self.start_time
                        hours, remainder = divmod(elapsed.seconds, 3600)
                        minutes, seconds = divmod(remainder, 60)
                        self.stats[key] = f"{hours:02}:{minutes:02}:{seconds:02}"
                else:
                    self.stats[key] += value
            else:
                self.stats[key] = value

        self.trigger_event('stats_update')

    def update_activity(self, activity):
        """Update the current activity."""
        self.activity = activity
        self.trigger_event('activity_update')

    def report_finding(self, finding):
        """Report a vulnerability finding."""
        self.findings.append(finding)
        self.update_stats("Vulnerabilities Found")
        self.trigger_event('finding', finding=finding)

    def _create_layout(self):
        """Create the layout for the animation."""
        from rich.live import Live
        from rich.layout import Layout

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body")
        )

        layout["body"].split_row(
            Layout(name="stats", ratio=1),
            Layout(name="main", ratio=3)
        )

        layout["main"].split_column(
            Layout(name="progress", size=3),
            Layout(name="findings")
        )

        self.layout = layout
        self.live = Live(layout, refresh_per_second=4, screen=True)

    def _update_header_panel(self):
        """Update the header panel."""
        self.layout["header"].update(
            Panel(
                Align.center("[bold blue]HumanFuzz Universal Scanner[/bold blue]"),
                box=box.DOUBLE
            )
        )

    def _update_stats_panel(self):
        """Update the stats panel."""
        # Update elapsed time
        self.update_stats("Elapsed Time", increment=True)

        stats_table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
        stats_table.add_column("Metric", style="dim")
        stats_table.add_column("Value", justify="right")

        for key, value in self.stats.items():
            stats_table.add_row(key, str(value))

        self.layout["stats"].update(
            Panel(
                stats_table,
                title="Fuzzing Statistics",
                border_style="blue"
            )
        )

    def _update_progress_panel(self):
        """Update the progress panel."""
        self.layout["progress"].update(
            Panel(
                Text(self.activity),
                title="Current Activity",
                border_style="green"
            )
        )

    def _update_findings_panel(self):
        """Update the findings panel."""
        if not self.findings:
            self.layout["findings"].update(
                Panel(
                    Text("No vulnerabilities found yet."),
                    title="Latest Findings (0 total)",
                    border_style="yellow"
                )
            )
            return

        findings_table = Table(show_header=True, header_style="bold")
        findings_table.add_column("Type", style="dim")
        findings_table.add_column("Severity")
        findings_table.add_column("URL")

        # Show the latest 5 findings
        for finding in self.findings[-5:]:
            severity_style = "green"
            if finding["severity"] == "medium":
                severity_style = "yellow"
            elif finding["severity"] == "high":
                severity_style = "red bold"

            findings_table.add_row(
                finding.get("type", "unknown"),
                Text(finding.get("severity", "low"), style=severity_style),
                finding.get("url", "unknown")
            )

        self.layout["findings"].update(
            Panel(
                findings_table,
                title=f"Latest Findings ({len(self.findings)} total)",
                border_style="yellow"
            )
        )

    def start_animation(self):
        """Start the animation."""
        self.start_time = datetime.now()
        self._create_layout()

        # Update all panels initially
        self._update_header_panel()
        self._update_stats_panel()
        self._update_progress_panel()
        self._update_findings_panel()

        # Add a footer
        footer = Panel(
            Align.center("[bold]Press Ctrl+C to stop fuzzing[/bold]"),
            box=box.DOUBLE
        )

        # Start the live display
        self.live.start()

        # Register event callbacks
        self.register_callback('stats_update', lambda **kwargs: self._update_stats_panel())
        self.register_callback('activity_update', lambda **kwargs: self._update_progress_panel())
        self.register_callback('finding', lambda finding, **kwargs: self._update_findings_panel())

        # Initial update
        self._update_stats_panel()
        self._update_progress_panel()
        self._update_findings_panel()

    def stop_animation(self):
        """Stop the animation."""
        if self.live:
            self.live.stop()

def display_intro_animation():
    """Display an intro animation."""
    console.clear()

    # ASCII Art for the banner
    banner = """
██╗  ██╗██╗   ██╗███╗   ███╗ █████╗ ███╗   ██╗███████╗██╗   ██╗███████╗███████╗
██║  ██║██║   ██║████╗ ████║██╔══██╗████╗  ██║██╔════╝██║   ██║╚══███╔╝╚══███╔╝
███████║██║   ██║██╔████╔██║███████║██╔██╗ ██║█████╗  ██║   ██║  ███╔╝   ███╔╝
██╔══██║██║   ██║██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══╝  ██║   ██║ ███╔╝   ███╔╝
██║  ██║╚██████╔╝██║ ╚═╝ ██║██║  ██║██║ ╚████║██║     ╚██████╔╝███████╗███████╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚══════╝╚══════╝
"""

    subtitle = "Universal Web Application Fuzzer - Scan Any Website with Style"

    console.print(banner, style="bold blue")
    console.print(subtitle, style="bold yellow")

    # Show loading animation
    with console.status("[bold green]Initializing...", spinner="dots"):
        time.sleep(1)
        console.print("✅ Enhanced HTTP Requests using urllib4-enhanced", style="green")
        time.sleep(0.5)
        console.print("✅ Advanced Browser Automation with Playwright", style="green")
        time.sleep(0.5)

def fuzz_website(url, max_depth=2, max_pages=10, headless=True, simulation=False):
    """
    Fuzz a website with animated progress display.

    Args:
        url: The URL to fuzz
        max_depth: Maximum crawl depth
        max_pages: Maximum number of pages to crawl
        headless: Whether to run the browser in headless mode
        simulation: Whether to run in simulation mode (no actual browser)

    Returns:
        tuple: (results, report_file) - The scan results and the path to the report file
    """
    # Display intro animation
    display_intro_animation()

    # Create custom animation handler
    animation_handler = RichAnimationHandler()

    try:
        # Start animation
        animation_handler.start_animation()

        if simulation:
            # Simulation mode - no actual browser interaction
            simulate_fuzzing(url, max_depth, max_pages, animation_handler)
            report_file = os.path.join(os.getcwd(), f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
            results = animation_handler.findings

            # Generate a simple HTML report for simulation mode
            if report_file:
                generate_html_report(results, report_file)
        else:
            # Real fuzzing mode - import HumanFuzzer here to avoid circular imports
            from humanfuzz import HumanFuzzer

            # Initialize the fuzzer
            fuzzer = HumanFuzzer(headless=headless)

            # Start fuzzing session
            fuzzer.start_session(url)

            # Fuzz the site
            results = fuzzer.fuzz_site(max_depth=max_depth, max_pages=max_pages)

            # Generate report
            try:
                report_file = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                fuzzer.generate_report(report_file)
            except Exception as e:
                console.print(f"\n[bold red]Error generating report: {str(e)}[/bold red]")
                report_file = None

            # Close the fuzzer
            fuzzer.close()

    except KeyboardInterrupt:
        console.print("\n[bold red]Fuzzing interrupted by user![/bold red]")
        if not simulation and 'fuzzer' in locals():
            fuzzer.close()
        return [], None
    except Exception as e:
        console.print(f"\n[bold red]Error during fuzzing: {str(e)}[/bold red]")
        return [], None
    finally:
        # Stop animation
        animation_handler.stop_animation()

    # Return results and report file
    return results if 'results' in locals() else [], report_file if 'report_file' in locals() else None

def simulate_fuzzing(url, max_depth, max_pages, animation_handler):
    """
    Simulate fuzzing a website without actually using a browser.
    This is useful for demonstration purposes.

    Args:
        url: The URL to simulate fuzzing
        max_depth: Maximum crawl depth
        max_pages: Maximum pages to crawl
        animation_handler: Animation handler to update
    """
    # Sample vulnerability types for simulation
    vuln_types = ["xss", "sqli", "csrf", "idor", "sensitive_data", "broken_auth"]

    # Sample pages for the target website
    domain = url.split("//")[-1].split("/")[0]
    base_url = url.split("/")[0] + "//" + domain

    pages = [
        f"{base_url}/",
        f"{base_url}/login",
        f"{base_url}/products",
        f"{base_url}/about",
        f"{base_url}/contact",
        f"{base_url}/profile",
        f"{base_url}/cart",
        f"{base_url}/checkout",
        f"{base_url}/search",
        f"{base_url}/admin"
    ]

    # Limit pages based on max_pages
    pages = pages[:min(len(pages), max_pages)]

    # Update animation
    animation_handler.update_activity(f"Starting site-wide crawling (depth: {max_depth}, max pages: {max_pages})")
    time.sleep(2)

    # Simulate crawling
    animation_handler.update_activity(f"Crawling site structure...")
    time.sleep(2)

    # Update pages crawled
    animation_handler.update_stats("Pages Crawled", len(pages))
    animation_handler.update_activity(f"Discovered {len(pages)} pages, starting fuzzing")
    time.sleep(1)

    # Simulate fuzzing each page
    for i, page in enumerate(pages):
        # Update animation
        animation_handler.update_activity(f"Fuzzing page {i+1}/{len(pages)}: {page}")
        time.sleep(1)

        # Simulate finding forms
        num_forms = random.randint(1, 3)
        animation_handler.update_activity(f"Found {num_forms} forms on {page}")
        time.sleep(1)

        # Simulate fuzzing forms
        for j in range(num_forms):
            animation_handler.update_activity(f"Fuzzing form {j+1}/{num_forms} on {page}")
            animation_handler.update_stats("Forms Fuzzed", 1)

            # Simulate sending payloads
            num_payloads = random.randint(5, 15)
            animation_handler.update_stats("Payloads Sent", num_payloads)

            # Simulate finding vulnerabilities
            if random.random() < 0.3:  # 30% chance to find a vulnerability
                vuln_type = random.choice(vuln_types)
                severity = random.choice(["low", "medium", "high"])

                finding = {
                    "type": vuln_type,
                    "severity": severity,
                    "url": page,
                    "description": f"Potential {vuln_type} vulnerability found",
                    "payload": f"test_{vuln_type}_payload"
                }

                # Report finding
                animation_handler.report_finding(finding)

            time.sleep(1)

    # Simulate completing fuzzing
    animation_handler.update_activity("Fuzzing completed")
    time.sleep(2)

def generate_html_report(findings, output_file=None):
    """
    Generate a simple HTML report for simulation mode.

    Args:
        findings: List of vulnerability findings
        output_file: Path to the output file (optional)
    """
    if output_file is None:
        return
    # Count findings by severity
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = finding.get("severity", "low")
        severity_counts[severity] += 1

    # Generate HTML content
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HumanFuzz - Vulnerability Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f8f9fa;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            border-radius: 5px;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }}
        .logo {{
            font-size: 24px;
            font-weight: bold;
            color: #3498db;
        }}
        .summary {{
            display: flex;
            justify-content: space-between;
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .severity-count {{
            text-align: center;
            padding: 10px;
            border-radius: 5px;
            margin: 0 5px;
            flex: 1;
        }}
        .high {{
            background-color: #f8d7da;
            color: #721c24;
        }}
        .medium {{
            background-color: #fff3cd;
            color: #856404;
        }}
        .low {{
            background-color: #d1ecf1;
            color: #0c5460;
        }}
        .finding {{
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f8f9fa;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            text-align: center;
            color: #7f8c8d;
            font-size: 14px;
        }}
        .animated {{
            animation: fadeIn 0.5s ease-in;
        }}
        @keyframes fadeIn {{
            from {{ opacity: 0; }}
            to {{ opacity: 1; }}
        }}
    </style>
</head>
<body>
    <div class="container animated">
        <div class="header">
            <div class="logo">HumanFuzz</div>
            <div>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>

        <h1>Vulnerability Report</h1>

        <div class="summary">
            <div class="severity-count high">
                <h3>High</h3>
                <p>{severity_counts['high']}</p>
            </div>
            <div class="severity-count medium">
                <h3>Medium</h3>
                <p>{severity_counts['medium']}</p>
            </div>
            <div class="severity-count low">
                <h3>Low</h3>
                <p>{severity_counts['low']}</p>
            </div>
        </div>

        <h2>Vulnerability Findings</h2>

        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>URL</th>
                    <th>Payload</th>
                </tr>
            </thead>
            <tbody>
"""

    # Add findings to the table
    for finding in findings:
        severity_class = finding.get("severity", "low")
        html_content += f"""
                <tr>
                    <td>{finding.get("type", "unknown")}</td>
                    <td><span class="{severity_class}">{finding.get("severity", "low")}</span></td>
                    <td>{finding.get("url", "unknown")}</td>
                    <td><code>{finding.get("payload", "unknown")}</code></td>
                </tr>
"""

    html_content += """
            </tbody>
        </table>

        <div class="footer">
            <p>Generated by HumanFuzz - A human-like web application fuzzing library</p>
            <p>© 2025 Powered By zinzied</p>
        </div>
    </div>

    <script>
        // Add some simple animations
        document.addEventListener('DOMContentLoaded', function() {
            const findings = document.querySelectorAll('.finding');
            findings.forEach((finding, index) => {
                finding.style.animationDelay = `${index * 0.1}s`;
            });
        });
    </script>
</body>
</html>
"""

    # Write the HTML report
    with open(output_file, 'w') as f:
        f.write(html_content)

    if output_file:
        print(f"Report saved to: {os.path.abspath(output_file)}")
