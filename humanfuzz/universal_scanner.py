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
                # Create a timestamped report filename
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                report_dir = os.path.abspath(os.getcwd())
                report_file = os.path.join(report_dir, f"report_{timestamp}.html")

                # Ensure the directory exists
                os.makedirs(os.path.dirname(report_file), exist_ok=True)

                # Generate the report
                console.print(f"\n[bold blue]Generating report to: {report_file}[/bold blue]")
                fuzzer.generate_report(report_file)

                # Verify the report was created
                if os.path.exists(report_file):
                    console.print(f"[bold green]Report successfully saved to: {report_file}[/bold green]")
                else:
                    console.print(f"[bold yellow]Warning: Report file was not found at: {report_file}[/bold yellow]")
                    report_file = None
            except Exception as e:
                console.print(f"\n[bold red]Error generating report: {str(e)}[/bold red]")
                import traceback
                console.print(f"[red]{traceback.format_exc()}[/red]")
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
    # Create realistic vulnerability types with detailed information
    vulnerability_templates = {
        "xss": {
            "name": "Cross-Site Scripting (XSS)",
            "payloads": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg/onload=alert('XSS')>",
                "'-alert('XSS')-'"
            ],
            "descriptions": [
                "Reflected XSS vulnerability allows attackers to execute arbitrary JavaScript in users' browsers",
                "Stored XSS vulnerability allows persistent JavaScript injection",
                "DOM-based XSS vulnerability in client-side code",
                "XSS vulnerability in form input not properly sanitized",
                "XSS vulnerability bypassing HTML encoding"
            ],
            "evidence": [
                "Response contains the injected script tag without encoding",
                "JavaScript execution confirmed in the context of the application",
                "Alert dialog displayed when payload is processed",
                "Payload reflected in the response without sanitization",
                "DOM manipulation observed after payload execution"
            ]
        },
        "sqli": {
            "name": "SQL Injection",
            "payloads": [
                "' OR 1=1 --",
                "'; DROP TABLE users; --",
                "1' UNION SELECT username,password FROM users --",
                "admin' --",
                "' OR '1'='1"
            ],
            "descriptions": [
                "SQL injection vulnerability allows unauthorized database access",
                "Blind SQL injection vulnerability in query parameter",
                "Time-based SQL injection vulnerability detected",
                "SQL injection vulnerability allows authentication bypass",
                "SQL injection vulnerability enables data extraction"
            ],
            "evidence": [
                "Database error message exposed in response",
                "Query results show unauthorized data access",
                "Authentication bypassed with SQL injection payload",
                "Application behavior changes with different SQL syntax",
                "Database schema information leaked in error messages"
            ]
        },
        "csrf": {
            "name": "Cross-Site Request Forgery (CSRF)",
            "payloads": [
                "<img src='https://example.com/api/action?param=value'>",
                "<form id='csrf' action='https://example.com/api/action' method='POST'><input type='hidden' name='param' value='value'></form><script>document.getElementById('csrf').submit()</script>",
                "<iframe src='https://example.com/api/action?param=value'></iframe>",
                "<script>fetch('https://example.com/api/action', {method: 'POST', credentials: 'include', body: 'param=value'})</script>",
                "<a href='https://example.com/api/action?param=value' target='_blank'>Click me</a>"
            ],
            "descriptions": [
                "CSRF vulnerability allows unauthorized actions on behalf of authenticated users",
                "Missing CSRF token in sensitive form submission",
                "CSRF protection bypass in user profile update",
                "CSRF vulnerability in account settings modification",
                "CSRF vulnerability in password change functionality"
            ],
            "evidence": [
                "Form submission lacks anti-CSRF token",
                "Same-site cookie restrictions not implemented",
                "No origin validation on sensitive requests",
                "Action performed successfully without proper validation",
                "Missing SameSite cookie attribute"
            ]
        },
        "idor": {
            "name": "Insecure Direct Object Reference",
            "payloads": [
                "/api/users/2",
                "/profile?id=1001",
                "/download?file=../../../etc/passwd",
                "/account/settings?user_id=admin",
                "/documents?doc_id=12345"
            ],
            "descriptions": [
                "IDOR vulnerability allows accessing other users' data",
                "IDOR vulnerability in API endpoint exposes sensitive information",
                "IDOR vulnerability allows unauthorized resource access",
                "IDOR vulnerability in user profile enables account takeover",
                "IDOR vulnerability in document management system"
            ],
            "evidence": [
                "Changing resource ID in request returns another user's data",
                "API returns sensitive data without proper authorization checks",
                "Unauthorized access to resource confirmed",
                "Application does not validate resource ownership",
                "Access control check bypassed by direct reference manipulation"
            ]
        },
        "sensitive_data": {
            "name": "Sensitive Data Exposure",
            "payloads": [
                "/api/debug",
                "/admin/logs",
                "/?debug=true",
                "/api/users?full=true",
                "/system/status"
            ],
            "descriptions": [
                "API endpoint leaks sensitive user information",
                "Debug mode exposes internal application details",
                "Error messages reveal database structure",
                "Sensitive data transmitted over unencrypted channel",
                "Directory listing enabled exposing configuration files"
            ],
            "evidence": [
                "Response contains plaintext credentials",
                "Internal IP addresses and hostnames disclosed",
                "Stack traces exposed in error responses",
                "PII data transmitted without encryption",
                "Source code fragments visible in response"
            ]
        },
        "broken_auth": {
            "name": "Broken Authentication",
            "payloads": [
                "admin:admin",
                "password:password123",
                "/login?bypass=true",
                "/reset-password?email=victim@example.com",
                "/api/auth?remember=true"
            ],
            "descriptions": [
                "Weak password policy allows brute force attacks",
                "Session fixation vulnerability in authentication flow",
                "Password reset functionality vulnerable to account takeover",
                "Missing rate limiting on login attempts",
                "Session tokens transmitted over unencrypted channel"
            ],
            "evidence": [
                "Multiple login attempts without lockout",
                "Session token remains valid after password change",
                "Password reset link without proper validation",
                "Default credentials accepted",
                "Session token predictable or insufficiently random"
            ]
        }
    }

    # Generate realistic pages based on the target URL
    domain = url.split("//")[-1].split("/")[0]
    base_url = url.split("/")[0] + "//" + domain

    # Create a more realistic site structure based on common web applications
    common_paths = [
        "/",
        "/login",
        "/register",
        "/products",
        "/product-details",
        "/cart",
        "/checkout",
        "/account",
        "/profile",
        "/settings",
        "/admin",
        "/api/users",
        "/api/products",
        "/search",
        "/contact",
        "/about",
        "/reset-password",
        "/blog",
        "/faq",
        "/terms",
        "/privacy"
    ]

    # Generate pages with query parameters for more realistic testing
    pages = []
    for path in common_paths[:max_pages]:
        pages.append(f"{base_url}{path}")

        # Add some pages with query parameters for more realistic testing
        if path == "/search":
            pages.append(f"{base_url}{path}?q=test")
        elif path == "/product-details":
            pages.append(f"{base_url}{path}?id=1")
        elif path == "/api/users":
            pages.append(f"{base_url}{path}?id=1001")

    # Limit pages based on max_pages
    pages = pages[:min(len(pages), max_pages)]

    # Update animation
    animation_handler.update_activity(f"Starting site-wide crawling (depth: {max_depth}, max pages: {max_pages})")
    time.sleep(1)

    # Simulate crawling
    animation_handler.update_activity(f"Crawling site structure...")
    time.sleep(1)

    # Update pages crawled
    animation_handler.update_stats("Pages Crawled", len(pages))
    animation_handler.update_activity(f"Discovered {len(pages)} pages, starting fuzzing")
    time.sleep(1)

    # Simulate fuzzing each page
    for i, page in enumerate(pages):
        # Update animation
        animation_handler.update_activity(f"Fuzzing page {i+1}/{len(pages)}: {page}")
        time.sleep(0.5)

        # Determine page type for more realistic form detection
        page_type = page.split('/')[-1].split('?')[0]
        if not page_type:
            page_type = "home"

        # Simulate finding forms based on page type
        if page_type in ["login", "register", "checkout", "contact", "search", "reset-password"]:
            num_forms = 1  # These pages typically have one main form
        elif page_type in ["profile", "settings", "admin"]:
            num_forms = random.randint(1, 3)  # These pages might have multiple forms
        elif "api" in page:
            num_forms = 0  # API endpoints typically don't have forms
        else:
            num_forms = random.randint(0, 2)  # Other pages might have forms

        animation_handler.update_activity(f"Found {num_forms} forms on {page}")
        time.sleep(0.5)

        # Simulate fuzzing forms
        for j in range(num_forms):
            form_type = "unknown"
            if page_type == "login":
                form_type = "authentication"
            elif page_type == "register":
                form_type = "registration"
            elif page_type == "checkout":
                form_type = "payment"
            elif page_type == "contact":
                form_type = "contact"
            elif page_type == "search":
                form_type = "search"
            elif page_type == "reset-password":
                form_type = "password-reset"

            animation_handler.update_activity(f"Fuzzing {form_type} form {j+1}/{num_forms} on {page}")
            animation_handler.update_stats("Forms Fuzzed", 1)

            # Simulate sending payloads - more for authentication forms
            if form_type in ["authentication", "registration", "payment"]:
                num_payloads = random.randint(10, 20)  # More payloads for sensitive forms
            else:
                num_payloads = random.randint(5, 15)

            animation_handler.update_stats("Payloads Sent", num_payloads)

            # Determine which vulnerabilities are more likely based on page/form type
            likely_vulns = []
            if form_type == "authentication":
                likely_vulns = ["sqli", "broken_auth", "xss"]
            elif form_type == "registration":
                likely_vulns = ["xss", "csrf", "sensitive_data"]
            elif form_type == "payment":
                likely_vulns = ["csrf", "sensitive_data", "idor"]
            elif form_type == "search":
                likely_vulns = ["sqli", "xss"]
            elif "api" in page:
                likely_vulns = ["idor", "sensitive_data", "broken_auth"]
            else:
                likely_vulns = list(vulnerability_templates.keys())

            # Higher chance of finding vulnerabilities in certain pages
            vuln_chance = 0.1  # Base chance
            if "admin" in page:
                vuln_chance = 0.5  # Admin pages often have vulnerabilities
            elif "api" in page:
                vuln_chance = 0.4  # API endpoints often have vulnerabilities
            elif form_type in ["authentication", "payment"]:
                vuln_chance = 0.3  # Sensitive forms often have vulnerabilities

            # Simulate finding vulnerabilities
            for _ in range(random.randint(0, 3)):  # Up to 3 vulnerabilities per form
                if random.random() < vuln_chance:
                    # Select vulnerability type with preference for likely ones
                    if likely_vulns and random.random() < 0.7:
                        vuln_type = random.choice(likely_vulns)
                    else:
                        vuln_type = random.choice(list(vulnerability_templates.keys()))

                    vuln_info = vulnerability_templates[vuln_type]
                    severity = random.choice(["low", "medium", "high"])

                    # Higher severity for sensitive pages
                    if "admin" in page and random.random() < 0.7:
                        severity = "high"
                    elif "payment" in page and random.random() < 0.6:
                        severity = random.choice(["medium", "high"])

                    # Select random payload, description and evidence
                    payload_idx = random.randint(0, len(vuln_info["payloads"]) - 1)

                    finding = {
                        "type": vuln_info["name"],
                        "severity": severity,
                        "url": page,
                        "description": vuln_info["descriptions"][payload_idx],
                        "payload": vuln_info["payloads"][payload_idx],
                        "evidence": vuln_info["evidence"][payload_idx]
                    }

                    # Report finding
                    animation_handler.report_finding(finding)
                    time.sleep(0.5)

            time.sleep(0.5)

    # Simulate completing fuzzing
    animation_handler.update_activity("Fuzzing completed")
    time.sleep(1)

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

    # Write the HTML report only if output_file is provided
    if output_file:
        with open(output_file, 'w') as f:
            f.write(html_content)
        print(f"Report saved to: {os.path.abspath(output_file)}")
