"""
Main fuzzer class that orchestrates the fuzzing process.
"""

import logging
import time
from typing import Dict, List, Optional, Union, Any, Callable
from datetime import datetime

from humanfuzz.browser import BrowserController
from humanfuzz.discovery import FormDiscovery
from humanfuzz.analyzer import ResponseAnalyzer
from humanfuzz.reporter import Reporter
from humanfuzz.payloads import PayloadManager
from humanfuzz.captcha_handler import CaptchaHandler

logger = logging.getLogger(__name__)

class AnimationHandler:
    """
    Handles animations and visual feedback during the fuzzing process.
    This can be customized or replaced to provide different visual experiences.
    """

    def __init__(self):
        """Initialize the animation handler."""
        self.start_time = time.time()
        self.animation_callbacks = {}
        self.stats = {
            "Pages Crawled": 0,
            "Forms Fuzzed": 0,
            "Payloads Sent": 0,
            "Vulnerabilities Found": 0,
            "Elapsed Time": "00:00:00"
        }
        self.current_activity = "Initializing..."

    def register_callback(self, event_name: str, callback: Callable):
        """
        Register a callback function for a specific event.

        Args:
            event_name: Name of the event (e.g., 'start', 'finding', 'complete')
            callback: Function to call when the event occurs
        """
        self.animation_callbacks[event_name] = callback

    def trigger_event(self, event_name: str, **kwargs):
        """
        Trigger an event and call the associated callback.

        Args:
            event_name: Name of the event to trigger
            **kwargs: Additional arguments to pass to the callback
        """
        if event_name in self.animation_callbacks:
            self.animation_callbacks[event_name](**kwargs)

    def update_stats(self, key: str, value):
        """
        Update a statistic value.

        Args:
            key: Statistic key to update
            value: New value or increment
        """
        if key in self.stats:
            if key == "Elapsed Time":
                self.stats[key] = value
            else:
                if isinstance(value, int) and isinstance(self.stats[key], int):
                    self.stats[key] += value
                else:
                    self.stats[key] = value

            # Trigger stats update event
            self.trigger_event('stats_update', stats=self.stats)

    def update_activity(self, activity: str):
        """
        Update the current activity description.

        Args:
            activity: Description of the current activity
        """
        self.current_activity = activity

        # Trigger activity update event
        self.trigger_event('activity_update', activity=activity)

    def update_elapsed_time(self):
        """Update the elapsed time statistic."""
        elapsed = time.time() - self.start_time
        hours, remainder = divmod(int(elapsed), 3600)
        minutes, seconds = divmod(remainder, 60)
        self.stats["Elapsed Time"] = f"{hours:02}:{minutes:02}:{seconds:02}"

        # Trigger stats update event
        self.trigger_event('stats_update', stats=self.stats)

    def report_finding(self, finding: Dict):
        """
        Report a new vulnerability finding.

        Args:
            finding: Dictionary with finding information
        """
        # Update stats
        self.update_stats("Vulnerabilities Found", 1)

        # Trigger finding event
        self.trigger_event('finding', finding=finding)

class HumanFuzzer:
    """
    Main class for the HumanFuzz library.

    This class orchestrates the fuzzing process, including browser control,
    form discovery, payload generation, and vulnerability detection.
    """

    def __init__(self, headless: bool = True, browser_type: str = "chromium",
                 animation_handler=None, captcha_solver_api_key: Optional[str] = None,
                 bypass_cloudflare: bool = False, cloudflare_browser_settings: Optional[Dict] = None):
        """
        Initialize the HumanFuzzer.

        Args:
            headless: Whether to run the browser in headless mode
            browser_type: Type of browser to use (chromium, firefox, or webkit)
            animation_handler: Custom animation handler (optional)
            captcha_solver_api_key: API key for external CAPTCHA solving service (optional)
            bypass_cloudflare: Whether to enable Cloudflare bypass using cloudscraper25
            cloudflare_browser_settings: Custom browser settings for cloudscraper25 (optional)
        """
        # Initialize Cloudflare bypass if enabled
        self.bypass_cloudflare = bypass_cloudflare
        self.cloudflare_scraper = None

        if bypass_cloudflare:
            try:
                import cloudscraper25 as cloudscraper
                logger.info("Initializing Cloudflare bypass with cloudscraper25")

                # Default browser settings for cloudscraper
                default_settings = {
                    'browser': 'chrome',
                    'platform': 'windows',
                    'desktop': True
                }

                # Use custom settings if provided, otherwise use defaults
                browser_settings = cloudflare_browser_settings or default_settings

                # Create the scraper
                self.cloudflare_scraper = cloudscraper.create_scraper(
                    browser=browser_settings,
                    delay=10  # Add delay between requests
                )
                logger.info("Cloudflare bypass initialized successfully")
            except ImportError:
                logger.warning("cloudscraper25 not installed. Cloudflare bypass disabled.")
                logger.warning("Install with: pip install cloudscraper25")
                self.bypass_cloudflare = False

        # Initialize browser controller
        self.browser = BrowserController(headless=headless, browser_type=browser_type)
        self.discovery = FormDiscovery(self.browser)
        self.analyzer = ResponseAnalyzer()
        self.reporter = Reporter()
        self.payload_manager = PayloadManager()
        self.results = []
        self.current_url = None

        # Initialize animation handler
        self.animation = animation_handler if animation_handler else AnimationHandler()

        # Initialize CAPTCHA handler
        self.captcha_handler = CaptchaHandler(self.browser, solver_api_key=captcha_solver_api_key)

    def start_session(self, url: str, timeout: int = 60000) -> None:
        """
        Start a new fuzzing session by navigating to the specified URL.

        Args:
            url: The URL to start fuzzing from
            timeout: Navigation timeout in milliseconds (default: 60000)
        """
        logger.info(f"Starting new fuzzing session at {url}")
        self.current_url = url

        # Update animation
        self.animation.update_activity(f"Starting fuzzing session at {url}")
        self.animation.trigger_event('session_start', url=url)

        # Set longer timeout for navigation
        self.browser.page.set_default_timeout(timeout)

        # Use Cloudflare bypass if enabled
        if self.bypass_cloudflare and self.cloudflare_scraper:
            try:
                logger.info(f"Using Cloudflare bypass to access {url}")
                self.animation.update_activity(f"Using Cloudflare bypass for {url}")

                # Fetch the page using cloudscraper
                response = self.cloudflare_scraper.get(url)

                if response.status_code == 200:
                    logger.info(f"Successfully bypassed Cloudflare protection for {url}")

                    # Navigate to a blank page first
                    self.browser.navigate("about:blank")

                    # Set the content from cloudscraper
                    self.browser.page.set_content(response.text)

                    # Transfer cookies from cloudscraper to browser
                    cookies = self.cloudflare_scraper.cookies.get_dict()
                    for name, value in cookies.items():
                        self.browser.context.add_cookies([{
                            "name": name,
                            "value": value,
                            "url": url
                        }])

                    logger.info("Content and cookies transferred to browser")
                else:
                    logger.warning(f"Failed to bypass Cloudflare. Status code: {response.status_code}")
                    # Fall back to direct navigation
                    self.browser.navigate(url)
            except Exception as e:
                logger.error(f"Error using Cloudflare bypass: {e}")
                # Fall back to direct navigation
                self.browser.navigate(url)
        else:
            # Navigate to the URL directly
            self.browser.navigate(url)

        # Check for CAPTCHA
        self.check_and_handle_captcha()

    def check_and_handle_captcha(self, captcha_callback: Optional[Callable] = None) -> bool:
        """
        Check for CAPTCHA on the current page and handle it if found.

        Args:
            captcha_callback: Optional callback function for manual CAPTCHA solving

        Returns:
            True if no CAPTCHA was found or it was successfully handled, False otherwise
        """
        logger.info("Checking for CAPTCHA on current page")

        # Update animation
        self.animation.update_activity("Checking for CAPTCHA challenges")

        # Detect CAPTCHA
        is_captcha, captcha_type = self.captcha_handler.detect_captcha()

        if is_captcha:
            logger.warning(f"CAPTCHA detected: {captcha_type}")

            # Update animation
            self.animation.update_activity(f"CAPTCHA detected: {captcha_type}")
            self.animation.trigger_event('captcha_detected', captcha_type=captcha_type)

            # Try to handle the CAPTCHA
            success = self.captcha_handler.handle_captcha(captcha_type, callback=captcha_callback)

            # Update animation
            if success:
                self.animation.update_activity("CAPTCHA handled successfully")
                self.animation.trigger_event('captcha_solved', captcha_type=captcha_type)
            else:
                self.animation.update_activity("Failed to handle CAPTCHA")
                self.animation.trigger_event('captcha_failed', captcha_type=captcha_type)

            return success

        return True  # No CAPTCHA found

    def authenticate(self, login_url: str, username_field: str,
                    password_field: str, username: str, password: str,
                    submit_button_selector: Optional[str] = None,
                    captcha_callback: Optional[Callable] = None) -> bool:
        """
        Authenticate with the target application.

        Args:
            login_url: URL of the login page
            username_field: ID or name of the username field
            password_field: ID or name of the password field
            username: Username to use
            password: Password to use
            submit_button_selector: CSS selector for the submit button
            captcha_callback: Optional callback function for manual CAPTCHA solving

        Returns:
            bool: True if authentication was successful
        """
        logger.info(f"Authenticating at {login_url}")

        # Update animation
        self.animation.update_activity(f"Authenticating at {login_url}")
        self.animation.trigger_event('authentication_start', login_url=login_url)

        # Navigate to login page
        self.browser.navigate(login_url)

        # Check for CAPTCHA before filling the form
        if not self.check_and_handle_captcha(captcha_callback):
            logger.error("Could not handle CAPTCHA on login page")
            return False

        # Fill in the login form
        self.browser.fill_field(username_field, username)
        self.browser.fill_field(password_field, password)

        # Submit the form
        if submit_button_selector:
            self.browser.click(submit_button_selector)
        else:
            self.browser.submit_current_form()

        # Check for CAPTCHA after submission
        if not self.check_and_handle_captcha(captcha_callback):
            logger.error("Could not handle CAPTCHA after login submission")
            return False

        # Check if authentication was successful
        auth_success = login_url != self.browser.current_url

        # Update animation
        self.animation.update_activity(
            f"Authentication {'successful' if auth_success else 'failed'}"
        )
        self.animation.trigger_event(
            'authentication_complete',
            success=auth_success,
            current_url=self.browser.current_url
        )

        return auth_success

    def fuzz_site(self, max_depth: int = 3, max_pages: int = 50,
                captcha_callback: Optional[Callable] = None) -> List[Dict]:
        """
        Discover and fuzz all forms on the site up to the specified depth.

        Args:
            max_depth: Maximum crawl depth
            max_pages: Maximum number of pages to crawl
            captcha_callback: Optional callback function for manual CAPTCHA solving

        Returns:
            List of vulnerability findings
        """
        logger.info(f"Starting site-wide fuzzing with depth {max_depth}")

        # Update animation
        self.animation.update_activity(f"Starting site-wide crawling (depth: {max_depth}, max pages: {max_pages})")
        self.animation.trigger_event('crawl_start', max_depth=max_depth, max_pages=max_pages)

        # Start timer for elapsed time updates
        self._start_elapsed_time_updates()

        # Discover site structure and forms
        pages = self.discovery.crawl_site(self.current_url, max_depth, max_pages)

        # Update animation
        self.animation.update_stats("Pages Crawled", len(pages))
        self.animation.update_activity(f"Discovered {len(pages)} pages, starting fuzzing")
        self.animation.trigger_event('crawl_complete', pages=pages)

        # Fuzz each discovered page
        for i, page in enumerate(pages):
            # Update animation
            self.animation.update_activity(f"Fuzzing page {i+1}/{len(pages)}: {page}")
            self.animation.trigger_event('page_start', page=page, index=i, total=len(pages))

            # Navigate to the page
            self.browser.navigate(page)

            # Fuzz the page
            self.fuzz_current_page(captcha_callback=captcha_callback)

            # Update animation
            self.animation.trigger_event('page_complete', page=page, index=i, total=len(pages))

        # Update animation
        self.animation.update_activity("Fuzzing completed")
        self.animation.trigger_event('fuzzing_complete', results=self.results)

        # Stop elapsed time updates
        self._stop_elapsed_time_updates()

        return self.results

    def fuzz_current_page(self, captcha_callback: Optional[Callable] = None) -> List[Dict]:
        """
        Fuzz all forms and inputs on the current page.

        Args:
            captcha_callback: Optional callback function for manual CAPTCHA solving

        Returns:
            List of vulnerability findings on this page
        """
        current_url = self.browser.current_url
        logger.info(f"Fuzzing current page: {current_url}")

        # Update animation
        self.animation.update_activity(f"Discovering forms on {current_url}")

        # Check for CAPTCHA before fuzzing
        if not self.check_and_handle_captcha(captcha_callback):
            logger.warning(f"Could not handle CAPTCHA on {current_url}, skipping page")
            return []

        # Discover forms and inputs on the current page
        forms = self.discovery.find_forms()

        # Update animation
        self.animation.update_activity(f"Found {len(forms)} forms to fuzz")
        self.animation.trigger_event('forms_found', forms=forms, url=current_url)

        # Fuzz each form
        page_results = []
        for i, form in enumerate(forms):
            # Update animation
            self.animation.update_activity(f"Fuzzing form {i+1}/{len(forms)}")
            self.animation.trigger_event('form_start', form=form, index=i, total=len(forms))

            # Fuzz the form
            form_results = self.fuzz_form(form)
            page_results.extend(form_results)

            # Update animation
            self.animation.update_stats("Forms Fuzzed", 1)
            self.animation.trigger_event(
                'form_complete',
                form=form,
                results=form_results,
                index=i,
                total=len(forms)
            )

        # Add results to the overall results
        self.results.extend(page_results)

        # Update animation
        self.animation.update_activity(f"Completed fuzzing page: {current_url}")
        self.animation.trigger_event('page_results', results=page_results, url=current_url)

        return page_results

    def fuzz_form(self, form: Dict) -> List[Dict]:
        """
        Fuzz a specific form with various payloads.

        Args:
            form: Form information dictionary

        Returns:
            List of vulnerability findings for this form
        """
        form_id = form.get('id', 'unknown')
        logger.info(f"Fuzzing form: {form_id}")

        form_results = []
        total_fields = len(form['fields'])

        # Update animation
        self.animation.update_activity(f"Preparing payloads for form: {form_id}")

        # Fuzz each field in the form
        for field_idx, field in enumerate(form['fields']):
            field_name = field.get('name', field.get('id', f'field_{field_idx}'))

            # Update animation
            self.animation.update_activity(f"Testing field: {field_name} ({field_idx+1}/{total_fields})")
            self.animation.trigger_event('field_start', field=field, index=field_idx, total=total_fields)

            # Get appropriate payloads for the field
            payloads = self.payload_manager.get_payloads_for_field(field)

            # Update animation
            self.animation.update_activity(f"Sending {len(payloads)} payloads to field: {field_name}")

            # Test each payload
            for payload_idx, payload in enumerate(payloads):
                # Update animation for each payload
                if payload_idx % 5 == 0:  # Update every 5 payloads to avoid too many updates
                    self.animation.update_activity(
                        f"Testing payload {payload_idx+1}/{len(payloads)} on field: {field_name}"
                    )

                # Fill the form with the payload
                self.browser.fill_field(field['selector'], payload.value)

                # Submit the form
                response = self.browser.submit_form(form['selector'])

                # Update animation
                self.animation.update_stats("Payloads Sent", 1)

                # Analyze the response for vulnerabilities
                findings = self.analyzer.analyze(response, payload)

                if findings:
                    # Add findings to results
                    form_results.extend(findings)

                    # Update animation for each finding
                    for finding in findings:
                        self.animation.report_finding(finding)
                        self.animation.trigger_event('vulnerability_found', finding=finding)

            # Update animation
            self.animation.trigger_event('field_complete', field=field, index=field_idx, total=total_fields)

        # Update animation
        self.animation.update_activity(f"Completed fuzzing form: {form_id}")
        self.animation.trigger_event('form_results', form=form, results=form_results)

        return form_results

    def generate_report(self, output_file: str) -> None:
        """
        Generate a report of the fuzzing results.

        Args:
            output_file: Path to the output file
        """
        logger.info(f"Generating report to {output_file}")

        # Update animation
        self.animation.update_activity(f"Generating report to {output_file}")
        self.animation.trigger_event('report_start', output_file=output_file)

        # Generate the report
        self.reporter.generate(self.results, output_file)

        # Update animation
        self.animation.update_activity(f"Report generated: {output_file}")
        self.animation.trigger_event('report_complete', output_file=output_file)

    def close(self) -> None:
        """
        Close the browser and clean up resources.
        """
        logger.info("Closing HumanFuzzer session")

        # Update animation
        self.animation.update_activity("Closing browser and cleaning up resources")
        self.animation.trigger_event('session_end')

        # Close the browser
        self.browser.close()

    def _start_elapsed_time_updates(self):
        """Start a background thread to update elapsed time."""
        import threading

        def update_time():
            while getattr(self, '_update_time', True):
                self.animation.update_elapsed_time()
                time.sleep(1)

        self._update_time = True
        self._timer_thread = threading.Thread(target=update_time)
        self._timer_thread.daemon = True
        self._timer_thread.start()

    def _stop_elapsed_time_updates(self):
        """Stop the background thread updating elapsed time."""
        self._update_time = False
