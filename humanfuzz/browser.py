"""
Browser automation module for HumanFuzz.
"""

import logging
import asyncio
from typing import Dict, List, Optional, Union, Any
from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext

logger = logging.getLogger(__name__)

class BrowserController:
    """
    Controls browser interactions using Playwright.

    This class handles browser automation, including navigation, form filling,
    clicking, and other user-like interactions.
    """

    def __init__(self, headless: bool = True, browser_type: str = "chromium"):
        """
        Initialize the browser controller.

        Args:
            headless: Whether to run the browser in headless mode
            browser_type: Type of browser to use (chromium, firefox, or webkit)
        """
        self.headless = headless
        self.browser_type = browser_type
        self.playwright = sync_playwright().start()

        # Select browser based on type
        if browser_type == "chromium":
            self.browser = self.playwright.chromium.launch(headless=headless)
        elif browser_type == "firefox":
            self.browser = self.playwright.firefox.launch(headless=headless)
        elif browser_type == "webkit":
            self.browser = self.playwright.webkit.launch(headless=headless)
        else:
            raise ValueError(f"Unsupported browser type: {browser_type}")

        # Create a new browser context and page
        self.context = self.browser.new_context()
        self.page = self.context.new_page()

        # Set up event listeners
        self._setup_listeners()

    def _setup_listeners(self):
        """Set up event listeners for the page."""
        self.page.on("console", lambda msg: logger.debug(f"Console {msg.type}: {msg.text}"))
        self.page.on("pageerror", lambda err: logger.error(f"Page error: {err}"))
        self.page.on("requestfailed", lambda request: logger.warning(f"Request failed: {request.url}"))

    @property
    def current_url(self) -> str:
        """Get the current URL of the page."""
        return self.page.url

    def navigate(self, url: str, wait_until: str = "networkidle", timeout: int = 30000) -> bool:
        """
        Navigate to a URL.

        Args:
            url: URL to navigate to
            wait_until: When to consider navigation complete
            timeout: Navigation timeout in milliseconds

        Returns:
            bool: True if navigation was successful, False otherwise
        """
        logger.info(f"Navigating to {url}")
        try:
            self.page.goto(url, wait_until=wait_until, timeout=timeout)
            return True
        except Exception as e:
            logger.error(f"Error navigating to {url}: {e}")
            # Try to recover by creating a new page if the current one is closed
            try:
                if self.page.is_closed():
                    logger.warning("Page is closed, creating a new page")
                    self.page = self.context.new_page()
                    self._setup_listeners()
            except Exception as inner_e:
                logger.error(f"Error recovering from navigation failure: {inner_e}")
            return False

    def fill_field(self, selector: str, value: str) -> None:
        """
        Fill a form field with a value.

        Args:
            selector: CSS selector for the field
            value: Value to fill in
        """
        logger.debug(f"Filling field {selector} with value {value}")
        try:
            self.page.fill(selector, value)
        except Exception as e:
            logger.error(f"Error filling field {selector}: {e}")

    def click(self, selector: str) -> None:
        """
        Click an element.

        Args:
            selector: CSS selector for the element
        """
        logger.debug(f"Clicking element {selector}")
        try:
            self.page.click(selector)
        except Exception as e:
            logger.error(f"Error clicking element {selector}: {e}")

    def submit_form(self, form_selector: str) -> Dict:
        """
        Submit a form and capture the response.

        Args:
            form_selector: CSS selector for the form

        Returns:
            Dictionary with response information
        """
        logger.debug(f"Submitting form {form_selector}")

        # Set up a response listener
        response_info = {}

        def handle_response(response):
            if response.url != self.current_url:
                response_info["status"] = response.status
                response_info["url"] = response.url
                response_info["headers"] = response.headers
                response_info["body"] = response.text()

        self.page.once("response", handle_response)

        # Submit the form
        try:
            self.page.evaluate(f"""() => {{
                const form = document.querySelector('{form_selector}');
                if (form) form.submit();
            }}""")
        except Exception as e:
            logger.error(f"Error submitting form {form_selector}: {e}")

        # Wait for navigation to complete
        self.page.wait_for_load_state("networkidle")

        return response_info

    def submit_current_form(self) -> Dict:
        """
        Submit the current form (useful when selector is unknown).

        Returns:
            Dictionary with response information
        """
        logger.debug("Submitting current form")

        # Set up a response listener
        response_info = {}

        def handle_response(response):
            if response.url != self.current_url:
                response_info["status"] = response.status
                response_info["url"] = response.url
                response_info["headers"] = response.headers
                try:
                    response_info["body"] = response.text()
                except Exception as e:
                    logger.warning(f"Could not get response body: {e}")
                    response_info["body"] = ""

        self.page.once("response", handle_response)

        # Try multiple submission methods
        try:
            # First try pressing Enter
            self.page.keyboard.press("Enter")

            # Wait for navigation to complete with a reasonable timeout
            try:
                self.page.wait_for_load_state("networkidle", timeout=10000)
            except Exception as e:
                logger.warning(f"Navigation timeout after form submission: {e}")

            # If no response was captured, try finding and clicking a submit button
            if not response_info:
                logger.debug("Trying to find and click submit button")
                try:
                    # Try common submit button selectors
                    for selector in ['input[type="submit"]', 'button[type="submit"]', 'button:contains("Submit")', 'button:contains("Login")']:
                        if self.page.query_selector(selector):
                            logger.debug(f"Found submit button with selector: {selector}")
                            self.page.click(selector)
                            try:
                                self.page.wait_for_load_state("networkidle", timeout=10000)
                            except Exception as e:
                                logger.warning(f"Navigation timeout after clicking submit button: {e}")
                            break
                except Exception as e:
                    logger.warning(f"Error finding or clicking submit button: {e}")

        except Exception as e:
            logger.error(f"Error submitting form: {e}")
            response_info["error"] = str(e)

        return response_info

    def get_page_content(self) -> str:
        """
        Get the HTML content of the current page.

        Returns:
            HTML content as a string
        """
        return self.page.content()

    def take_screenshot(self, path: str) -> None:
        """
        Take a screenshot of the current page.

        Args:
            path: Path to save the screenshot
        """
        try:
            self.page.screenshot(path=path)
            logger.info(f"Screenshot saved to {path}")
        except Exception as e:
            logger.error(f"Error taking screenshot: {e}")

    def close(self) -> None:
        """Close the browser and clean up resources."""
        self.context.close()
        self.browser.close()
        self.playwright.stop()
