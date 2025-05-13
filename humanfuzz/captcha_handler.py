"""
CAPTCHA handling module for HumanFuzz.

This module provides functionality to detect and handle various CAPTCHA challenges,
including Google reCAPTCHA v2 and v3.
"""

import logging
import time
import random
from typing import Dict, Optional, Tuple, Union, Callable
import re

logger = logging.getLogger(__name__)

class CaptchaHandler:
    """
    Handles detection and solving of CAPTCHA challenges.
    
    This class provides methods to detect the presence of CAPTCHAs on a page
    and implements various strategies to handle them.
    """
    
    def __init__(self, browser_controller, solver_api_key: Optional[str] = None):
        """
        Initialize the CAPTCHA handler.
        
        Args:
            browser_controller: Instance of BrowserController
            solver_api_key: API key for external CAPTCHA solving service (optional)
        """
        self.browser = browser_controller
        self.solver_api_key = solver_api_key
        
    def detect_captcha(self) -> Tuple[bool, str]:
        """
        Detect if a CAPTCHA is present on the current page.
        
        Returns:
            Tuple of (is_captcha_present, captcha_type)
            captcha_type can be 'recaptcha_v2', 'recaptcha_v3', 'hcaptcha', or 'unknown'
        """
        logger.debug("Detecting CAPTCHA on current page")
        
        # Check for reCAPTCHA v2
        recaptcha_v2 = self.browser.page.evaluate("""() => {
            return Boolean(
                document.querySelector('.g-recaptcha') || 
                document.querySelector('iframe[src*="recaptcha/api2"]')
            );
        }""")
        
        if recaptcha_v2:
            logger.info("Detected reCAPTCHA v2")
            return True, 'recaptcha_v2'
            
        # Check for reCAPTCHA v3
        recaptcha_v3 = self.browser.page.evaluate("""() => {
            return Boolean(
                document.querySelector('script[src*="recaptcha/api.js?render="]')
            );
        }""")
        
        if recaptcha_v3:
            logger.info("Detected reCAPTCHA v3")
            return True, 'recaptcha_v3'
            
        # Check for hCaptcha
        hcaptcha = self.browser.page.evaluate("""() => {
            return Boolean(
                document.querySelector('.h-captcha') || 
                document.querySelector('iframe[src*="hcaptcha.com"]')
            );
        }""")
        
        if hcaptcha:
            logger.info("Detected hCaptcha")
            return True, 'hcaptcha'
            
        # Check for generic CAPTCHA indicators
        generic_captcha = self.browser.page.evaluate("""() => {
            const pageText = document.body.innerText.toLowerCase();
            return (
                pageText.includes('captcha') || 
                pageText.includes('robot') ||
                pageText.includes('human verification')
            );
        }""")
        
        if generic_captcha:
            logger.info("Detected possible CAPTCHA (generic indicators)")
            return True, 'unknown'
            
        logger.debug("No CAPTCHA detected")
        return False, ''
        
    def handle_captcha(self, captcha_type: str, callback: Optional[Callable] = None) -> bool:
        """
        Handle a detected CAPTCHA based on its type.
        
        Args:
            captcha_type: Type of CAPTCHA ('recaptcha_v2', 'recaptcha_v3', 'hcaptcha', 'unknown')
            callback: Optional callback function for manual solving
            
        Returns:
            True if CAPTCHA was successfully handled, False otherwise
        """
        logger.info(f"Handling {captcha_type} CAPTCHA")
        
        if captcha_type == 'recaptcha_v2':
            return self._handle_recaptcha_v2(callback)
        elif captcha_type == 'recaptcha_v3':
            return self._handle_recaptcha_v3()
        elif captcha_type == 'hcaptcha':
            return self._handle_hcaptcha(callback)
        else:
            return self._handle_unknown_captcha(callback)
            
    def _handle_recaptcha_v2(self, callback: Optional[Callable] = None) -> bool:
        """
        Handle reCAPTCHA v2 challenge.
        
        Args:
            callback: Optional callback function for manual solving
            
        Returns:
            True if CAPTCHA was successfully handled, False otherwise
        """
        if self.solver_api_key:
            # Use external CAPTCHA solving service
            logger.info("Using external service to solve reCAPTCHA v2")
            # Implementation would go here
            return False  # Placeholder
        elif callback:
            # Use manual solving callback
            logger.info("Using manual callback to solve reCAPTCHA v2")
            return callback(captcha_type='recaptcha_v2')
        else:
            # Try to use browser automation to solve
            logger.info("Attempting automated solving of reCAPTCHA v2")
            
            # Click the reCAPTCHA checkbox
            try:
                self.browser.page.click('.recaptcha-checkbox-border')
                time.sleep(2)  # Wait for potential image challenge
                
                # Check if we need to solve an image challenge
                image_challenge = self.browser.page.evaluate("""() => {
                    return Boolean(document.querySelector('.rc-imageselect-instructions'));
                }""")
                
                if image_challenge:
                    logger.warning("Image challenge detected, cannot solve automatically")
                    return False
                
                # Check if checkbox is checked
                success = self.browser.page.evaluate("""() => {
                    return Boolean(document.querySelector('.recaptcha-checkbox-checked'));
                }""")
                
                return success
            except Exception as e:
                logger.error(f"Error attempting to solve reCAPTCHA v2: {e}")
                return False
                
    def _handle_recaptcha_v3(self) -> bool:
        """
        Handle reCAPTCHA v3 challenge.
        
        Returns:
            True if CAPTCHA was successfully handled, False otherwise
        """
        # reCAPTCHA v3 is invisible and scores user behavior
        # The best approach is to make the browser behave more human-like
        logger.info("Attempting to handle reCAPTCHA v3 with human-like behavior")
        
        # Perform some random mouse movements
        self._simulate_human_behavior()
        
        # Since we can't directly solve v3, we return True and hope our behavior was human-like enough
        return True
        
    def _handle_hcaptcha(self, callback: Optional[Callable] = None) -> bool:
        """
        Handle hCaptcha challenge.
        
        Args:
            callback: Optional callback function for manual solving
            
        Returns:
            True if CAPTCHA was successfully handled, False otherwise
        """
        if self.solver_api_key:
            # Use external CAPTCHA solving service
            logger.info("Using external service to solve hCaptcha")
            # Implementation would go here
            return False  # Placeholder
        elif callback:
            # Use manual solving callback
            logger.info("Using manual callback to solve hCaptcha")
            return callback(captcha_type='hcaptcha')
        else:
            logger.warning("Automated solving of hCaptcha not implemented")
            return False
            
    def _handle_unknown_captcha(self, callback: Optional[Callable] = None) -> bool:
        """
        Handle unknown CAPTCHA type.
        
        Args:
            callback: Optional callback function for manual solving
            
        Returns:
            True if CAPTCHA was successfully handled, False otherwise
        """
        if callback:
            # Use manual solving callback
            logger.info("Using manual callback to solve unknown CAPTCHA")
            return callback(captcha_type='unknown')
        else:
            logger.warning("Cannot automatically solve unknown CAPTCHA type")
            return False
            
    def _simulate_human_behavior(self) -> None:
        """Simulate human-like behavior to help pass reCAPTCHA v3."""
        # Random mouse movements
        for _ in range(random.randint(5, 10)):
            x = random.randint(100, 700)
            y = random.randint(100, 500)
            self.browser.page.mouse.move(x, y)
            time.sleep(random.uniform(0.1, 0.3))
            
        # Random scrolling
        self.browser.page.evaluate(f"window.scrollTo(0, {random.randint(100, 300)});")
        time.sleep(random.uniform(0.5, 1.5))
        self.browser.page.evaluate(f"window.scrollTo(0, {random.randint(301, 600)});")
        time.sleep(random.uniform(0.5, 1.5))
        self.browser.page.evaluate("window.scrollTo(0, 0);")
