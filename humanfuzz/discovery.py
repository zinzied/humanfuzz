"""
Form and input discovery module for HumanFuzz.
"""

import logging
from typing import Dict, List, Optional, Set
from bs4 import BeautifulSoup
import re
import urllib.parse

logger = logging.getLogger(__name__)

class FormDiscovery:
    """
    Discovers forms, inputs, and interactive elements on web pages.
    """
    
    def __init__(self, browser_controller):
        """
        Initialize the form discovery module.
        
        Args:
            browser_controller: Instance of BrowserController
        """
        self.browser = browser_controller
        self.visited_urls = set()
        
    def crawl_site(self, start_url: str, max_depth: int = 3, max_pages: int = 50) -> List[str]:
        """
        Crawl a site to discover pages.
        
        Args:
            start_url: URL to start crawling from
            max_depth: Maximum crawl depth
            max_pages: Maximum number of pages to crawl
            
        Returns:
            List of discovered page URLs
        """
        logger.info(f"Crawling site starting from {start_url}")
        
        base_url = self._get_base_url(start_url)
        to_visit = [(start_url, 0)]  # (url, depth)
        self.visited_urls = set()
        
        while to_visit and len(self.visited_urls) < max_pages:
            url, depth = to_visit.pop(0)
            
            if url in self.visited_urls:
                continue
                
            if depth > max_depth:
                continue
                
            logger.debug(f"Visiting {url} (depth {depth})")
            
            # Visit the page
            self.browser.navigate(url)
            self.visited_urls.add(url)
            
            # Don't crawl further if we've reached max depth
            if depth == max_depth:
                continue
                
            # Find links on the page
            links = self._extract_links(base_url)
            
            # Add new links to the queue
            for link in links:
                if link not in self.visited_urls:
                    to_visit.append((link, depth + 1))
                    
        return list(self.visited_urls)
    
    def _get_base_url(self, url: str) -> str:
        """Extract the base URL (scheme + domain)."""
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _extract_links(self, base_url: str) -> List[str]:
        """
        Extract links from the current page.
        
        Args:
            base_url: Base URL for resolving relative links
            
        Returns:
            List of absolute URLs
        """
        # Get all links using JavaScript
        links = self.browser.page.evaluate("""() => {
            return Array.from(document.querySelectorAll('a[href]'))
                .map(a => a.href)
                .filter(href => href.startsWith('http') || href.startsWith('/'));
        }""")
        
        # Normalize and filter links
        normalized_links = []
        for link in links:
            # Convert relative URLs to absolute
            if link.startswith('/'):
                link = f"{base_url}{link}"
                
            # Filter out external links and non-HTML resources
            if link.startswith(base_url) and not any(ext in link for ext in ['.jpg', '.png', '.pdf', '.zip']):
                normalized_links.append(link)
                
        return normalized_links
    
    def find_forms(self) -> List[Dict]:
        """
        Find all forms on the current page.
        
        Returns:
            List of form information dictionaries
        """
        logger.debug(f"Finding forms on {self.browser.current_url}")
        
        # Get forms using JavaScript
        forms = self.browser.page.evaluate("""() => {
            return Array.from(document.querySelectorAll('form')).map(form => {
                const fields = Array.from(form.querySelectorAll('input, textarea, select'))
                    .filter(el => el.type !== 'submit' && el.type !== 'button')
                    .map(el => ({
                        name: el.name || '',
                        id: el.id || '',
                        type: el.type || 'text',
                        selector: el.id ? `#${el.id}` : el.name ? `[name="${el.name}"]` : '',
                        required: el.required || false
                    }));
                    
                const submitButtons = Array.from(form.querySelectorAll('input[type="submit"], button[type="submit"], button:not([type])'))
                    .map(el => ({
                        selector: el.id ? `#${el.id}` : el.name ? `[name="${el.name}"]` : '',
                        text: el.innerText || el.value || 'Submit'
                    }));
                
                return {
                    id: form.id || '',
                    name: form.name || '',
                    action: form.action || '',
                    method: form.method || 'get',
                    selector: form.id ? `#${form.id}` : form.name ? `form[name="${form.name}"]` : 'form',
                    fields: fields,
                    submitButtons: submitButtons
                };
            });
        }""")
        
        return forms
    
    def find_interactive_elements(self) -> List[Dict]:
        """
        Find interactive elements that aren't in forms (buttons, links, etc.).
        
        Returns:
            List of interactive element information dictionaries
        """
        logger.debug(f"Finding interactive elements on {self.browser.current_url}")
        
        # Get interactive elements using JavaScript
        elements = self.browser.page.evaluate("""() => {
            return Array.from(document.querySelectorAll('button, [role="button"], [onclick]'))
                .filter(el => !el.closest('form')) // Exclude elements inside forms
                .map(el => ({
                    type: el.tagName.toLowerCase(),
                    id: el.id || '',
                    text: el.innerText || '',
                    selector: el.id ? `#${el.id}` : '',
                    hasOnClick: el.hasAttribute('onclick')
                }));
        }""")
        
        return elements
