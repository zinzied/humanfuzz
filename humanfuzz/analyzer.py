"""
Response analysis module for HumanFuzz.
"""

import logging
import re
from typing import Dict, List, Optional, Any
from humanfuzz.payloads import Payload

logger = logging.getLogger(__name__)

class ResponseAnalyzer:
    """
    Analyzes responses to detect potential vulnerabilities.
    """
    
    def __init__(self):
        """Initialize the response analyzer."""
        # Patterns for detecting various vulnerabilities
        self.patterns = {
            "xss_reflection": re.compile(r'<script>alert\(1\)</script>|<img src=x onerror=alert\(1\)>|<svg onload=alert\(1\)>'),
            "sql_error": re.compile(r'SQL syntax|ORA-[0-9]|mysql_fetch|pg_query|sqlite3_|SQLSTATE'),
            "server_error": re.compile(r'Exception|Error|Warning|Fatal|Undefined|stack trace|at .+\(.+:[0-9]+\)'),
            "path_disclosure": re.compile(r'[A-Za-z]:\\|/var/www/|/home/|/usr/local/|/opt/|/etc/'),
            "debug_info": re.compile(r'DEBUG|TRACE|console\.log|System\.out\.print|print_r|var_dump'),
        }
        
    def analyze(self, response: Dict, payload: Payload) -> List[Dict]:
        """
        Analyze a response for potential vulnerabilities.
        
        Args:
            response: Response information dictionary
            payload: The payload that was used
            
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        # Skip if response is empty
        if not response:
            return findings
            
        # Get response data
        status = response.get("status", 0)
        body = response.get("body", "")
        headers = response.get("headers", {})
        url = response.get("url", "")
        
        # Check for payload reflection (potential XSS)
        if payload.category == "xss" and self._check_xss_reflection(body, payload):
            findings.append({
                "type": "xss",
                "severity": "high",
                "payload": payload.value,
                "evidence": self._extract_evidence(body, payload.value),
                "description": "XSS payload was reflected in the response",
                "url": url
            })
            
        # Check for SQL errors
        if payload.category == "sqli" and self._check_sql_error(body):
            findings.append({
                "type": "sqli",
                "severity": "high",
                "payload": payload.value,
                "evidence": self._extract_evidence(body, self.patterns["sql_error"]),
                "description": "SQL error detected in response",
                "url": url
            })
            
        # Check for server errors
        if self._check_server_error(body, status):
            findings.append({
                "type": "server_error",
                "severity": "medium",
                "payload": payload.value,
                "evidence": self._extract_evidence(body, self.patterns["server_error"]),
                "description": "Server error detected in response",
                "url": url
            })
            
        # Check for path disclosure
        if self._check_path_disclosure(body):
            findings.append({
                "type": "path_disclosure",
                "severity": "low",
                "payload": payload.value,
                "evidence": self._extract_evidence(body, self.patterns["path_disclosure"]),
                "description": "Path disclosure detected in response",
                "url": url
            })
            
        # Check for debug information
        if self._check_debug_info(body):
            findings.append({
                "type": "debug_info",
                "severity": "low",
                "payload": payload.value,
                "evidence": self._extract_evidence(body, self.patterns["debug_info"]),
                "description": "Debug information detected in response",
                "url": url
            })
            
        # Check for SSRF success indicators
        if payload.category == "ssrf" and self._check_ssrf_success(body, status):
            findings.append({
                "type": "ssrf",
                "severity": "high",
                "payload": payload.value,
                "evidence": "Response indicates successful SSRF",
                "description": "Potential SSRF vulnerability detected",
                "url": url
            })
            
        return findings
    
    def _check_xss_reflection(self, body: str, payload: Payload) -> bool:
        """Check if XSS payload is reflected in the response."""
        # Escape special regex characters in the payload value
        escaped_payload = re.escape(payload.value)
        return bool(re.search(escaped_payload, body))
    
    def _check_sql_error(self, body: str) -> bool:
        """Check for SQL error messages in the response."""
        return bool(self.patterns["sql_error"].search(body))
    
    def _check_server_error(self, body: str, status: int) -> bool:
        """Check for server error indicators."""
        return status >= 500 or bool(self.patterns["server_error"].search(body))
    
    def _check_path_disclosure(self, body: str) -> bool:
        """Check for path disclosure in the response."""
        return bool(self.patterns["path_disclosure"].search(body))
    
    def _check_debug_info(self, body: str) -> bool:
        """Check for debug information in the response."""
        return bool(self.patterns["debug_info"].search(body))
    
    def _check_ssrf_success(self, body: str, status: int) -> bool:
        """
        Check for indicators of successful SSRF.
        
        This is more complex and might require custom logic based on the target.
        """
        # Look for common indicators of successful SSRF
        ssrf_indicators = [
            # AWS metadata indicators
            "ami-id", "instance-id", "instance-type", "local-hostname",
            # GCP metadata indicators
            "instance/attributes", "instance/service-accounts",
            # Common internal service responses
            "<title>Router</title>", "<title>Admin</title>",
            # Common file content indicators
            "root:x:", "mysql:", "www-data:"
        ]
        
        return any(indicator in body for indicator in ssrf_indicators)
    
    def _extract_evidence(self, body: str, pattern) -> str:
        """
        Extract evidence from the response body.
        
        Args:
            body: Response body
            pattern: String or regex pattern to search for
            
        Returns:
            Extracted evidence string
        """
        if isinstance(pattern, str):
            # Find the pattern and extract some context
            index = body.find(pattern)
            if index != -1:
                start = max(0, index - 20)
                end = min(len(body), index + len(pattern) + 20)
                return f"...{body[start:end]}..."
            return ""
        else:
            # Use regex to find the pattern
            match = pattern.search(body)
            if match:
                start = max(0, match.start() - 20)
                end = min(len(body), match.end() + 20)
                return f"...{body[start:end]}..."
            return ""
