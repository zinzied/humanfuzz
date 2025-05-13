"""
Simple test script for HumanFuzz.
"""

import sys
import os

# Add the parent directory to the path so we can import the package
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from humanfuzz.payloads import Payload, PayloadManager
from humanfuzz.analyzer import ResponseAnalyzer

def test_payload_creation():
    """Test creating payloads."""
    payload = Payload("<script>alert(1)</script>", "xss", "Test XSS")
    print(f"Created payload: {payload}")
    assert payload.value == "<script>alert(1)</script>"
    assert payload.category == "xss"
    assert payload.name == "Test XSS"
    print("Payload creation test passed!")

def test_payload_manager():
    """Test the payload manager."""
    manager = PayloadManager()
    
    # Test getting payloads for a text field
    text_payloads = manager.get_payloads_for_field({"type": "text"})
    print(f"Got {len(text_payloads)} payloads for text field")
    assert len(text_payloads) > 0
    
    # Test getting payloads for a number field
    number_payloads = manager.get_payloads_for_field({"type": "number"})
    print(f"Got {len(number_payloads)} payloads for number field")
    assert len(number_payloads) > 0
    
    print("Payload manager test passed!")

def test_analyzer():
    """Test the response analyzer."""
    analyzer = ResponseAnalyzer()
    
    # Create a test payload
    payload = Payload("' OR '1'='1", "sqli", "Test SQLi")
    
    # Create a mock response with SQL error
    response = {
        "status": 500,
        "url": "https://example.com/login",
        "headers": {},
        "body": "Error: SQL syntax error in query: SELECT * FROM users WHERE username='' OR '1'='1'"
    }
    
    # Analyze the response
    findings = analyzer.analyze(response, payload)
    print(f"Found {len(findings)} vulnerabilities in test response")
    assert len(findings) > 0
    assert findings[0]["type"] == "sqli"
    
    print("Analyzer test passed!")

def main():
    """Run all tests."""
    print("Running HumanFuzz tests...")
    
    test_payload_creation()
    test_payload_manager()
    test_analyzer()
    
    print("\nAll tests passed!")

if __name__ == "__main__":
    main()
