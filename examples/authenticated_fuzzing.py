"""
Authenticated fuzzing example for HumanFuzz.
"""

from humanfuzz import HumanFuzzer

def main():
    # Create a fuzzer instance
    fuzzer = HumanFuzzer(headless=False)  # Set headless=False to see the browser in action
    
    try:
        # Start a fuzzing session
        fuzzer.start_session("https://example.com/login")
        
        # Authenticate
        auth_success = fuzzer.authenticate(
            login_url="https://example.com/login",
            username_field="username",
            password_field="password",
            username="test_user",
            password="test_password"
        )
        
        if not auth_success:
            print("Authentication failed")
            return
            
        print("Authentication successful")
        
        # Fuzz the site
        findings = fuzzer.fuzz_site(max_depth=2, max_pages=10)
        
        # Print findings
        print(f"Found {len(findings)} potential vulnerabilities")
        for finding in findings:
            print(f"- {finding['type']} ({finding['severity']}): {finding['description']}")
            
        # Generate a report
        fuzzer.generate_report("authenticated_report.html")
        print(f"Report saved to authenticated_report.html")
        
    finally:
        # Always close the fuzzer to clean up resources
        fuzzer.close()

if __name__ == "__main__":
    main()
