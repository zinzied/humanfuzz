"""
Basic usage example for HumanFuzz.
"""

from humanfuzz import HumanFuzzer

def main():
    # Create a fuzzer instance
    fuzzer = HumanFuzzer(headless=False)  # Set headless=False to see the browser in action
    
    try:
        # Start a fuzzing session
        fuzzer.start_session("https://example.com")
        
        # Fuzz the current page
        findings = fuzzer.fuzz_current_page()
        
        # Print findings
        print(f"Found {len(findings)} potential vulnerabilities")
        for finding in findings:
            print(f"- {finding['type']} ({finding['severity']}): {finding['description']}")
            
        # Generate a report
        fuzzer.generate_report("vulnerability_report.html")
        print(f"Report saved to vulnerability_report.html")
        
    finally:
        # Always close the fuzzer to clean up resources
        fuzzer.close()

if __name__ == "__main__":
    main()
