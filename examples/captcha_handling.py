"""
Example of handling CAPTCHAs with HumanFuzz.
"""

from humanfuzz import HumanFuzzer
from humanfuzz.captcha_handler import CaptchaHandler

def manual_captcha_solver(captcha_type):
    """
    Manual CAPTCHA solving callback function.
    
    This function will be called when a CAPTCHA is detected and needs manual solving.
    In a real application, this could display a UI or notify the user to solve the CAPTCHA.
    
    Args:
        captcha_type: Type of CAPTCHA detected
        
    Returns:
        True if CAPTCHA was solved, False otherwise
    """
    print(f"\n[!] CAPTCHA detected: {captcha_type}")
    print("[!] Please solve the CAPTCHA in the browser window")
    input("[!] Press Enter when you've solved the CAPTCHA...")
    return True

def main():
    # Create a fuzzer instance with visible browser
    fuzzer = HumanFuzzer(headless=False)  # Set headless=False to see the browser
    
    try:
        # Start a fuzzing session
        fuzzer.start_session("https://example.com")
        
        # Create a CAPTCHA handler
        captcha_handler = CaptchaHandler(fuzzer.browser)
        
        # Check if there's a CAPTCHA on the current page
        is_captcha, captcha_type = captcha_handler.detect_captcha()
        
        if is_captcha:
            print(f"CAPTCHA detected: {captcha_type}")
            
            # Try to handle the CAPTCHA
            success = captcha_handler.handle_captcha(captcha_type, callback=manual_captcha_solver)
            
            if success:
                print("CAPTCHA handled successfully!")
            else:
                print("Failed to handle CAPTCHA")
                return
        
        # Continue with normal operations
        findings = fuzzer.fuzz_current_page()
        
        # Print findings
        print(f"Found {len(findings)} potential vulnerabilities")
        for finding in findings:
            print(f"- {finding['type']} ({finding['severity']}): {finding['description']}")
            
    finally:
        # Always close the fuzzer to clean up resources
        fuzzer.close()

if __name__ == "__main__":
    main()
