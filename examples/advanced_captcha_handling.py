"""
Advanced example of handling CAPTCHAs with HumanFuzz using third-party services.
"""

import os
import time
import logging
from humanfuzz import HumanFuzzer

# Set up logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# This is a mock implementation of a CAPTCHA solving service
# In a real application, you would use a service like 2Captcha, Anti-Captcha, etc.
class MockCaptchaSolver:
    def __init__(self, api_key):
        self.api_key = api_key
        
    def solve_recaptcha_v2(self, site_key, page_url):
        """
        Mock implementation of solving reCAPTCHA v2.
        
        In a real implementation, this would call the API of a CAPTCHA solving service.
        """
        print(f"[Mock Solver] Solving reCAPTCHA v2 for site key: {site_key} on {page_url}")
        # Simulate solving delay
        time.sleep(3)
        return "03AGdBq24PBCbZZzPHY4A7H5..."  # Mock response token
        
    def solve_recaptcha_v3(self, site_key, page_url, action="verify"):
        """
        Mock implementation of solving reCAPTCHA v3.
        """
        print(f"[Mock Solver] Solving reCAPTCHA v3 for site key: {site_key} on {page_url}")
        # Simulate solving delay
        time.sleep(2)
        return "03AGdBq26_HZ7dq9bKZ_EV8a..."  # Mock response token
        
    def solve_hcaptcha(self, site_key, page_url):
        """
        Mock implementation of solving hCaptcha.
        """
        print(f"[Mock Solver] Solving hCaptcha for site key: {site_key} on {page_url}")
        # Simulate solving delay
        time.sleep(4)
        return "P0_eyJ0eXAiOiJKV1QiLCJhbG..."  # Mock response token

def captcha_solver_callback(captcha_type):
    """
    Callback function for solving CAPTCHAs using a third-party service.
    
    Args:
        captcha_type: Type of CAPTCHA detected
        
    Returns:
        True if CAPTCHA was solved, False otherwise
    """
    # Get API key from environment variable (for security)
    api_key = os.environ.get("CAPTCHA_SOLVER_API_KEY", "mock_api_key")
    
    # Create solver instance
    solver = MockCaptchaSolver(api_key)
    
    # Get current page information
    current_url = fuzzer.browser.current_url
    
    try:
        if captcha_type == 'recaptcha_v2':
            # Extract site key from the page
            site_key = fuzzer.browser.page.evaluate("""() => {
                const recaptchaDiv = document.querySelector('.g-recaptcha');
                return recaptchaDiv ? recaptchaDiv.getAttribute('data-sitekey') : null;
            }""")
            
            if not site_key:
                print("Could not find reCAPTCHA site key")
                return False
                
            # Solve the CAPTCHA
            token = solver.solve_recaptcha_v2(site_key, current_url)
            
            # Apply the solution
            fuzzer.browser.page.evaluate(f"""(token) => {{
                // Find the g-recaptcha-response textarea and set its value
                document.querySelector('#g-recaptcha-response').innerHTML = token;
                
                // Trigger the callback
                ___grecaptcha_cfg.clients[0].L.L.callback(token);
            }}""", token)
            
            return True
            
        elif captcha_type == 'recaptcha_v3':
            # Extract site key from the page
            site_key = fuzzer.browser.page.evaluate("""() => {
                const script = document.querySelector('script[src*="recaptcha/api.js?render="]');
                if (!script) return null;
                const src = script.getAttribute('src');
                return src.split('render=')[1].split('&')[0];
            }""")
            
            if not site_key:
                print("Could not find reCAPTCHA v3 site key")
                return False
                
            # Solve the CAPTCHA
            token = solver.solve_recaptcha_v3(site_key, current_url)
            
            # Apply the solution (this is more complex for v3 and depends on the site implementation)
            # This is a simplified example
            fuzzer.browser.page.evaluate(f"""(token) => {{
                // Find the grecaptcha object and set the token
                window.grecaptchaResponse = token;
            }}""", token)
            
            return True
            
        elif captcha_type == 'hcaptcha':
            # Extract site key from the page
            site_key = fuzzer.browser.page.evaluate("""() => {
                const hcaptchaDiv = document.querySelector('.h-captcha');
                return hcaptchaDiv ? hcaptchaDiv.getAttribute('data-sitekey') : null;
            }""")
            
            if not site_key:
                print("Could not find hCaptcha site key")
                return False
                
            # Solve the CAPTCHA
            token = solver.solve_hcaptcha(site_key, current_url)
            
            # Apply the solution
            fuzzer.browser.page.evaluate(f"""(token) => {{
                document.querySelector('[name="h-captcha-response"]').value = token;
                // Trigger form submission or callback
                hcaptcha.submit();
            }}""", token)
            
            return True
            
        else:
            print(f"Unsupported CAPTCHA type: {captcha_type}")
            return False
            
    except Exception as e:
        print(f"Error solving CAPTCHA: {e}")
        return False

def main():
    global fuzzer
    
    # Create a fuzzer instance with visible browser
    fuzzer = HumanFuzzer(headless=False)  # Set headless=False to see the browser
    
    try:
        # Start a fuzzing session
        fuzzer.start_session("https://example.com")
        
        # Authenticate with CAPTCHA handling
        fuzzer.authenticate(
            login_url="https://example.com/login",
            username_field="username",
            password_field="password",
            username="test_user",
            password="test_password",
            captcha_callback=captcha_solver_callback
        )
        
        # Fuzz the site with CAPTCHA handling
        results = fuzzer.fuzz_site(
            max_depth=2,
            max_pages=10,
            captcha_callback=captcha_solver_callback
        )
        
        # Print findings
        print(f"Found {len(results)} potential vulnerabilities")
        for finding in results:
            print(f"- {finding['type']} ({finding['severity']}): {finding['description']}")
            
        # Generate a report
        fuzzer.generate_report("vulnerability_report.html")
        print(f"Report saved to vulnerability_report.html")
        
    finally:
        # Always close the fuzzer to clean up resources
        fuzzer.close()

if __name__ == "__main__":
    main()
