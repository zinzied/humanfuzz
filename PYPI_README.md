# HumanFuzz

A human-like web application fuzzing library that simulates real user interactions to discover security vulnerabilities. HumanFuzz uses advanced browser automation to interact with web applications just like a real user would, making it highly effective at finding vulnerabilities that traditional scanners might miss.

## Features

- **Human-like Interaction**: Uses a headless browser to interact with web applications like a real user
- **Automatic Form Discovery**: Identifies and interacts with forms, buttons, and other interactive elements
- **Smart Payload Generation**: Generates and mutates payloads based on context and target responses
- **Comprehensive Vulnerability Detection**: Supports testing for XSS, SQL injection, CSRF, IDOR, and more
- **Session Awareness**: Maintains authentication and session context throughout testing
- **Extensible Architecture**: Easily add custom payload modules and detection rules
- **Comprehensive Reporting**: Generates detailed reports of findings with proof-of-concept examples
- **Animated Interface**: Real-time visual feedback during scanning operations
- **Enhanced Protection Bypass**: Integration with cloudscraper25 for Cloudflare bypass
- **CAPTCHA Handling**: Detection and handling of Google reCAPTCHA and other CAPTCHA challenges
- **Improved HTTP Handling**: Integration with urllib4-enhanced for better HTTP requests

## Installation

### Basic Installation

```bash
pip install humanfuzz
```

### Enhanced Installation (Recommended)

```bash
pip install humanfuzz[enhanced]
```

### CAPTCHA Handling Installation

```bash
pip install humanfuzz[captcha]
```

### Complete Installation (All Features)

```bash
pip install humanfuzz[enhanced,captcha]
```

## Quick Start

### Basic Usage

```python
from humanfuzz import HumanFuzzer

# Create a fuzzer instance
fuzzer = HumanFuzzer()

# Start a fuzzing session
fuzzer.start_session("https://example.com")

# Discover and fuzz forms automatically
results = fuzzer.fuzz_site()

# Generate a report
fuzzer.generate_report("vulnerability_report.html")
```

### Advanced Usage with Authentication

```python
from humanfuzz import HumanFuzzer

# Create a fuzzer instance with enhanced options
fuzzer = HumanFuzzer(
    headless=True,
    browser_type="chromium",
    bypass_cloudflare=True,                  # Enable Cloudflare bypass
    captcha_solver_api_key="YOUR_API_KEY",   # API key for CAPTCHA solving service (optional)
    enhanced_http=True                       # Use enhanced HTTP client
)

# Start a fuzzing session
fuzzer.start_session("https://example.com")

# Authenticate
fuzzer.authenticate(
    login_url="https://example.com/login",
    username_field="username",
    password_field="password",
    username="test_user",
    password="test_password"
)

# Discover and fuzz forms automatically
results = fuzzer.fuzz_site(max_depth=3, max_pages=20)

# Generate a report
fuzzer.generate_report("vulnerability_report.html")
```

## Command-Line Interface

HumanFuzz provides a comprehensive command-line interface:

### Basic Scan

```bash
humanfuzz scan https://example.com
```

### Advanced Scan with Authentication

```bash
humanfuzz scan https://example.com --auth --username admin --password secret
```

### Scan with Enhanced Options

```bash
humanfuzz scan https://example.com --depth 3 --pages 20 --bypass-cloudflare --enhanced-http
```

### Scan with CAPTCHA Handling

```bash
humanfuzz scan https://example.com --captcha-solver-key "YOUR_API_KEY" --screenshot ./screenshots
```

### Comprehensive Scan with All Protection Bypass Features

```bash
humanfuzz scan https://example.com --bypass-cloudflare --captcha-solver-key "YOUR_API_KEY" --screenshot ./screenshots --enhanced-http
```

### API Scanning

```bash
humanfuzz api https://api.example.com --endpoints /users,/products --auth-type bearer --auth-token YOUR_TOKEN
```

### Generate Report from Saved Results

```bash
humanfuzz report --input scan_results.json --output report.html
```

## Enhanced Vulnerability Payloads

HumanFuzz includes a comprehensive set of payloads for various vulnerability types:

### XSS (Cross-Site Scripting)
- Basic XSS payloads
- Advanced DOM-based XSS
- Filter evasion techniques
- Framework-specific payloads (Angular, React)

### SQLi (SQL Injection)
- Basic authentication bypass
- Error-based SQL injection
- Union-based SQL injection
- Blind SQL injection
- Database-specific payloads (MySQL, MSSQL, PostgreSQL, Oracle, SQLite)

### CSRF (Cross-Site Request Forgery)
- Form-based CSRF
- JSON-based CSRF
- Clickjacking techniques
- CORS bypass attempts

## Copyright

© 2025 Powered By zinzied
