# HumanFuzz

A human-like web application fuzzing library that simulates real user interactions to discover security vulnerabilities. HumanFuzz provides both a Python API and a comprehensive command-line interface for scanning web applications and APIs.

## Features

- **Human-like Interaction**: Uses a headless browser to interact with web applications like a real user
- **Automatic Form Discovery**: Identifies and interacts with forms, buttons, and other interactive elements
- **Smart Payload Generation**: Generates and mutates payloads based on context and target responses
- **Multiple Vulnerability Classes**: Supports testing for XSS, SQL injection, SSRF, and more
- **Session Awareness**: Maintains authentication and session context throughout testing
- **Extensible Architecture**: Easily add custom payload modules and detection rules
- **Comprehensive Reporting**: Generates detailed reports of findings with proof-of-concept examples
- **Animated Interface**: Real-time visual feedback during scanning operations
- **Enhanced Protection Bypass**: Advanced techniques for bypassing web application firewalls and protections
- **Improved HTTP Handling**: Enhanced HTTP client for better request handling and performance

## Installation

### Basic Installation

```bash
pip install humanfuzz
```

### Enhanced Installation (Recommended)

```bash
# Install the required dependencies
pip install -r requirements.txt

# Install additional libraries for enhanced scanning
pip install humanfuzz[enhanced]
```

## Using the Python API

### Quick Start

```python
from humanfuzz import HumanFuzzer

# Create a fuzzer instance
fuzzer = HumanFuzzer()

# Start a fuzzing session
fuzzer.start_session("https://example.com")

# Authenticate (if needed)
fuzzer.authenticate(
    login_url="https://example.com/login",
    username_field="username",
    password_field="password",
    username="test_user",
    password="test_password"
)

# Discover and fuzz forms automatically
results = fuzzer.fuzz_site()

# Generate a report
fuzzer.generate_report("vulnerability_report.html")
```

### Enhanced API Usage

```python
from humanfuzz import HumanFuzzer

# Create an enhanced fuzzer instance
fuzzer = HumanFuzzer(
    headless=True,
    browser_type="chromium",
    bypass_cloudflare=True,  # Enable Cloudflare bypass
    enhanced_http=True       # Use enhanced HTTP client
)

# Start a fuzzing session
fuzzer.start_session("https://example.com")

# Perform API scanning
fuzzer.api_scan(
    base_url="https://api.example.com",
    endpoints=["/users", "/products", "/orders"],
    auth_headers={"Authorization": "Bearer YOUR_TOKEN"}
)

# Generate a comprehensive report
fuzzer.generate_report("vulnerability_report.html")
```

## Using the Command-Line Interface

HumanFuzz provides a comprehensive command-line interface for easy scanning operations.

### Basic Usage

```bash
humanfuzz_cli.py [-h] {scan,api,report,version} ...
```

### Commands

- `scan`: Scan a website for vulnerabilities
- `api`: Scan API endpoints
- `report`: Generate a report from saved results
- `version`: Show version information

### Scan Command

The `scan` command is used to scan a website for vulnerabilities:

```bash
humanfuzz_cli.py scan https://example.com [options]
```

#### Options

- `--depth, -d DEPTH`: Maximum crawl depth (default: 2)
- `--pages, -p PAGES`: Maximum pages to crawl (default: 10)
- `--visible, -v`: Show browser window
- `--simulate, -s`: Run in simulation mode (no actual browser)
- `--output, -o OUTPUT`: Output file for the report (default: auto-generated)
- `--format, -f {html,json,md}`: Report format (default: html)
- `--auth, -a`: Enable authentication
- `--username, -u USERNAME`: Username for authentication
- `--password, -pw PASSWORD`: Password for authentication
- `--login-url, -l LOGIN_URL`: Login URL (if different from main URL)
- `--username-field USERNAME_FIELD`: Username field name/ID (default: username)
- `--password-field PASSWORD_FIELD`: Password field name/ID (default: password)
- `--submit-button SUBMIT_BUTTON`: Submit button selector (optional)
- `--cookies, -c COOKIES`: Cookies to use (format: name1=value1;name2=value2)
- `--headers HEADERS`: Custom headers (format: name1=value1;name2=value2)
- `--user-agent USER_AGENT`: Custom User-Agent
- `--timeout TIMEOUT`: Request timeout in seconds (default: 30)
- `--delay DELAY`: Delay between requests in seconds (default: 0)
- `--bypass-cloudflare`: Enable Cloudflare bypass using cloudscraper25
- `--enhanced-http`: Use urllib4-enhanced for HTTP requests
- `--verbose`: Enable verbose output
- `--save-results SAVE_RESULTS`: Save raw results to JSON file

### API Command

The `api` command is used to scan API endpoints:

```bash
humanfuzz_cli.py api https://api.example.com [options]
```

#### Options

- `--endpoints, -e ENDPOINTS`: Comma-separated list of endpoints to scan
- `--endpoints-file ENDPOINTS_FILE`: File containing endpoints (one per line)
- `--methods, -m METHODS`: HTTP methods to use (comma-separated, default: GET,POST,PUT,DELETE)
- `--auth-type {none,basic,bearer,api-key}`: Authentication type
- `--auth-user AUTH_USER`: Username for Basic Auth
- `--auth-pass AUTH_PASS`: Password for Basic Auth
- `--auth-token AUTH_TOKEN`: Token for Bearer Auth
- `--api-key-name API_KEY_NAME`: API key header name (default: X-API-Key)
- `--api-key-value API_KEY_VALUE`: API key value
- `--headers HEADERS`: Custom headers (format: name1=value1;name2=value2)
- `--output, -o OUTPUT`: Output file for the report (default: auto-generated)
- `--format, -f {html,json,md}`: Report format (default: html)
- `--simulate, -s`: Run in simulation mode
- `--verbose`: Enable verbose output
- `--save-results SAVE_RESULTS`: Save raw results to JSON file

### Report Command

The `report` command is used to generate a report from saved results:

```bash
humanfuzz_cli.py report --input results.json --output report.html [options]
```

#### Options

- `--input, -i INPUT`: Input JSON file with scan results (required)
- `--output, -o OUTPUT`: Output report file (required)
- `--format, -f {html,json,md}`: Report format (default: html)
- `--template, -t TEMPLATE`: Custom template file for the report

### Version Command

The `version` command shows version information:

```bash
humanfuzz_cli.py version
```

## CLI Examples

### Basic Website Scan

```bash
humanfuzz_cli.py scan https://example.com
```

### Scan with Authentication

```bash
humanfuzz_cli.py scan https://example.com --auth --username admin --password secret
```

### Scan with Cloudflare Bypass and Enhanced HTTP

```bash
humanfuzz_cli.py scan https://example.com --bypass-cloudflare --enhanced-http
```

### API Scan with Bearer Authentication

```bash
humanfuzz_cli.py api https://api.example.com --endpoints /users,/products --auth-type bearer --auth-token "YOUR_TOKEN"
```

### Generate Report from Saved Results

```bash
humanfuzz_cli.py report --input scan_results.json --output vulnerability_report.html
```

## Enhanced Features

### Cloudflare Bypass

The `--bypass-cloudflare` option enables Cloudflare protection bypass. This allows scanning websites protected by Cloudflare, which would normally block automated scanning tools.

Benefits:
- Bypass Cloudflare's anti-bot protection
- Access protected content for scanning
- Maintain session context through Cloudflare challenges

### Enhanced HTTP Requests

The `--enhanced-http` option enables the use of enhanced HTTP libraries for requests, providing improved capabilities for more effective scanning.

Benefits:
- Automatic retry mechanisms for failed requests
- Better error handling and reporting
- Improved performance for large-scale scanning
- Enhanced cookie and session management
- Support for complex authentication schemes

## Advanced Usage

See the [documentation](https://humanfuzz.readthedocs.io) for advanced usage examples, including:

- Custom payload modules
- Targeted fuzzing of specific forms or endpoints
- Recording and replaying user flows
- Integration with CI/CD pipelines
- Creating custom scan profiles

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Copyright

© 2025 Powered By zinzied
