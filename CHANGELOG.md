# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-05-13

### Added

- **CAPTCHA Handling**: Added support for detecting and handling various CAPTCHA challenges
  - Detection of Google reCAPTCHA v2, v3, and hCaptcha
  - Manual solving capability with browser interaction
  - Integration with external CAPTCHA solving services (2Captcha, Anti-Captcha)
  - Human-like behavior simulation to reduce CAPTCHA triggers

- **Cloudflare Bypass Integration**: Improved integration with cloudscraper25
  - Added proper error handling and fallback mechanisms
  - Automatic cookie transfer between cloudscraper and browser
  - Content injection from cloudscraper to browser

- **Screenshot Functionality**: Added screenshot capabilities for debugging
  - Command-line option to save screenshots to a specified directory
  - Automatic screenshots on authentication success/failure
  - Screenshot method with improved error handling

### Changed

- **CLI Interface**: Updated to include new CAPTCHA and Cloudflare bypass options
  - Added `--captcha-solver-key` option for external CAPTCHA solving services
  - Added `--screenshot` option for saving screenshots
  - Improved help text and documentation

- **Documentation**: Updated to reflect new features
  - Added detailed sections on CAPTCHA handling and Cloudflare bypass
  - Updated examples to demonstrate new features
  - Added installation instructions for CAPTCHA handling dependencies

### Fixed

- Improved error handling in browser navigation
- Fixed timeout issues when dealing with protected sites
- Enhanced robustness when dealing with JavaScript errors

## [1.0.0] - 2025-04-15

### Added

- Initial release of HumanFuzz
- Human-like web application fuzzing
- Automatic form discovery and interaction
- Smart payload generation and mutation
- Multiple vulnerability class detection
- Session-aware testing
- Comprehensive reporting
- Command-line interface
- Python API
