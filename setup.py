from setuptools import setup, find_packages

setup(
    name="humanfuzz",
    version="1.1.0",  # Updated with Cloudflare bypass and CAPTCHA handling
    packages=find_packages(),
    install_requires=[
        "playwright>=1.30.0",
        "beautifulsoup4>=4.10.0",
        "requests>=2.27.1",
        "rich>=12.0.0",
        "click>=8.0.0",
        "pydantic>=1.9.0",
    ],
    extras_require={
        "enhanced": [
            "cloudscraper25",
            "urllib4-enhanced",
        ],
        "captcha": [
            "2captcha-python",
            "anticaptchaofficial",
        ],
        "dev": [
            "pytest>=7.0.0",
            "flake8>=4.0.0",
            "black>=22.0.0",
            "sphinx>=4.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "humanfuzz=humanfuzz.cli:cli",
            "humanfuzz_cli=humanfuzz.cli_main:main",
        ],
    },
    author="zinzied",
    author_email="Ziedboughdir@gmail.com",
    description="A human-like web application fuzzing library that simulates real user interactions to discover security vulnerabilities",
    long_description=open("PYPI_README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/zinzied/humanfuzz",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
)
