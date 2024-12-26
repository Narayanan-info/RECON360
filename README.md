# RECON360 - Advanced Bug Bounty Hunting Recon Tool Kit

RECON360 is a powerful recon tool designed for bug bounty hunters and security researchers. It automates a series of tasks related to reconnaissance, including subdomain enumeration, URL collection, live endpoint checks, and file-type filtering. This tool integrates with several popular recon tools and performs the entire recon process with minimal user input.

## Features

- **Subdomain Enumeration**: Uses `subfinder` and `assetfinder` for discovering subdomains.
- **Live Subdomain Check**: Validates subdomains using `httpx` for active endpoints.
- **URL Collection**: Collects URLs from `waybackurls` and `gau`.
- **URL Filtering**: Filters and checks for specific file types such as `PHP`, `JSON`, `.env`, and `.log` files.
- **Live Endpoint Check**: Uses `httpx` to check live endpoints.
- **Automated Tool Installation**: If required tools are missing, the script will automatically install them.
- **Custom Output**: Saves results in a structured output folder for each domain.

## Installation

RECON360 requires Go to be installed on your system to run and install the necessary tools. Follow these steps to get started:

1. **Install Go:**:
   If Go is not installed, download and install it from [].

2. **Install RECON360:**:
   ```bash
   go install github.com/Narayanan-info/RECON360@main
   ```

3. **Install the necessary tools:**:
    The tool will automatically check and install missing tools such as `subfinder`, `assetfinder`, `httpx`, `waybackurls`, `gau`, and `uro`.
