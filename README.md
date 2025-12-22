# WhatIf? - Automated Reconnaissance & Vulnerability Scanner

![WhatIf? Banner](https://img.shields.io/badge/WhatIf?-Security_Scanner-red)
![Python Version](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL-blue)

**WhatIf?** is a comprehensive automated reconnaissance and vulnerability scanning tool designed for security professionals, penetration testers, and ethical hackers.

> ⚠️ **WARNING**: This tool is for authorized security testing purposes only. Always obtain proper authorization before scanning any systems.

## ✨ Features

### 🎯 Reconnaissance Modules
- **Subdomain Enumeration**: Multiple techniques including brute-force and certificate transparency
- **Network Scanning**: Nmap integration with socket scanning fallback
- **Email Collection**: WHOIS lookup and website scraping
- **S3 Bucket Discovery**: Check for open cloud storage buckets
- **WHOIS Information**: Gather domain registration details

### 🔍 Vulnerability Scanning
- **Security Headers**: Check for missing security headers
- **Sensitive Information**: Detect exposed credentials, API keys, and secrets
- **File Exposure**: Find sensitive files (.env, config files, backups)
- **HTTP Methods**: Test for dangerous HTTP methods
- **SQL Injection**: Basic SQL injection vector detection
- **XSS Testing**: Reflected XSS vulnerability checking
- **Technology Detection**: Identify web technologies with known vulnerabilities

### 🎨 Unique Interface
- Color-coded terminal output with "bizarre" styling
- Progress bars with random characters
- Categorized status messages (info, success, warning, error, vulnerability)
- Comprehensive report generation

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Nmap (optional but recommended for full network scanning)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/WhatIf.git
cd WhatIf
