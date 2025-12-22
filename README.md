# WhatIf? - Automated Reconnaissance & Vulnerability Scanner

![WhatIf? Banner](https://img.shields.io/badge/WhatIf?-Security-red)
![Python Version](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL-blue)

**WhatIf?** is a comprehensive automated reconnaissance and vulnerability scanning tool designed for security professionals, penetration testers, and ethical hackers.

> ⚠️ **WARNING**: This tool is for authorized security testing and educational purposes only. Always obtain proper authorization before scanning any systems.

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
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Install Nmap (optional but recommended)**
```bash
# Ubuntu/Debian
sudo apt-get install nmap

# macOS
brew install nmap

# Windows (via WSL or download from nmap.org)
```

4. **Make the script executable**
```bash
chmod +x whatif.py
```

## 📖 Usage Examples

### Basic Scan
```bash
python3 whatif.py example.com
```

### Full Comprehensive Scan
```bash
python3 whatif.py example.com --full-scan --ports 1-65535
```

### Vulnerability Scan Only
```bash
python3 whatif.py example.com --vuln-only
```

### Quick Scan (Skip Intensive Checks)
```bash
python3 whatif.py example.com --quick
```

### Custom Output Directory
```bash
python3 whatif.py example.com --output ./scan_results
```

### Without Nmap (Socket Scanning Only)
```bash
python3 whatif.py example.com --no-nmap
```

## 🗂️ Output Structure

After running a scan, results are saved in the specified output directory (default: `whatif_results/`):

```
whatif_results/
├── example.com_recon.json          # Complete results in JSON format
├── subdomains.txt                  # List of discovered subdomains
├── emails.txt                      # Collected email addresses
├── open_ports.txt                  # Open ports and services
├── vulnerabilities.txt             # Detected vulnerabilities
├── sensitive_files.txt             # Exposed sensitive files
└── scan_report.md                  # Human-readable report
```

## 🔧 Advanced Configuration

### Rate Limiting
The tool includes basic delays between requests. For larger scans, you can modify the script to add more aggressive rate limiting.

### API Integration
Future versions may include integration with:
- VirusTotal API
- SecurityTrails API
- Shodan API
- Censys API

### Custom Wordlists
You can extend the subdomain enumeration by adding custom wordlists to the script.

## ⚠️ Legal and Ethical Use

### Authorized Testing Only
- Only scan systems you own or have explicit written permission to test
- Respect robots.txt and website terms of service
- Be aware of local laws and regulations (CFAA, GDPR, etc.)

### Responsible Disclosure
If you find vulnerabilities in systems you don't own:
1. Do not exploit them
2. Document your findings
3. Report them responsibly to the organization

## 🛡️ Security Considerations

### Tool Security
- Keep the tool updated
- Review the code before use
- Use in isolated environments when testing

### Scanning Ethics
- Limit scan intensity to avoid disrupting services
- Consider time of day for scanning production systems
- Keep detailed logs of all scanning activities

## 🔮 Future Roadmap

### Planned Features
- [ ] API key integration for enhanced reconnaissance
- [ ] Database for storing scan results
- [ ] Scheduled scanning capabilities
- [ ] Advanced vulnerability detection
- [ ] Report generation in multiple formats (PDF, HTML)
- [ ] Plugin system for custom modules

### Integration Targets
- [ ] Slack/Teams notifications
- [ ] JIRA integration for ticket creation
- [ ] SIEM integration for alerting
- [ ] Grafana dashboards for visualization

## :coffee: Buy Me a Coffee

[<img src="https://img.shields.io/badge/Buy_Me_A_Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black" width="200" />](https://www.buymeacoffee.com/samunana "Buy me a Coffee")

## :rocket: Follow Me

[![GitHub followers](https://img.shields.io/github/followers/Samucahub?style=social&label=Follow&maxAge=2592000)](https://github.com/Samucahub "Follow Me")
[![Twitter](https://img.shields.io/twitter/url?style=social&url=https%3A%2F%2Ftwitter.com%2FTechnicalShubam)](https://twitter.com/intent/tweet?text=Wow:&url=https://github.com/Samucahub/next-portfolio "Tweet")

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/NewFeature`)
3. Commit your changes (`git commit -m 'Add some NewFeature'`)
4. Push to the branch (`git push origin feature/NewFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Inspired by various open-source security tools
- Thanks to the security community for best practices
- Built with education and authorized testing in mind

**What If...** you could automate your reconnaissance? Now you can. 🚀
