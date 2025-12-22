#!/usr/bin/env python3
"""
WhatIf? - Automated Reconnaissance & Vulnerability Scanner
Author: The Arquitect
Version: 1.0
Description: Performs passive and active reconnaissance with web vulnerability scanning
Important: Use only on systems you own or have explicit permission to test
"""

import sys
import os
import json
import time
import socket
import requests
import subprocess
import argparse
import re
import random
import platform
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BLINK = '\033[5m'

if platform.system() == "Windows":
    try:
        import colorama
        colorama.init()
    except ImportError:
        Colors.RED = Colors.GREEN = Colors.YELLOW = Colors.BLUE = ""
        Colors.MAGENTA = Colors.CYAN = Colors.WHITE = Colors.BOLD = ""
        Colors.UNDERLINE = Colors.RESET = Colors.BG_RED = ""
        Colors.BG_GREEN = Colors.BG_YELLOW = Colors.BLINK = ""

try:
    import requests
    from bs4 import BeautifulSoup
    import whois
    import dns.resolver
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print(f"[*] Install with: pip install -r requirements.txt")
    sys.exit(1)

class Interface:
    
    @staticmethod
    def show_banner():
        banner = f"""
{Colors.MAGENTA}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║    ██╗    ██╗██╗  ██╗ █████╗ ████████╗██╗███████╗██╗███████╗     ║
║    ██║    ██║██║  ██║██╔══██╗╚══██╔══╝██║██╔════╝██║██╔════╝     ║
║    ██║ █╗ ██║███████║███████║   ██║   ██║█████╗  ██║███████╗     ║
║    ██║███╗██║██╔══██║██╔══██║   ██║   ██║██╔══╝  ██║╚════██║     ║
║    ╚███╔███╔╝██║  ██║██║  ██║   ██║   ██║██║     ██║███████║     ║
║     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝     ╚═╝╚══════╝     ║
║                                                                  ║
║           AUTOMATED RECONNAISSANCE & VULNERABILITY SCANNER       ║
║                     Version 2.1 | What If...?                    ║
║           For Authorized Security Testing Only!                  ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}
        """
        print(banner)
    
    @staticmethod
    def show_status(message: str, status_type: str = "info"):
        symbols = {
            "info": f"{Colors.BLUE}[*]{Colors.RESET}",
            "success": f"{Colors.GREEN}[+]{Colors.RESET}",
            "error": f"{Colors.RED}[!]{Colors.RESET}",
            "warning": f"{Colors.YELLOW}[~]{Colors.RESET}",
            "crazy": f"{Colors.MAGENTA}[#]{Colors.RESET}",
            "vuln": f"{Colors.RED}{Colors.BLINK}[VULN]{Colors.RESET}"
        }
        
        symbol = symbols.get(status_type, symbols["info"])
        print(f"{symbol} {message}")
    
    @staticmethod
    def progress(total: int, current: int, text: str = "Progress"):
        if total == 0:
            return
            
        percentage = int((current / total) * 100)
        bars = int(percentage / 5)
        
        characters = ["▓", "▒", "░", "█", "▄", "▀", "■", "□", "◘", "○"]
        filled_char = random.choice(characters)
        empty_char = random.choice(characters)
        
        bar = f"{Colors.CYAN}{filled_char * bars}{Colors.WHITE}{empty_char * (20 - bars)}{Colors.RESET}"
        print(f"\r{Colors.YELLOW}[{bar}] {percentage}% - {text}", end="")
        
        if current >= total:
            print()
    
    @staticmethod
    def show_section(title: str):
        print(f"\n{Colors.CYAN}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.MAGENTA}{Colors.BOLD}{title.center(80)}{Colors.RESET}")
        print(f"{Colors.CYAN}{'═' * 80}{Colors.RESET}")

class WhatIfScanner:
    def __init__(self, domain: str, output_dir: str = "whatif_results"):
        self.domain = domain
        self.output_dir = output_dir
        self.interface = Interface()
        self.results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "subdomains": [],
            "open_ports": [],
            "services": [],
            "emails": [],
            "s3_buckets": [],
            "vulnerabilities": [],
            "whois_info": {},
            "web_technologies": [],
            "exposed_files": [],
            "security_headers": []
        }

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WhatIfScanner/2.1',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }

        self.is_windows = platform.system() == "Windows"
    
    def save_results(self):
        filename = os.path.join(self.output_dir, f"{self.domain}_recon.json")
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=4, default=str, ensure_ascii=False)
        
        self.interface.show_status(f"Results saved to {filename}", "success")
        
        self._save_to_file("subdomains.txt", "\n".join(self.results["subdomains"]))
        self._save_to_file("emails.txt", "\n".join(self.results["emails"]))
        
        if self.results["open_ports"]:
            self._save_to_file("open_ports.txt", 
                             "\n".join([f"{p['port']}:{p['service']}" for p in self.results["open_ports"]]))
        
        if self.results["vulnerabilities"]:
            self._save_to_file("vulnerabilities.txt", 
                             "\n".join([f"{v['type']}: {v['description']}" for v in self.results["vulnerabilities"]]))
    
    def _save_to_file(self, filename: str, content: str):
        path = os.path.join(self.output_dir, filename)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def enumerate_subdomains(self) -> List[str]:
        self.interface.show_status(f"Enumerating subdomains for {self.domain}", "crazy")
        
        subdomains = set()
        
        common_subs = [
            "www", "mail", "ftp", "admin", "webmail", "server", "ns1", "ns2",
            "blog", "dev", "test", "staging", "api", "secure", "portal", "cpanel",
            "web", "app", "mobile", "cloud", "storage", "backup", "db", "mysql",
            "panel", "system", "intranet", "vpn", "mail2", "ns3", "mx", "mx1",
            "owa", "exchange", "sharepoint", "git", "jenkins", "docker"
        ]
        
        total = len(common_subs)
        for i, sub in enumerate(common_subs):
            self.interface.progress(total, i + 1, f"Testing {sub}.{self.domain}")
            test_domain = f"{sub}.{self.domain}"
            try:
                socket.gethostbyname(test_domain)
                subdomains.add(test_domain)
                self.interface.show_status(f"Subdomain found: {test_domain}", "success")
            except (socket.gaierror, socket.timeout):
                continue
        
        self.interface.show_status("Analyzing SSL certificates...", "info")
        self._enumerate_ssl_certificates(subdomains)
        
        self.results["subdomains"] = list(subdomains)
        return list(subdomains)
    
    def _enumerate_ssl_certificates(self, subdomains: set):
        certificate_patterns = [
            f"*.{self.domain}",
            f"mail.{self.domain}",
            f"autodiscover.{self.domain}",
            f"lyncdiscover.{self.domain}",
            f"sip.{self.domain}",
            f"enterpriseenrollment.{self.domain}",
            f"enterpriseregistration.{self.domain}",
            f"remote.{self.domain}",
            f"vpn.{self.domain}",
            f"secure.{self.domain}"
        ]
        
        for pattern in certificate_patterns:
            subdomains.add(pattern.replace("*.", ""))
            self.interface.show_status(f"Certificate pattern: {pattern}", "info")
    
    def scan_s3_buckets(self) -> List[Dict]:
        self.interface.show_status(f"Scanning S3 buckets related to {self.domain}", "warning")
        
        buckets = []
        
        bucket_patterns = [
            f"{self.domain}",
            f"www.{self.domain}",
            f"assets.{self.domain}",
            f"media.{self.domain}",
            f"storage.{self.domain}",
            f"s3.{self.domain}",
            f"bucket-{self.domain}",
            f"{self.domain.replace('.', '-')}-assets",
            f"{self.domain.replace('.', '')}assets",
            f"prod-{self.domain}",
            f"dev-{self.domain}",
            f"test-{self.domain}",
            f"staging-{self.domain}",
            f"backup-{self.domain}"
        ]
        
        endpoints = [
            "s3.amazonaws.com",
            "s3-website-us-east-1.amazonaws.com",
            "s3-website-us-west-2.amazonaws.com",
            "digitaloceanspaces.com",
            "blob.core.windows.net",
            "storage.googleapis.com"
        ]
        
        total = len(bucket_patterns) * len(endpoints)
        current = 0
        
        for pattern in bucket_patterns:
            for endpoint in endpoints:
                current += 1
                self.interface.progress(total, current, f"Testing {pattern}")
                
                test_url = f"https://{pattern}.{endpoint}"
                try:
                    response = requests.head(test_url, timeout=3, headers=self.headers)
                    if response.status_code in [200, 403]:
                        buckets.append({
                            "url": test_url,
                            "status": response.status_code,
                            "public": response.status_code == 200
                        })
                        bucket_type = "PUBLIC" if response.status_code == 200 else "RESTRICTED"
                        self.interface.show_status(f"{bucket_type} bucket: {test_url}", "success")
                except (requests.RequestException, requests.exceptions.Timeout):
                    continue
        
        self.results["s3_buckets"] = buckets
        return buckets
    
    def network_scan(self, ports: str = "1-1000") -> List[Dict]:
        self.interface.show_status(f"Network scanning for {self.domain}", "crazy")
        
        open_ports = []
        
        try:
            ip_address = socket.gethostbyname(self.domain)
            self.interface.show_status(f"Resolved to IP: {ip_address}", "success")
        except socket.gaierror:
            self.interface.show_status(f"Could not resolve {self.domain}", "error")
            return []
        
        if self._check_nmap_installed():
            try:
                self.interface.show_status(f"Running nmap scan on {ip_address}", "info")
                
                encoding = 'cp850' if self.is_windows else 'utf-8'
                
                result = subprocess.run(
                    ["nmap", "-sS", "-sV", "-p", ports, "-T4", "--open", ip_address],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    encoding=encoding,
                    errors='replace'
                )
                
                if result.stdout:
                    for line in result.stdout.split('\n'):
                        if '/tcp' in line and 'open' in line:
                            parts = line.split()
                            if parts:
                                port_info = parts[0].split('/')
                                if len(port_info) > 0:
                                    try:
                                        port = int(port_info[0])
                                        service = port_info[-1] if len(port_info) > 1 else "unknown"
                                        
                                        version = ""
                                        if len(parts) > 2:
                                            version = " ".join(parts[2:])
                                        
                                        port_data = {
                                            "port": port,
                                            "service": service,
                                            "state": "open",
                                            "version": version,
                                            "banner": self._get_banner(ip_address, port)
                                        }
                                        open_ports.append(port_data)
                                        self.interface.show_status(f"Open port: {port}/{service}", "success")
                                    except (ValueError, IndexError):
                                        continue
                
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.interface.show_status("Nmap scan failed or timed out", "warning")
                open_ports = self._socket_scan(ip_address, ports)
        else:
            self.interface.show_status("Nmap not found, using socket scanning", "warning")
            open_ports = self._socket_scan(ip_address, ports)
        
        self.results["open_ports"] = open_ports
        return open_ports
    
    def _check_nmap_installed(self) -> bool:
        try:
            if self.is_windows:
                common_paths = [
                    "C:\\Program Files (x86)\\Nmap\\nmap.exe",
                    "C:\\Program Files\\Nmap\\nmap.exe",
                    "nmap.exe",
                    "nmap"
                ]
                for path in common_paths:
                    try:
                        subprocess.run([path, "--version"], capture_output=True, timeout=5)
                        return True
                    except:
                        continue
                return False
            else:
                result = subprocess.run(["which", "nmap"], capture_output=True, text=True)
                return result.returncode == 0
        except:
            return False
    
    def _socket_scan(self, ip: str, ports_range: str) -> List[Dict]:
        open_ports = []
        
        try:
            if '-' in ports_range:
                start, end = map(int, ports_range.split('-'))
                ports_to_scan = range(start, min(end, 1000) + 1)
            else:
                ports_to_scan = [int(ports_range)]
        except ValueError:
            ports_to_scan = self._get_common_ports()
        
        total = len(ports_to_scan)
        for i, port in enumerate(ports_to_scan):
            self.interface.progress(total, i + 1, f"Scanning port {port}")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    banner = self._get_banner(ip, port)
                    service = self._port_to_service(port)
                    
                    port_data = {
                        "port": port,
                        "service": service,
                        "state": "open",
                        "version": "",
                        "banner": banner
                    }
                    open_ports.append(port_data)
                    self.interface.show_status(f"Open port: {port}/{service}", "success")
                
                sock.close()
            except (socket.timeout, socket.error):
                continue
        
        return open_ports
    
    def _get_common_ports(self) -> List[int]:
        return [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
            465, 587, 993, 995, 1433, 1521, 3306, 3389, 
            5432, 5900, 5985, 5986, 6379, 8080, 8443, 8888, 9000,
            27017, 11211, 2049, 161, 162, 389, 636, 5060, 5061
        ]
    
    def _get_banner(self, ip: str, port: int) -> str:
        try:
            socket.setdefaulttimeout(2)
            s = socket.socket()
            s.connect((ip, port))
            
            if port == 80 or port == 443 or port == 8080:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                s.send(b"\r\n")
            elif port == 22:
                s.send(b"SSH-2.0-Client\r\n")
            elif port == 25:
                s.send(b"EHLO example.com\r\n")
            
            try:
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            except UnicodeDecodeError:
                banner = s.recv(1024).decode('latin-1', errors='ignore').strip()
            
            s.close()
            return banner[:200]
        except:
            return ""
    
    def _port_to_service(self, port: int) -> str:
        service_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
            465: "smtps", 587: "smtp-sub", 993: "imaps", 995: "pop3s",
            1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 5900: "vnc", 5985: "winrm", 5986: "winrm-ssl",
            6379: "redis", 8080: "http-alt", 8443: "https-alt", 8888: "sun-answerbook",
            9000: "hadoop", 27017: "mongodb", 11211: "memcached", 2049: "nfs",
            161: "snmp", 162: "snmptrap", 389: "ldap", 636: "ldaps",
            5060: "sip", 5061: "sips"
        }
        return service_map.get(port, "unknown")
    
    def collect_emails(self) -> List[str]:
        self.interface.show_status(f"Collecting emails for {self.domain}", "info")
        
        emails = set()
        
        try:
            w = whois.whois(self.domain)
            if w.emails:
                if isinstance(w.emails, list):
                    for email in w.emails:
                        if email and '@' in str(email):
                            emails.add(str(email).lower().strip())
                else:
                    if w.emails and '@' in str(w.emails):
                        emails.add(str(w.emails).lower().strip())
                
                self.results["whois_info"] = {
                    "registrar": w.registrar,
                    "creation_date": str(w.creation_date) if w.creation_date else None,
                    "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                    "org": w.org,
                    "address": w.address
                }
                
                self.interface.show_status("WHOIS information obtained", "success")
        except Exception as e:
            self.interface.show_status(f"WHOIS lookup failed: {e}", "warning")

        urls_to_test = [
            f"http://{self.domain}",
            f"https://{self.domain}",
            f"http://www.{self.domain}",
            f"https://www.{self.domain}"
        ]
        
        for url in urls_to_test:
            try:
                response = requests.get(url, headers=self.headers, timeout=5, verify=False)
                
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                found_emails = re.findall(email_pattern, response.text, re.IGNORECASE)
                for email in found_emails:
                    emails.add(email.lower().strip())
                
                mailto_pattern = r'mailto:([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})'
                mailto_emails = re.findall(mailto_pattern, response.text, re.IGNORECASE)
                for email in mailto_emails:
                    emails.add(email.lower().strip())
                    
            except requests.RequestException:
                continue
        
        common_users = ["admin", "webmaster", "info", "support", "contact", 
                       "sales", "help", "postmaster", "hostmaster", "administrator",
                       "helpdesk", "noc", "security", "abuse"]
        
        for user in common_users:
            emails.add(f"{user}@{self.domain}")
            clean_domain = self.domain.replace('www.', '')
            emails.add(f"{user}@{clean_domain}")
        
        self.results["emails"] = list(emails)
        
        for email in emails:
            self.interface.show_status(f"Email found: {email}", "success")
        
        return list(emails)
    
    def scan_web_vulnerabilities(self) -> List[Dict]:
        self.interface.show_status(f"Scanning web vulnerabilities for {self.domain}", "vuln")
        
        vulnerabilities = []

        base_urls = [
            f"http://{self.domain}",
            f"https://{self.domain}",
            f"http://www.{self.domain}",
            f"https://www.{self.domain}"
        ]
        
        successful_urls = []
        
        for base_url in base_urls:
            try:
                response = requests.get(base_url, headers=self.headers, timeout=10, verify=False)
                successful_urls.append(base_url)
                
                if response.status_code == 200:
                    vulnerabilities.extend(self._check_security_headers(base_url, response.headers))
                    
                    vulnerabilities.extend(self._check_sensitive_information(base_url, response.text))
                    
                    vulnerabilities.extend(self._check_technologies(base_url, response.headers, response.text))
                
                vulnerabilities.extend(self._check_sensitive_files(base_url))
                
            except requests.RequestException as e:
                self.interface.show_status(f"Failed to test {base_url}: {e}", "warning")
                continue
        
        if successful_urls:
            for url in successful_urls[:1]:
                try:
                    vulnerabilities.extend(self._check_http_methods(url))
                    
                    vulnerabilities.extend(self._check_sql_injection(url))
                    
                    vulnerabilities.extend(self._check_xss(url))
                    
                except requests.RequestException:
                    continue
        
        self.results["vulnerabilities"] = vulnerabilities
        return vulnerabilities
    
    def _check_security_headers(self, url: str, headers: Dict) -> List[Dict]:
        vulnerabilities = []
        
        required_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": None,
            "Content-Security-Policy": None
        }
        
        for header, expected_value in required_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    "type": "Missing Security Header",
                    "severity": "Medium",
                    "description": f"Header {header} is not present in {url}",
                    "recommendation": f"Add {header} header to HTTP response"
                })
                self.interface.show_status(f"Missing header: {header}", "warning")
        
        return vulnerabilities
    
    def _check_sensitive_information(self, url: str, content: str) -> List[Dict]:
        vulnerabilities = []
        
        sensitive_patterns = {
            "password": ["password", "passwd", "pwd", "secret"],
            "api_key": ["api_key", "apikey", "access_key", "secret_key"],
            "token": ["token", "jwt", "bearer", "oauth", "access_token"],
            "private_key": ["-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----"]
        }
        
        for info_type, patterns in sensitive_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    vulnerabilities.append({
                        "type": "Sensitive Information Exposed",
                        "severity": "High",
                        "description": f"Possible {info_type} leakage found in {url}",
                        "recommendation": "Remove sensitive information from source code"
                    })
                    self.interface.show_status(f"Sensitive info: {info_type}", "vuln")
                    break
        
        return vulnerabilities
    
    def _check_sensitive_files(self, base_url: str) -> List[Dict]:
        vulnerabilities = []
        
        sensitive_files = [
            "/.git/HEAD",
            "/.env",
            "/.htaccess",
            "/.htpasswd",
            "/phpinfo.php",
            "/info.php",
            "/config.php",
            "/database.php",
            "/wp-config.php",
            "/robots.txt",
            "/sitemap.xml",
            "/admin/",
            "/administrator/",
            "/phpmyadmin/",
            "/server-status",
            "/web.config"
        ]
        
        for file_path in sensitive_files:
            url = urljoin(base_url, file_path)
            try:
                response = requests.get(url, headers=self.headers, timeout=3, verify=False)
                if response.status_code == 200:
                    size = len(response.content)
                    if size > 100:
                        severity = "High" if any(x in file_path for x in [".env", "config", ".git"]) else "Medium"
                        vulnerabilities.append({
                            "type": "Sensitive File Exposed",
                            "severity": severity,
                            "description": f"Sensitive file found: {url} ({size} bytes)",
                            "recommendation": f"Remove or restrict access to {file_path}"
                        })
                        self.interface.show_status(f"Sensitive file: {file_path}", "vuln")
            except requests.RequestException:
                continue
        
        return vulnerabilities
    
    def _check_http_methods(self, url: str) -> List[Dict]:
        vulnerabilities = []
        
        dangerous_methods = ["PUT", "DELETE", "TRACE"]
        
        for method in dangerous_methods:
            try:
                response = requests.request(method, url, headers=self.headers, timeout=3, verify=False)
                if response.status_code not in [405, 501]:
                    vulnerabilities.append({
                        "type": "Dangerous HTTP Method Enabled",
                        "severity": "Medium",
                        "description": f"Method {method} allowed on {url} (Status: {response.status_code})",
                        "recommendation": f"Disable method {method} on web server"
                    })
                    self.interface.show_status(f"Dangerous method: {method}", "warning")
            except requests.RequestException:
                continue
        
        return vulnerabilities
    
    def _check_sql_injection(self, url: str) -> List[Dict]:
        vulnerabilities = []
        
        try:
            response = requests.get(url, headers=self.headers, timeout=3, verify=False)

            sql_errors = [
                "SQL syntax",
                "mysql_fetch",
                "ORA-",
                "PostgreSQL",
                "SQLite",
                "Unclosed quotation mark"
            ]
            
            for error in sql_errors:
                if error.lower() in response.text.lower():
                    vulnerabilities.append({
                        "type": "Possible SQL Injection Vulnerability",
                        "severity": "High",
                        "description": f"SQL error message found in response from {url}",
                        "recommendation": "Implement proper input validation and parameterized queries"
                    })
                    self.interface.show_status(f"SQL error detected", "vuln")
                    break
                    
        except requests.RequestException:
            pass
        
        return vulnerabilities
    
    def _check_xss(self, url: str) -> List[Dict]:
        vulnerabilities = []
        
        test_params = ["q", "search", "query", "id"]
        
        for param in test_params:
            test_url = f"{url}?{param}=test"
            try:
                response = requests.get(test_url, headers=self.headers, timeout=3, verify=False)
                
                if "test" in response.text:
                    dangerous_patterns = [
                        f'>{test_url}<',
                        f'"{test_url}"',
                        f"'{test_url}'",
                        f'={test_url}'
                    ]
                    
                    for pattern in dangerous_patterns:
                        if pattern in response.text:
                            vulnerabilities.append({
                                "type": "Possible XSS Vulnerability",
                                "severity": "Medium",
                                "description": f"Parameter {param} is reflected without encoding in {url}",
                                "recommendation": "Implement proper output encoding"
                            })
                            self.interface.show_status(f"Reflected parameter: {param}", "warning")
                            break
                            
            except requests.RequestException:
                continue
        
        return vulnerabilities
    
    def _check_technologies(self, url: str, headers: Dict, content: str) -> List[Dict]:
        vulnerabilities = []
        detected_tech = []
        
        technologies = {
            "WordPress": ["wp-content", "wordpress", "wp-includes", "/wp-"],
            "Joomla": ["joomla", "Joomla", "/media/jui/"],
            "Drupal": ["Drupal", "drupal", "sites/all/"],
            "Apache": ["Apache", "apache", "Server: Apache"],
            "Nginx": ["nginx", "Server: nginx"],
            "PHP": ["PHP", "php", ".php", "X-Powered-By: PHP"]
        }
        
        for tech, indicators in technologies.items():
            for indicator in indicators:
                if (indicator in content or 
                    any(indicator.lower() in str(v).lower() for v in headers.values())):
                    detected_tech.append(tech)
                    vulnerabilities.append({
                        "type": "Technology Detected",
                        "severity": "Informational",
                        "description": f"{tech} detected on {url}",
                        "recommendation": f"Ensure {tech} is updated to latest version"
                    })
                    self.interface.show_status(f"Technology detected: {tech}", "info")
                    break
        
        self.results["web_technologies"] = detected_tech
        return vulnerabilities
    
    def generate_report(self):
        self.interface.show_section("WHATIF? SCAN REPORT")
        
        print(f"{Colors.YELLOW}Target Domain:{Colors.WHITE} {self.domain}")
        print(f"{Colors.YELLOW}Scan Time:{Colors.WHITE} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.CYAN}{'-'*80}{Colors.RESET}")
        
        print(f"{Colors.GREEN}✓ Subdomains Found:{Colors.WHITE} {len(self.results['subdomains'])}")
        print(f"{Colors.GREEN}✓ Open Ports:{Colors.WHITE} {len(self.results['open_ports'])}")
        print(f"{Colors.GREEN}✓ Emails Collected:{Colors.WHITE} {len(self.results['emails'])}")
        print(f"{Colors.GREEN}✓ S3 Buckets:{Colors.WHITE} {len(self.results['s3_buckets'])}")
        print(f"{Colors.RED}⚠ Vulnerabilities:{Colors.WHITE} {len(self.results['vulnerabilities'])}")

        if self.results["open_ports"]:
            print(f"\n{Colors.BLUE}{Colors.BOLD}OPEN PORTS:{Colors.RESET}")
            for port_info in self.results["open_ports"]:
                service_color = Colors.GREEN if port_info['service'] in ['http', 'https'] else Colors.YELLOW
                print(f"  {Colors.GREEN}▶{Colors.RESET} Port {port_info['port']}: {service_color}{port_info['service']}{Colors.RESET}")
                if port_info.get('version'):
                    print(f"    Version: {port_info['version'][:50]}")

        critical_vulns = [v for v in self.results["vulnerabilities"] if v["severity"] in ["Critical", "High"]]
        if critical_vulns:
            print(f"\n{Colors.RED}{Colors.BLINK}CRITICAL FINDINGS:{Colors.RESET}")
            for vuln in critical_vulns:
                print(f"\n  {Colors.RED}▶ {vuln['type']}{Colors.RESET}")
                print(f"    {vuln['description']}")
                print(f"    {Colors.CYAN}Recommendation:{Colors.RESET} {vuln['recommendation']}")
        
        if self.results["subdomains"]:
            print(f"\n{Colors.CYAN}{Colors.BOLD}SUBDOMAINS:{Colors.RESET}")
            for i, sub in enumerate(self.results["subdomains"][:10], 1):
                print(f"  {i:2d}. {sub}")

        if self.results["emails"]:
            print(f"\n{Colors.MAGENTA}{Colors.BOLD}EMAILS FOUND:{Colors.RESET}")
            for email in self.results["emails"][:10]:
                print(f"  ✉ {email}")
        
        print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
        print(f"{Colors.GREEN}Complete report saved in: {self.output_dir}/{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(
        description="WhatIf? - Automated Reconnaissance & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com --full-scan
  %(prog)s example.com --ports 1-1000 --output ./scan_results
        
Legal Warning:
  This tool is for educational purposes and authorized testing only.
  Never use on systems you don't own or have explicit permission to test.
        """
    )
    
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("-p", "--ports", default="1-1000", 
                       help="Port range to scan (default: 1-1000)")
    parser.add_argument("-o", "--output", default="whatif_results",
                       help="Output directory (default: whatif_results)")
    parser.add_argument("--full-scan", action="store_true",
                       help="Perform comprehensive scanning")
    parser.add_argument("--no-nmap", action="store_true",
                       help="Skip nmap scanning")
    parser.add_argument("--vuln-only", action="store_true",
                       help="Only scan for web vulnerabilities")
    parser.add_argument("--quick", action="store_true",
                       help="Quick scan (skip intensive checks)")
    
    args = parser.parse_args()
    
    Interface.show_banner()
    
    scanner = WhatIfScanner(args.domain, args.output)
    
    try:
        scanner.interface.show_status(f"Starting reconnaissance on {args.domain}", "crazy")
        
        if args.vuln_only:
            scanner.scan_web_vulnerabilities()
        else:
            scanner.enumerate_subdomains()
            
            if not args.quick:
                scanner.scan_s3_buckets()
            
            scanner.collect_emails()
            
            if not args.no_nmap:
                scanner.network_scan(args.ports)

            scanner.scan_web_vulnerabilities()
        
        scanner.save_results()
        scanner.generate_report()
        
        scanner.interface.show_status("Scan completed successfully!", "success")
        scanner.interface.show_status(f"Check '{args.output}' directory for detailed results", "info")
        
    except KeyboardInterrupt:
        scanner.interface.show_status("\n[!] Scan interrupted by user", "error")
        scanner.save_results()
        sys.exit(0)
    except Exception as e:
        scanner.interface.show_status(f"\n[!] Error: {str(e)}", "error")
        import traceback
        traceback.print_exc()
        scanner.save_results()
        sys.exit(1)

if __name__ == "__main__":
    main()
