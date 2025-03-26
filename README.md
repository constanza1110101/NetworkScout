# NetworkScout - Cybersecurity Tool

A powerful network reconnaissance tool designed for cybersecurity professionals to identify potential security vulnerabilities and map network infrastructure with comprehensive scanning capabilities.

## Security Audit

**Python Version:** 3.6+  
**License:** MIT  

## Overview

NetworkScout provides advanced network scanning and information-gathering capabilities, including port scanning, DNS enumeration, WHOIS lookup, and HTTP header analysis. It is an all-in-one tool designed for security researchers and penetration testers.

## Key Security Features

- **Advanced Port Scanning:** Detects running services with customizable port ranges.
- **DNS Intelligence:** Enumerates complete DNS records (A, AAAA, MX, NS, TXT, SOA).
- **WHOIS Analysis:** Retrieves domain registration and ownership details.
- **Header Security Analysis:** Verifies HTTP security headers.
- **Comprehensive Reporting:** Outputs structured results for seamless integration with other tools.
- **Multi-threaded Operations:** Optimized scanning for efficiency.

## Technical Features

- **High-Performance Scanning:** Configurable timeouts for fast and accurate results.
- **Flexible Target Selection:** Supports domains, IP addresses, and CIDR ranges.
- **Customizable Scan Profiles:** Predefined templates for different reconnaissance scenarios.
- **Export Flexibility:** Outputs scan results in JSON, CSV, or plain text.
- **Interactive CLI:** A rich console interface with progress tracking and formatted tables.
- **Low Footprint:** Minimal resource consumption for easy deployment in constrained environments.

## Installation

### Clone the Repository
```bash
git clone https://github.com/yourusername/NetworkScout.git
cd NetworkScout
```

### Create a Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

## Quick Start

### Basic Scan of a Domain
```bash
./networkscout.py example.com
```

### Scan Specific Ports with DNS Lookup
```bash
./networkscout.py 192.168.1.1 -p 80,443,8080 --dns
```

### Full Reconnaissance with All Features
```bash
./networkscout.py example.com -p 1-1000 --dns --whois --headers
```

## Scanning Features

### Scan Multiple Ports
```bash
./networkscout.py target.com -p 22,80,443,3389
```

### Scan Port Ranges
```bash
./networkscout.py target.com -p 1-1000
```

### Perform DNS Lookup
```bash
./networkscout.py target.com --dns
```

### Retrieve WHOIS Information
```bash
./networkscout.py target.com --whois
```

### Check HTTP Headers
```bash
./networkscout.py target.com --headers
```

## Requirements

- Python 3.6+
- nmap>=7.80
- dnspython>=2.2.0
- python-whois>=0.7.3
- requests>=2.27.1
- colorama>=0.4.4

## Compliance

NetworkScout assists security professionals with:

- Network vulnerability assessments
- Security perimeter mapping
- Open port discovery
- Domain intelligence gathering
- Certificate validation

## Contributing

Contributions are welcome! Please read `CONTRIBUTING.md` for guidelines.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

