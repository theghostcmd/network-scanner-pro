# Network Scanner Pro

A comprehensive network scanning tool for ethical hackers and security professionals, created by **GhostCmd**.

## Features

### Core Scanning Capabilities
- **Real-time Network Discovery**: ARP scanning, ICMP ping sweeps, TCP discovery
- **Comprehensive Port Scanning**: SYN, Connect, and UDP scanning
- **Service Detection**: Version detection and OS fingerprinting
- **Vulnerability Assessment**: CVE lookup, SSL/TLS checks, web vulnerability scanning

### Reporting
- **PDF Reports**: Professional reports with charts and executive summaries
- **HTML Reports**: Interactive web-based reports
- **CSV Export**: Data analysis-friendly format
- **Multiple Output Formats**: Customizable reporting options

### User Interface
- **Command-line Interface**: Color-coded output for easy reading
- **Interactive Mode**: Step-by-step guided scanning
- **Batch Mode**: Automated scanning of multiple targets
- **Progress Indicators**: Real-time scan progress updates

## Installation

### Kali Linux
```bash
# Clone the repository
git clone https://github.com/ghostcmd/network-scanner-pro.git
cd network-scanner-pro

# Install dependencies
sudo apt update
sudo apt install python3-pip
pip3 install -r requirements.txt

# Install nmap
sudo apt install nmap

# Run the tool
sudo python3 main.py --help