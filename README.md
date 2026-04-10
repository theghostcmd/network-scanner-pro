Termux (Android)
# Update packages
pkg update && pkg upgrade

# Install dependencies
pkg install python nmap
pip install -r requirements.txt

# Run the tool
python main.py --help


Usage Examples
Basic Network Discovery
bash
sudo python3 main.py -t 192.168.1.0/24 -m discovery
Full Assessment
bash
sudo python3 main.py -t 192.168.1.100 -m full -p 1-1000
Interactive Mode
bash
python3 main.py --interactive
Batch Scanning
bash
# Create target file
echo "192.168.1.0/24" > targets.txt
echo "10.0.0.0/24" >> targets.txt

# Run batch scan
sudo python3 main.py --batch -f targets.txt -m full
Custom Port Range
bash
sudo python3 main.py -t 192.168.1.1 -p 22,80,443,8080 -m ports
Configuration
Edit config.json to customize scanning behavior:

json
{
    "scan_settings": {
        "default_timeout": 2,
        "max_threads": 100,
        "ping_sweep": true,
        "arp_scan": true,
        "syn_scan": true,
        "udp_scan": false
    }
}
Legal Disclaimer
This tool is designed for:

Security professionals conducting authorized penetration tests

Network administrators assessing their own networks

Educational purposes in controlled environments

You must have explicit permission to scan any network or system you don't own. Unauthorized scanning may be illegal in your jurisdiction.

Modules
Network Scanner
ARP discovery for local networks

ICMP ping sweeps

TCP discovery on common ports

MAC address and vendor identification

Port Scanner
Multi-threaded TCP SYN scanning (requires root)

TCP Connect scanning (non-root)

UDP port scanning

Service version detection

OS fingerprinting

Vulnerability Scanner
CVE database integration

SSL/TLS vulnerability checks

Web application security headers

Common service vulnerability detection

Output Examples
The tool generates comprehensive reports including:

Executive summaries for management

Technical details for security teams

Visual charts and statistics

Risk assessment and recommendations

Troubleshooting
Common Issues
Permission Errors: Use sudo for SYN scans on Linux

NMAP Not Found: Install nmap package

Missing Dependencies: Run pip install -r requirements.txt

Network Issues: Ensure proper network connectivity and permissions

Performance Tips
Limit port ranges for faster scans

Adjust thread count in configuration

Use specific scan types instead of full scans when possible

Contributing
Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

License
This tool is provided for educational and authorized security testing purposes only.

# Interactive mode
python main.py --interactive

# Network discovery only
python main.py -t 192.168.1.0/24 -m discovery


# Batch scanning
python main.py --batch -f targets.txt -m ful

l
# Full assessment with custom ports
sudo python main.py -t 192.168.1.1 -p 1-1000 -m full -o pdf
