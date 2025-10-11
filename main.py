#!/usr/bin/env python3
"""
Network Scanner Pro - Comprehensive Network Scanning Tool
Created by GhostCmd
"""

import argparse
import sys
import time
import json
import logging
from colorama import Fore, Style, init
from scanners.network_scanner import NetworkScanner
from scanners.port_scanner import PortScanner
from scanners.vulnerability_scanner import VulnerabilityScanner
from utils.report_generator import ReportGenerator
from utils.config_loader import ConfigLoader
from utils.helpers import display_banner, validate_target, setup_logging

# Initialize colorama
init(autoreset=True)

class NetworkScannerPro:
    def __init__(self):
        self.config = ConfigLoader().load_config()
        self.results = {}
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_scanner.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def display_legal_warning(self):
        """Display legal disclaimer"""
        print(f"\n{Fore.RED}{Style.BRIGHT}" + "="*70)
        print("                   LEGAL WARNING AND DISCLAIMER")
        print("="*70)
        print(f"{Fore.YELLOW}")
        print("This tool is designed for ethical hacking and security assessment purposes only.")
        print("You must have explicit permission to scan the target network/system.")
        print("Unauthorized scanning may be illegal in your jurisdiction.")
        print("The creators are not responsible for any misuse of this tool.")
        print(f"{Fore.RED}")
        print("By using this tool, you agree to use it only on networks you own or have")
        print("explicit permission to test.")
        print("="*70 + f"{Style.RESET_ALL}\n")
        
        response = input(f"{Fore.GREEN}Do you agree to use this tool ethically and legally? (y/N): {Style.RESET_ALL}")
        if response.lower() != 'y':
            print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
            sys.exit(1)
    
    def network_discovery(self, target):
        """Perform network discovery"""
        print(f"\n{Fore.CYAN}[*] Starting Network Discovery...{Style.RESET_ALL}")
        network_scanner = NetworkScanner(self.config)
        hosts = network_scanner.scan(target)
        self.results['network_discovery'] = hosts
        return hosts
    
    def port_scanning(self, target, ports=None):
        """Perform port scanning"""
        print(f"\n{Fore.CYAN}[*] Starting Port Scanning...{Style.RESET_ALL}")
        port_scanner = PortScanner(self.config)
        if not ports:
            ports = "1-1000"
        port_results = port_scanner.scan(target, ports)
        self.results['port_scanning'] = port_results
        return port_results
    
    def vulnerability_assessment(self, target, port_results):
        """Perform vulnerability assessment"""
        print(f"\n{Fore.CYAN}[*] Starting Vulnerability Assessment...{Style.RESET_ALL}")
        vuln_scanner = VulnerabilityScanner(self.config)
        vuln_results = vuln_scanner.scan(target, port_results)
        self.results['vulnerability_assessment'] = vuln_results
        return vuln_results
    
    def generate_reports(self, output_format="all"):
        """Generate comprehensive reports"""
        print(f"\n{Fore.CYAN}[*] Generating Reports...{Style.RESET_ALL}")
        report_gen = ReportGenerator(self.config)
        report_paths = report_gen.generate_reports(self.results, output_format)
        return report_paths
    
    def interactive_mode(self):
        """Interactive scanning mode"""
        display_banner()
        self.display_legal_warning()
        
        print(f"{Fore.GREEN}[*] Interactive Mode Activated{Style.RESET_ALL}")
        
        # Get target
        target = input(f"\n{Fore.YELLOW}Enter target (IP/CIDR/hostname): {Style.RESET_ALL}").strip()
        if not validate_target(target):
            print(f"{Fore.RED}[!] Invalid target format{Style.RESET_ALL}")
            return
        
        # Get scan options
        print(f"\n{Fore.YELLOW}Scan Options:{Style.RESET_ALL}")
        print("1. Network Discovery Only")
        print("2. Network Discovery + Port Scanning")
        print("3. Full Assessment (Discovery + Ports + Vulnerabilities)")
        
        choice = input(f"\n{Fore.YELLOW}Select option (1-3): {Style.RESET_ALL}").strip()
        
        # Perform scans based on choice
        if choice in ['1', '2', '3']:
            hosts = self.network_discovery(target)
            
            if choice in ['2', '3']:
                for host in hosts:
                    if host['status'] == 'up':
                        port_results = self.port_scanning(host['ip'])
                        
                        if choice == '3':
                            self.vulnerability_assessment(host['ip'], port_results)
        
        # Generate reports
        self.generate_reports()
        
        print(f"\n{Fore.GREEN}[+] Scan completed successfully!{Style.RESET_ALL}")
    
    def batch_mode(self, target_file, scan_type="full"):
        """Batch scanning mode"""
        display_banner()
        self.display_legal_warning()
        
        print(f"{Fore.GREEN}[*] Batch Mode Activated{Style.RESET_ALL}")
        
        try:
            with open(target_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Target file not found{Style.RESET_ALL}")
            return
        
        for i, target in enumerate(targets, 1):
            print(f"\n{Fore.CYAN}[*] Scanning target {i}/{len(targets)}: {target}{Style.RESET_ALL}")
            
            try:
                hosts = self.network_discovery(target)
                
                if scan_type in ["full", "ports"]:
                    for host in hosts:
                        if host['status'] == 'up':
                            self.port_scanning(host['ip'])
                
                if scan_type == "full":
                    for host in hosts:
                        if host['status'] == 'up':
                            self.vulnerability_assessment(host['ip'], self.results.get('port_scanning', {}))
            
            except Exception as e:
                print(f"{Fore.RED}[!] Error scanning {target}: {str(e)}{Style.RESET_ALL}")
                continue
        
        self.generate_reports()
        print(f"\n{Fore.GREEN}[+] Batch scan completed!{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Network Scanner Pro - Created by GhostCmd')
    parser.add_argument('-t', '--target', help='Target IP/CIDR/hostname')
    parser.add_argument('-p', '--ports', help='Port range (e.g., 1-1000)', default='1-1000')
    parser.add_argument('-f', '--file', help='File containing list of targets')
    parser.add_argument('-m', '--mode', choices=['discovery', 'ports', 'full'], 
                       default='full', help='Scan mode')
    parser.add_argument('-o', '--output', choices=['pdf', 'html', 'csv', 'all'], 
                       default='all', help='Output format')
    parser.add_argument('--interactive', action='store_true', help='Interactive mode')
    parser.add_argument('--batch', action='store_true', help='Batch mode')
    
    args = parser.parse_args()
    
    scanner = NetworkScannerPro()
    
    try:
        if args.interactive:
            scanner.interactive_mode()
        elif args.batch and args.file:
            scanner.batch_mode(args.file, args.mode)
        elif args.target:
            display_banner()
            scanner.display_legal_warning()
            
            if args.mode in ['discovery', 'ports', 'full']:
                hosts = scanner.network_discovery(args.target)
                
                if args.mode in ['ports', 'full']:
                    for host in hosts:
                        if host['status'] == 'up':
                            scanner.port_scanning(host['ip'], args.ports)
                
                if args.mode == 'full':
                    for host in hosts:
                        if host['status'] == 'up':
                            scanner.vulnerability_assessment(host['ip'], 
                                                           scanner.results.get('port_scanning', {}))
            
            scanner.generate_reports(args.output)
            print(f"\n{Fore.GREEN}[+] Scan completed successfully!{Style.RESET_ALL}")
        
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Scan error: {str(e)}")

if __name__ == "__main__":
    main()