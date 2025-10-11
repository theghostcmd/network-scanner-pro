"""
Port Scanner Module for Network Scanner Pro
Created by GhostCmd
"""

import threading
import socket
import nmap
from colorama import Fore, Style
import logging
from utils.helpers import parse_ports, print_progress

class PortScanner:
    def __init__(self, config):
        self.config = config
        self.nm = nmap.PortScanner()
        self.results = {}
    
    def syn_scan(self, target, ports):
        """Perform TCP SYN scan"""
        try:
            print(f"{Fore.YELLOW}[*] Performing TCP SYN scan on {target}...{Style.RESET_ALL}")
            
            # Convert port list to string
            port_str = ','.join(map(str, ports))
            
            # Perform SYN scan
            scan_args = f"-sS -T4 --min-rate {self.config['network_settings']['rate_limit']}"
            
            if self.config['scan_settings']['service_detection']:
                scan_args += " -sV"
            if self.config['scan_settings']['os_detection']:
                scan_args += " -O"
            
            self.nm.scan(hosts=target, ports=port_str, arguments=scan_args)
            
            if target in self.nm.all_hosts():
                host_result = {
                    'hostname': self.nm[target].hostname(),
                    'state': self.nm[target].state(),
                    'protocols': {}
                }
                
                for proto in self.nm[target].all_protocols():
                    host_result['protocols'][proto] = {}
                    ports = self.nm[target][proto].keys()
                    
                    for port in ports:
                        port_info = self.nm[target][proto][port]
                        host_result['protocols'][proto][port] = {
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
                
                self.results[target] = host_result
                return host_result
            
        except Exception as e:
            logging.error(f"SYN scan error: {str(e)}")
        
        return {}
    
    def connect_scan(self, target, ports):
        """Perform TCP Connect scan"""
        try:
            print(f"{Fore.YELLOW}[*] Performing TCP Connect scan on {target}...{Style.RESET_ALL}")
            
            open_ports = []
            total_ports = len(ports)
            completed = 0
            
            def scan_port(port):
                nonlocal completed
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.config['scan_settings']['default_timeout'])
                    
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        with threading.Lock():
                            open_ports.append(port)
                    
                    completed += 1
                    print_progress(completed, total_ports, "Connect Scan")
                    
                except Exception:
                    completed += 1
                    print_progress(completed, total_ports, "Connect Scan")
            
            # Create threads for port scanning
            threads = []
            for port in ports:
                if len(threads) >= self.config['scan_settings']['max_threads']:
                    for t in threads:
                        t.join()
                    threads = []
                
                thread = threading.Thread(target=scan_port, args=(port,))
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            # Wait for remaining threads
            for t in threads:
                t.join()
            
            # Get service information for open ports
            if open_ports and self.config['scan_settings']['service_detection']:
                port_str = ','.join(map(str, open_ports))
                self.nm.scan(hosts=target, ports=port_str, arguments="-sV")
            
            return open_ports
            
        except Exception as e:
            logging.error(f"Connect scan error: {str(e)}")
        
        return []
    
    def udp_scan(self, target, ports):
        """Perform UDP scan"""
        if not self.config['scan_settings']['udp_scan']:
            return {}
        
        try:
            print(f"{Fore.YELLOW}[*] Performing UDP scan on {target}...{Style.RESET_ALL}")
            
            # Convert port list to string
            port_str = ','.join(map(str, ports[:100]))  # Limit UDP ports for performance
            
            # Perform UDP scan
            self.nm.scan(hosts=target, ports=port_str, arguments="-sU -T3")
            
            if target in self.nm.all_hosts():
                udp_results = {}
                
                if 'udp' in self.nm[target]:
                    for port, port_info in self.nm[target]['udp'].items():
                        if port_info['state'] == 'open':
                            udp_results[port] = {
                                'state': port_info['state'],
                                'service': port_info['name'],
                                'version': port_info.get('version', '')
                            }
                
                return udp_results
            
        except Exception as e:
            logging.error(f"UDP scan error: {str(e)}")
        
        return {}
    
    def scan(self, target, ports="1-1000"):
        """Perform comprehensive port scanning"""
        print(f"{Fore.BLUE}[*] Starting port scanning for: {target}{Style.RESET_ALL}")
        
        # Parse port range
        port_list = parse_ports(ports)
        if len(port_list) > self.config['network_settings']['max_ports']:
            port_list = port_list[:self.config['network_settings']['max_ports']]
            print(f"{Fore.YELLOW}[!] Limiting to first {self.config['network_settings']['max_ports']} ports{Style.RESET_ALL}")
        
        results = {}
        
        # Perform SYN scan (requires root)
        try:
            import os
            if os.geteuid() == 0:  # Root user
                syn_results = self.syn_scan(target, port_list)
                if syn_results:
                    results = syn_results
            else:
                print(f"{Fore.YELLOW}[!] Root privileges required for SYN scan, falling back to Connect scan{Style.RESET_ALL}")
                open_ports = self.connect_scan(target, port_list)
                # Convert to same format as SYN results
                results = {
                    'hostname': socket.getfqdn(target),
                    'state': 'up',
                    'protocols': {'tcp': {}}
                }
                for port in open_ports:
                    results['protocols']['tcp'][port] = {
                        'state': 'open',
                        'service': 'unknown',
                        'version': ''
                    }
        except Exception as e:
            logging.error(f"TCP scan error: {str(e)}")
        
        # Perform UDP scan if enabled
        if self.config['scan_settings']['udp_scan']:
            udp_ports = [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 514, 520, 631, 1434, 1900, 4500, 49152]
            udp_results = self.udp_scan(target, udp_ports)
            if udp_results and 'protocols' in results:
                results['protocols']['udp'] = udp_results
        
        # Display results
        self.display_results(target, results)
        
        return results
    
    def display_results(self, target, results):
        """Display port scan results"""
        print(f"\n{Fore.CYAN}[*] Port Scan Results for {target}:{Style.RESET_ALL}")
        
        if not results or 'protocols' not in results:
            print(f"{Fore.RED}[-] No open ports found or host is down{Style.RESET_ALL}")
            return
        
        for protocol, ports in results['protocols'].items():
            print(f"\n{Fore.WHITE}Protocol: {protocol.upper()}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}{'Port':<8} {'State':<8} {'Service':<15} {'Version':<20}{Style.RESET_ALL}")
            print("-" * 60)
            
            for port, info in sorted(ports.items()):
                state_color = Fore.GREEN if info['state'] == 'open' else Fore.YELLOW
                print(f"{state_color}{port:<8} {info['state']:<8} {info['service']:<15} {info.get('version', '')[:20]:<20}{Style.RESET_ALL}")
        
        total_open = sum(len(ports) for ports in results['protocols'].values())
        print(f"\n{Fore.GREEN}[+] Total open ports: {total_open}{Style.RESET_ALL}")