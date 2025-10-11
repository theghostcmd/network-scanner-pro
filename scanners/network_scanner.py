"""
Network Scanner Module for Network Scanner Pro
Created by GhostCmd
"""

import threading
import time
import ipaddress
from scapy.all import ARP, Ether, ICMP, IP, srp, sr1
from scapy.layers.inet import TCP
from colorama import Fore, Style
import logging
from utils.helpers import print_progress, get_mac_vendor

class NetworkScanner:
    def __init__(self, config):
        self.config = config
        self.results = []
        self.lock = threading.Lock()
    
    def arp_scan(self, network):
        """Perform ARP scan for network discovery"""
        hosts = []
        try:
            # Create ARP packet
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send packets and receive responses
            answered_list = srp(arp_request_broadcast, timeout=self.config['scan_settings']['default_timeout'], 
                               verbose=False)[0]
            
            for sent, received in answered_list:
                vendor = get_mac_vendor(received.hwsrc)
                hosts.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': vendor,
                    'status': 'up',
                    'method': 'arp'
                })
                
        except Exception as e:
            logging.error(f"ARP scan error: {str(e)}")
        
        return hosts
    
    def icmp_ping_sweep(self, network):
        """Perform ICMP ping sweep"""
        hosts = []
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            total_hosts = len(list(network_obj.hosts()))
            completed = 0
            
            def ping_host(ip):
                nonlocal completed
                try:
                    # Send ICMP echo request
                    packet = IP(dst=str(ip))/ICMP()
                    response = sr1(packet, timeout=self.config['scan_settings']['default_timeout'], 
                                  verbose=False)
                    
                    if response:
                        with self.lock:
                            hosts.append({
                                'ip': str(ip),
                                'mac': 'Unknown',
                                'vendor': 'Unknown',
                                'status': 'up',
                                'method': 'icmp'
                            })
                    
                    completed += 1
                    print_progress(completed, total_hosts, "Ping Sweep")
                    
                except Exception as e:
                    completed += 1
                    print_progress(completed, total_hosts, "Ping Sweep")
            
            # Create threads for ping sweep
            threads = []
            for ip in network_obj.hosts():
                if len(threads) >= self.config['scan_settings']['max_threads']:
                    for t in threads:
                        t.join()
                    threads = []
                
                thread = threading.Thread(target=ping_host, args=(ip,))
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            # Wait for remaining threads
            for t in threads:
                t.join()
                
        except Exception as e:
            logging.error(f"ICMP ping sweep error: {str(e)}")
        
        return hosts
    
    def tcp_ping_sweep(self, network, ports=[22, 80, 443, 3389]):
        """Perform TCP ping sweep"""
        hosts = []
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            
            def tcp_ping_host(ip):
                try:
                    for port in ports:
                        # Send TCP SYN packet
                        packet = IP(dst=str(ip))/TCP(dport=port, flags="S")
                        response = sr1(packet, timeout=self.config['scan_settings']['default_timeout'], 
                                      verbose=False)
                        
                        if response and response.haslayer(TCP):
                            if response[TCP].flags & 0x12:  SYN-ACK received
                                with self.lock:
                                    hosts.append({
                                        'ip': str(ip),
                                        'mac': 'Unknown',
                                        'vendor': 'Unknown',
                                        'status': 'up',
                                        'method': f'tcp_{port}'
                                    })
                                break
                                
                            # Send RST to close connection
                            sr1(IP(dst=str(ip))/TCP(dport=port, flags="R"), 
                                timeout=1, verbose=False)
                                
                except Exception:
                    pass
            
            # Create threads for TCP ping
            threads = []
            for ip in network_obj.hosts():
                if len(threads) >= self.config['scan_settings']['max_threads']:
                    for t in threads:
                        t.join()
                    threads = []
                
                thread = threading.Thread(target=tcp_ping_host, args=(ip,))
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            # Wait for remaining threads
            for t in threads:
                t.join()
                
        except Exception as e:
            logging.error(f"TCP ping sweep error: {str(e)}")
        
        return hosts
    
    def scan(self, target):
        """Perform comprehensive network discovery"""
        print(f"{Fore.BLUE}[*] Starting network discovery for: {target}{Style.RESET_ALL}")
        
        all_hosts = []
        
        # Validate target
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            # If it's a single IP, convert to /32 network
            try:
                network = ipaddress.ip_network(f"{target}/32", strict=False)
            except ValueError:
                logging.error(f"Invalid target: {target}")
                return all_hosts
        
        # ARP Scan (only for local networks)
        if self.config['scan_settings']['arp_scan'] and network.is_private:
            print(f"{Fore.YELLOW}[*] Performing ARP scan...{Style.RESET_ALL}")
            arp_hosts = self.arp_scan(str(network))
            all_hosts.extend(arp_hosts)
            print(f"{Fore.GREEN}[+] ARP scan found {len(arp_hosts)} hosts{Style.RESET_ALL}")
        
        # ICMP Ping Sweep
        if self.config['scan_settings']['ping_sweep']:
            print(f"{Fore.YELLOW}[*] Performing ICMP ping sweep...{Style.RESET_ALL}")
            icmp_hosts = self.icmp_ping_sweep(str(network))
            
            # Merge results, avoiding duplicates
            existing_ips = {host['ip'] for host in all_hosts}
            for host in icmp_hosts:
                if host['ip'] not in existing_ips:
                    all_hosts.append(host)
                    existing_ips.add(host['ip'])
            
            print(f"{Fore.GREEN}[+] ICMP scan found {len(icmp_hosts)} hosts{Style.RESET_ALL}")
        
        # TCP Ping Sweep for additional discovery
        print(f"{Fore.YELLOW}[*] Performing TCP ping sweep...{Style.RESET_ALL}")
        tcp_hosts = self.tcp_ping_sweep(str(network))
        
        # Merge results
        existing_ips = {host['ip'] for host in all_hosts}
        for host in tcp_hosts:
            if host['ip'] not in existing_ips:
                all_hosts.append(host)
                existing_ips.add(host['ip'])
        
        print(f"{Fore.GREEN}[+] TCP scan found {len(tcp_hosts)} hosts{Style.RESET_ALL}")
        
        # Display results
        print(f"\n{Fore.CYAN}[*] Network Discovery Results:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'IP Address':<15} {'MAC Address':<18} {'Vendor':<20} {'Method':<10}{Style.RESET_ALL}")
        print("-" * 65)
        
        for host in sorted(all_hosts, key=lambda x: ipaddress.ip_address(x['ip'])):
            status_color = Fore.GREEN if host['status'] == 'up' else Fore.RED
            print(f"{status_color}{host['ip']:<15} {host['mac']:<18} {host['vendor']:<20} {host['method']:<10}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Total hosts discovered: {len(all_hosts)}{Style.RESET_ALL}")
        
        return all_hosts