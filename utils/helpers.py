"""
Helper functions for Network Scanner Pro
Created by GhostCmd
"""

import re
import socket
import ipaddress
from colorama import Fore, Style

def display_banner():
    """Display tool banner"""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║            ███╗   ██╗███████╗████████╗██╗    ██╗              ║
║            ████╗  ██║██╔════╝╚══██╔══╝██║    ██║              ║
║            ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║              ║
║            ██║╚██╗██║██╔══╝     ██║   ██║███╗██║              ║
║            ██║ ╚████║███████╗   ██║   ╚███╔███╔╝              ║
║            ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝               ║
║                                                                ║
║                ███████╗ ██████╗ █████╗ ███╗   ██╗             ║
║                ██╔════╝██╔════╝██╔══██╗████╗  ██║             ║
║                ███████╗██║     ███████║██╔██╗ ██║             ║
║                ╚════██║██║     ██╔══██║██║╚██╗██║             ║
║                ███████║╚██████╗██║  ██║██║ ╚████║             ║
║                ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝             ║
║                                                                ║
║                    Created by {Fore.RED}GhostCmd{Fore.CYAN}                          ║
║              Ethical Hacking Tool - Use Responsibly           ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

def validate_target(target):
    """Validate target IP/CIDR/hostname"""
    try:
        # Check if it's a CIDR notation
        if '/' in target:
            ipaddress.ip_network(target, strict=False)
            return True
        
        # Check if it's a single IP
        ipaddress.ip_address(target)
        return True
        
    except ValueError:
        # Check if it's a valid hostname
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False

def parse_ports(port_string):
    """Parse port range string into list of ports"""
    ports = []
    
    if not port_string:
        return list(range(1, 1001))
    
    # Handle comma-separated ports and ranges
    for part in port_string.split(','):
        if '-' in part:
            start, end = part.split('-')
            try:
                ports.extend(range(int(start), int(end) + 1))
            except ValueError:
                continue
        else:
            try:
                ports.append(int(part))
            except ValueError:
                continue
    
    return sorted(set(ports))

def print_progress(current, total, task="Processing"):
    """Print progress bar"""
    bar_length = 50
    progress = current / total
    arrow = '=' * int(round(progress * bar_length) - 1) + '>'
    spaces = ' ' * (bar_length - len(arrow))
    
    print(f'\r{Fore.YELLOW}[{task}] [{arrow + spaces}] {int(progress * 100)}% ({current}/{total})', 
          end='', flush=True)
    
    if current == total:
        print()

def is_root():
    """Check if running with root privileges"""
    import os
    return os.geteuid() == 0

def get_mac_vendor(mac_address):
    """Get vendor from MAC address (basic implementation)"""
    # This is a simplified version - in practice, you'd use a comprehensive OUI database
    oui_db = {
        '00:0C:29': 'VMware',
        '00:50:56': 'VMware',
        '00:1C:42': 'Parallels',
        '00:1D:0F': 'Cisco',
        '00:24:8C': 'Cisco',
        '00:26:BB': 'Cisco',
        '08:00:27': 'VirtualBox',
        '52:54:00': 'QEMU',
        '00:15:5D': 'Microsoft',
        '00:1B:21': 'Hewlett Packard',
        '00:1E:68': 'Hewlett Packard',
        '00:25:B3': 'Hewlett Packard',
    }
    
    mac_prefix = mac_address.upper()[:8]
    return oui_db.get(mac_prefix, 'Unknown')