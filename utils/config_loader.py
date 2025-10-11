"""
Configuration loader for Network Scanner Pro
Created by GhostCmd
"""

import json
import os
import logging

class ConfigLoader:
    def __init__(self, config_file="config.json"):
        self.config_file = config_file
        self.default_config = {
            "scan_settings": {
                "default_timeout": 2,
                "max_threads": 100,
                "ping_sweep": True,
                "arp_scan": True,
                "syn_scan": True,
                "udp_scan": False,
                "service_detection": True,
                "os_detection": True
            },
            "vulnerability_settings": {
                "cve_lookup": True,
                "ssl_checks": True,
                "weak_credential_testing": False,
                "web_vulnerability_checks": True
            },
            "report_settings": {
                "company_name": "Network Scanner Pro",
                "include_executive_summary": True,
                "include_technical_details": True,
                "generate_pdf": True,
                "generate_html": True,
                "generate_csv": True
            },
            "network_settings": {
                "rate_limit": 100,
                "packet_delay": 0,
                "max_ports": 1000
            }
        }
    
    def load_config(self):
        """Load configuration from file or create default"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                logging.info("Configuration loaded successfully")
                return config
            else:
                logging.warning("Config file not found, using defaults")
                self.save_config(self.default_config)
                return self.default_config
        except Exception as e:
            logging.error(f"Error loading config: {str(e)}")
            return self.default_config
    
    def save_config(self, config):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            logging.info("Configuration saved successfully")
        except Exception as e:
            logging.error(f"Error saving config: {str(e)}")
    
    def update_config(self, section, key, value):
        """Update specific configuration value"""
        config = self.load_config()
        if section in config and key in config[section]:
            config[section][key] = value
            self.save_config(config)
            return True
        return False