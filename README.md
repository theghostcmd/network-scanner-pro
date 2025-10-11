
## 8. Installation and Setup Script

**install.sh**
```bash
#!/bin/bash

echo "Network Scanner Pro - Installation Script"
echo "Created by GhostCmd"
echo "=========================================="

# Check Python version
python3 --version >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Create virtual environment
echo "[*] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "[*] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Install system dependencies
if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu/Kali
    echo "[*] Installing system dependencies (Debian-based)..."
    sudo apt update
    sudo apt install -y nmap python3-pip
elif [ -f /etc/redhat-release ]; then
    # RedHat/CentOS
    echo "[*] Installing system dependencies (RedHat-based)..."
    sudo yum install -y nmap python3-pip
elif [ -x "$(command -v pacman)" ]; then
    # Arch Linux
    echo "[*] Installing system dependencies (Arch-based)..."
    sudo pacman -S nmap python-pip
elif [ -x "$(command -v pkg)" ]; then
    # Termux
    echo "[*] Installing system dependencies (Termux)..."
    pkg install nmap python
fi

# Set executable permissions
chmod +x main.py

echo ""
echo "[+] Installation completed successfully!"
echo "[+] To use the tool:"
echo "    source venv/bin/activate"
echo "    python main.py --help"
echo ""
echo "Legal Disclaimer: Use this tool only on networks you own or have explicit permission to test."
