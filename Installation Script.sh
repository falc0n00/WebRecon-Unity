#!/bin/bash
# install_webscan.sh - Install WebRecon-Unity and dependencies

echo "Installing WebRecon-Unity for Kali Linux..."

# Install required tools
sudo apt update
sudo apt install -y whatweb amass ffuf nikto wpscan dnsrecon

# Install optional tools (nuclei requires Go)
if ! command -v nuclei &> /dev/null; then
    echo "Installing Nuclei..."
    sudo apt install -y golang-go
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    sudo cp ~/go/bin/nuclei /usr/local/bin/
fi

# Install seclists for wordlists
sudo apt install -y seclists

# Make the tool executable
chmod +x webscan.py

# Create symlink to /usr/local/bin
sudo ln -sf $(pwd)/webscan.py /usr/local/bin/webscan

echo "Installation complete!"
echo "Run: webscan https://example.com --full"