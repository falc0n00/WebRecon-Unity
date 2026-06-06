# Full reconnaissance
webscan https://example.com --full

# Quick scan (skip subdomain enumeration)
webscan https://example.com --quick

# Custom output directory with more threads
webscan https://target.com -o ./results -t 20

# Silent mode for automation
webscan https://target.com --silent --full