#!/usr/bin/env python3
"""
WebRecon-Unity - Unified Web Reconnaissance & Fuzzing Suite
For Kali Linux - Terminal-based professional pentesting tool
"""

import subprocess
import sys
import os
import argparse
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class WebReconUnity:
    def __init__(self, target, output_dir=None, threads=10, silent=False):
        self.target = target.rstrip('/')
        self.output_dir = output_dir or f"./recon_{target.replace('https://', '').replace('http://', '').replace('/', '_')}"
        self.threads = threads
        self.silent = silent
        self.results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "technologies": [],
            "subdomains": [],
            "directories": [],
            "cms_vulnerabilities": [],
            "vulnerabilities": []
        }
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
    def log(self, message, level="INFO"):
        """Colored terminal output"""
        if self.silent:
            return
        colors = {
            "INFO": "\033[94m",    # Blue
            "SUCCESS": "\033[92m", # Green
            "WARNING": "\033[93m", # Yellow
            "ERROR": "\033[91m",   # Red
            "PHASE": "\033[95m",   # Purple
            "RESET": "\033[0m"
        }
        print(f"{colors.get(level, colors['RESET'])}[{level}]{colors['RESET']} {message}")
    
    def run_command(self, cmd, description=None):
        """Run shell command and return output"""
        if description:
            self.log(description, "INFO")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            return {"success": result.returncode == 0, "stdout": result.stdout, "stderr": result.stderr}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def print_banner(self):
        """Display tool banner"""
        banner = f"""
╔══════════════════════════════════════════════════════════════════╗
║                    WebRecon-Unity v1.0                          ║
║         Unified Web Reconnaissance & Fuzzing Suite              ║
╠══════════════════════════════════════════════════════════════════╣
║  Target: {self.target}
║  Output: {self.output_dir}
║  Threads: {self.threads}
╚══════════════════════════════════════════════════════════════════╝
        """
        print(f"\033[95m{banner}\033[0m")
    
    # ============ PHASE 1: Technology Detection ============
    
    def detect_technologies(self):
        """Identify web technologies using WhatWeb and Wappalyzer"""
        self.log("\n[PHASE 1] Technology Detection", "PHASE")
        
        # WhatWeb scan
        self.log("  Running WhatWeb...", "INFO")
        whatweb_cmd = f"whatweb --no-errors --color=never {self.target}"
        result = self.run_command(whatweb_cmd, None)
        
        if result["success"] and result["stdout"]:
            techs = result["stdout"].strip()
            self.results["technologies"].append(techs)
            self.log(f"    Found: {techs[:100]}...", "SUCCESS")
            
            # Check for WordPress
            if "WordPress" in techs:
                self.results["cms_type"] = "wordpress"
                self.log("    ✓ WordPress detected", "SUCCESS")
            
            # Check for other CMS
            cms_indicators = ["Joomla", "Drupal", "Magento", "Shopify", "Wix", "SquareSpace"]
            for cms in cms_indicators:
                if cms.lower() in techs.lower():
                    self.results["cms_type"] = cms.lower()
                    self.log(f"    ✓ {cms} detected", "SUCCESS")
        
        # Save results
        with open(f"{self.output_dir}/technologies.txt", "w") as f:
            f.write(result.get("stdout", "No technologies detected"))
    
    # ============ PHASE 2: Subdomain Discovery ============
    
    def discover_subdomains(self):
        """Enumerate subdomains using Amass"""
        self.log("\n[PHASE 2] Subdomain Discovery", "PHASE")
        
        domain = self.target.replace("https://", "").replace("http://", "").split("/")[0]
        
        # Try Amass (best tool)
        self.log(f"  Running Amass on {domain}...", "INFO")
        amass_cmd = f"amass enum -passive -d {domain} -o {self.output_dir}/subdomains_amass.txt"
        result = self.run_command(amass_cmd, None)
        
        if result["success"] and os.path.exists(f"{self.output_dir}/subdomains_amass.txt"):
            with open(f"{self.output_dir}/subdomains_amass.txt", "r") as f:
                subdomains = [line.strip() for line in f if line.strip()]
            self.results["subdomains"].extend(subdomains)
            self.log(f"    Found {len(subdomains)} subdomains", "SUCCESS")
        else:
            self.log("    Amass failed or not installed. Trying alternative...", "WARNING")
            # Fallback to dnsrecon
            dnsrecon_cmd = f"dnsrecon -d {domain} -t axfr,zonewalk -o {self.output_dir}/subdomains_fallback.txt"
            self.run_command(dnsrecon_cmd, None)
    
    # ============ PHASE 3: Directory Fuzzing ============
    
    def fuzz_directories(self):
        """Fuzz for hidden directories using FFUF"""
        self.log("\n[PHASE 3] Directory Fuzzing", "PHASE")
        
        # Common wordlist locations in Kali
        wordlists = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"
        ]
        
        wordlist = None
        for wl in wordlists:
            if os.path.exists(wl):
                wordlist = wl
                break
        
        if not wordlist:
            self.log("    No wordlist found. Please install seclists", "ERROR")
            return
        
        self.log(f"  Using wordlist: {wordlist}", "INFO")
        self.log(f"  Running FFUF with {self.threads} threads...", "INFO")
        
        output_file = f"{self.output_dir}/directories.txt"
        ffuf_cmd = f"ffuf -u {self.target}/FUZZ -w {wordlist} -t {self.threads} -o {output_file} -of json -fc 404,403"
        
        result = self.run_command(ffuf_cmd, None)
        
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                found_count = len(data.get("results", []))
                self.results["directories"] = [r["input"]["FUZZ"] for r in data.get("results", [])[:50]]
                self.log(f"    Found {found_count} directories/files", "SUCCESS")
                
                # Display top findings
                for d in self.results["directories"][:10]:
                    self.log(f"      → /{d}", "INFO")
            except:
                self.log("    Could not parse FFUF output", "WARNING")
    
    # ============ PHASE 4: CMS Vulnerability Scan ============
    
    def scan_cms_vulnerabilities(self):
        """Run CMS-specific vulnerability scans"""
        self.log("\n[PHASE 4] CMS Vulnerability Scan", "PHASE")
        
        cms_type = self.results.get("cms_type")
        
        if cms_type == "wordpress":
            self.log("  Running WPScan...", "INFO")
            wpscan_cmd = f"wpscan --url {self.target} --enumerate vp,vt,tt --no-banner -o {self.output_dir}/wpscan_results.txt"
            result = self.run_command(wpscan_cmd, None)
            
            if result["success"]:
                self.log("    WordPress scan completed", "SUCCESS")
                self.results["cms_vulnerabilities"].append({"type": "wordpress", "output": result["stdout"][:500]})
        elif cms_type == "joomla":
            self.log("  Running JoomScan...", "INFO")
            joomscan_cmd = f"joomscan --url {self.target} -o {self.output_dir}/joomscan_results.txt"
            self.run_command(joomscan_cmd, None)
        else:
            self.log("  No specific CMS detected. Skipping CMS scan.", "WARNING")
    
    # ============ PHASE 5: Vulnerability Scan ============
    
    def scan_vulnerabilities(self):
        """Run vulnerability scans using Nikto"""
        self.log("\n[PHASE 5] Vulnerability Scan", "PHASE")
        
        self.log("  Running Nikto...", "INFO")
        nikto_cmd = f"nikto -h {self.target} -o {self.output_dir}/nikto_report.html -Format html -nolookup"
        result = self.run_command(nikto_cmd, None)
        
        if result["success"]:
            self.log("    Nikto scan completed", "SUCCESS")
        
        # Optional: Nuclei if installed
        nuclei_path = subprocess.run("which nuclei", shell=True, capture_output=True).stdout.decode().strip()
        if nuclei_path:
            self.log("  Running Nuclei (fast template scanner)...", "INFO")
            nuclei_cmd = f"nuclei -u {self.target} -o {self.output_dir}/nuclei_results.txt -silent"
            self.run_command(nuclei_cmd, None)
            self.log("    Nuclei scan completed", "SUCCESS")
    
    # ============ Final Report ============
    
    def generate_report(self):
        """Generate comprehensive report"""
        self.log("\n[FINAL] Generating Report", "PHASE")
        
        # Save JSON report
        report_file = f"{self.output_dir}/report.json"
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Generate HTML report
        html_report = f"""<!DOCTYPE html>
<html>
<head><title>WebRecon-Unity Report: {self.target}</title>
<style>
    body {{ font-family: monospace; margin: 40px; background: #1e1e1e; color: #d4d4d4; }}
    h1 {{ color: #4ec9b0; }}
    h2 {{ color: #ce9178; margin-top: 30px; }}
    pre {{ background: #252526; padding: 15px; border-radius: 5px; overflow-x: auto; }}
    .success {{ color: #4ec9b0; }}
    .info {{ color: #9cdcfe; }}
</style>
</head>
<body>
    <h1>WebRecon-Unity Report</h1>
    <p><strong>Target:</strong> {self.target}</p>
    <p><strong>Date:</strong> {self.results['timestamp']}</p>
    
    <h2>📊 Summary</h2>
    <pre>
├── Technologies: {len(self.results.get('technologies', []))} items
├── Subdomains: {len(self.results.get('subdomains', []))} found
├── Directories: {len(self.results.get('directories', []))} discovered
└── Output Directory: {self.output_dir}
    </pre>
    
    <h2>🔧 Technologies Detected</h2>
    <pre>{self.results.get('technologies', ['None detected'])[0][:500]}</pre>
    
    <h2>🌐 Directories Found</h2>
    <pre>{chr(10).join(['/{}'.format(d) for d in self.results.get('directories', [])[:30]]) or 'None found'}</pre>
    
    <h2>📁 Output Files</h2>
    <pre>
• {self.output_dir}/technologies.txt
• {self.output_dir}/directories.txt
• {self.output_dir}/subdomains_amass.txt
• {self.output_dir}/nikto_report.html
    </pre>
    
    <p class="info">For complete results, check the output directory: {self.output_dir}</p>
</body>
</html>"""
        
        html_file = f"{self.output_dir}/report.html"
        with open(html_file, 'w') as f:
            f.write(html_report)
        
        self.log(f"  Report saved to {report_file}", "SUCCESS")
        self.log(f"  HTML report saved to {html_file}", "SUCCESS")
        
        # Print final summary
        print(f"""
╔══════════════════════════════════════════════════════════════════╗
║                      RECONNAISSANCE COMPLETE                     ║
╠══════════════════════════════════════════════════════════════════╣
║  Technologies detected: {len(self.results.get('technologies', []))}                                    
║  Subdomains found:      {len(self.results.get('subdomains', []))}                                    
║  Directories discovered: {len(self.results.get('directories', []))}                                    
╠══════════════════════════════════════════════════════════════════╣
║  Output directory: {self.output_dir}
╚══════════════════════════════════════════════════════════════════╝
        """)
    
    def run_full(self):
        """Execute all phases"""
        self.print_banner()
        
        # Check dependencies
        required_tools = ["whatweb", "ffuf", "nmap", "nikto"]
        missing = []
        for tool in required_tools:
            if subprocess.run(f"which {tool}", shell=True, capture_output=True).returncode != 0:
                missing.append(tool)
        
        if missing:
            self.log(f"Missing tools: {', '.join(missing)}", "WARNING")
            self.log("Install with: sudo apt install " + " ".join(missing), "INFO")
            response = input("Continue anyway? (y/n): ")
            if response.lower() != 'y':
                return
        
        # Run phases in sequence
        self.detect_technologies()
        self.discover_subdomains()
        self.fuzz_directories()
        self.scan_cms_vulnerabilities()
        self.scan_vulnerabilities()
        self.generate_report()


def main():
    parser = argparse.ArgumentParser(
        description="WebRecon-Unity - Unified Web Reconnaissance & Fuzzing Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  webscan https://example.com --full
  webscan https://example.com --output ./results --threads 20 --silent
  webscan https://example.com --quick (skip subdomain and CMS scans)
        """
    )
    
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode (no output)")
    parser.add_argument("--quick", action="store_true", help="Quick mode (skip subdomain and CMS scans)")
    parser.add_argument("--no-fuzz", action="store_true", help="Skip directory fuzzing")
    parser.add_argument("--no-tech", action="store_true", help="Skip technology detection")
    
    args = parser.parse_args()
    
    tool = WebReconUnity(args.target, args.output, args.threads, args.silent)
    
    if args.quick:
        tool.detect_technologies()
        tool.fuzz_directories()
        tool.scan_vulnerabilities()
        tool.generate_report()
    elif args.no_fuzz:
        tool.detect_technologies()
        tool.discover_subdomains()
        tool.scan_cms_vulnerabilities()
        tool.scan_vulnerabilities()
        tool.generate_report()
    else:
        tool.run_full()

if __name__ == "__main__":
    main()