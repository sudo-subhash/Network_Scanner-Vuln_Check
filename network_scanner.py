#!/usr/bin/env python3
"""
🔍 AutoScanner - One Command Network Security Scanner
Author: Security Tool
Description: Just enter a target, and it automatically scans networks and checks vulnerabilities
"""

import subprocess
import sys
import os
import re
import json
from datetime import datetime
import ipaddress
import time

class AutoScanner:
    def __init__(self):
        self.target = ""
        self.scan_results = {
            'basic_info': {},
            'open_ports': [],
            'os_info': [],
            'vulnerabilities': [],
            'warnings': []
        }
        self.check_nmap()
    
    def check_nmap(self):
        """Check if nmap is installed"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                   capture_output=True, text=True)
            if result.returncode == 0:
                version = result.stdout.split('\n')[0]
                print(f"✅ Nmap found: {version}")
            else:
                print("❌ Nmap is not installed!")
                self.install_nmap()
        except FileNotFoundError:
            print("❌ Nmap is not installed!")
            self.install_nmap()
    
    def install_nmap(self):
        """Guide user to install nmap"""
        print("\n" + "="*60)
        print("🔧 NMAP INSTALLATION GUIDE")
        print("="*60)
        
        if sys.platform.startswith('linux'):
            print("\nFor Linux (Ubuntu/Debian):")
            print("  sudo apt-get update")
            print("  sudo apt-get install nmap")
        elif sys.platform == 'darwin':
            print("\nFor macOS:")
            print("  brew install nmap")
        elif sys.platform == 'win32':
            print("\nFor Windows:")
            print("  1. Download from: https://nmap.org/download.html")
            print("  2. Run the installer")
        
        print("\nAfter installing, run this tool again.")
        sys.exit(1)
    
    def validate_target(self, target):
        """Validate if target is valid"""
        if not target:
            return False
        
        # Check if it's localhost
        if target == 'localhost':
            return True
        
        # Check if it's an IP
        try:
            ipaddress.ip_address(target)
            return True
        except:
            pass
        
        # Check if it's a domain
        if '.' in target and not target.startswith('http'):
            return True
        
        return False
    
    def print_progress(self, message):
        """Print progress with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
    
    def run_command(self, cmd, timeout=300):
        """Run shell command and return output"""
        try:
            result = subprocess.run(cmd, 
                                   capture_output=True, 
                                   text=True, 
                                   timeout=timeout)
            return result.stdout
        except subprocess.TimeoutExpired:
            self.scan_results['warnings'].append(f"Command timed out: {' '.join(cmd)}")
            return ""
        except Exception as e:
            self.scan_results['warnings'].append(f"Error running command: {e}")
            return ""
    
    def scan_target(self, target):
        """Main scanning function - does everything automatically"""
        self.target = target
        self.print_progress(f"🎯 Starting automatic scan of: {target}")
        
        # Step 1: Basic ping check
        self.print_progress("📡 Checking if target is alive...")
        self.check_host_alive()
        
        # Step 2: Basic port scan
        self.print_progress("🔍 Scanning for open ports (this may take 1-2 minutes)...")
        self.basic_port_scan()
        
        # Step 3: Service detection
        if self.scan_results['open_ports']:
            self.print_progress("🔎 Detecting services on open ports...")
            self.service_detection()
        
        # Step 4: OS detection
        self.print_progress("💻 Attempting OS detection...")
        self.os_detection()
        
        # Step 5: Vulnerability scan
        self.print_progress("⚠️  Checking for known vulnerabilities...")
        self.vulnerability_scan()
        
        # Step 6: Quick security checks
        self.print_progress("🔒 Performing security checks...")
        self.security_checks()
        
        self.print_progress("✅ Scan complete!")
    
    def check_host_alive(self):
        """Simple ping check"""
        cmd = ['ping', '-c', '1', '-W', '2', self.target]
        if sys.platform == 'win32':
            cmd = ['ping', '-n', '1', '-w', '2000', self.target]
        
        output = self.run_command(cmd, timeout=5)
        if '1 received' in output or 'TTL=' in output or 'bytes from' in output:
            self.scan_results['basic_info']['status'] = 'Alive'
            self.print_progress("✅ Host is alive")
        else:
            self.scan_results['basic_info']['status'] = 'Unknown (may be down or blocking ping)'
            self.print_progress("⚠️  Host may be down or blocking ping")
    
    def basic_port_scan(self):
        """Scan common ports"""
        # Common ports to scan
        common_ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
                       1723,3306,3389,5900,8080,8443,9000,9200]
        
        port_str = ','.join(map(str, common_ports))
        cmd = ['nmap', '-p', port_str, '--open', '-T4', self.target]
        
        output = self.run_command(cmd, timeout=120)
        
        # Parse open ports
        for line in output.split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                port_info = parts[0]
                service = parts[2] if len(parts) > 2 else 'unknown'
                self.scan_results['open_ports'].append({
                    'port': port_info.split('/')[0],
                    'service': service
                })
        
        if self.scan_results['open_ports']:
            self.print_progress(f"✅ Found {len(self.scan_results['open_ports'])} open ports")
        else:
            self.print_progress("ℹ️  No open ports found on common ports")
    
    def service_detection(self):
        """Detect service versions on open ports"""
        port_list = [p['port'] for p in self.scan_results['open_ports']]
        if not port_list:
            return
        
        port_str = ','.join(port_list)
        cmd = ['nmap', '-sV', '-p', port_str, '--version-intensity', '5', self.target]
        
        output = self.run_command(cmd, timeout=180)
        
        # Update service information
        for i, line in enumerate(output.split('\n')):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                port = parts[0].split('/')[0]
                service = parts[2] if len(parts) > 2 else 'unknown'
                version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                
                # Update the port info with version
                for p in self.scan_results['open_ports']:
                    if p['port'] == port:
                        p['service'] = service
                        p['version'] = version
                        break
    
    def os_detection(self):
        """Detect operating system"""
        cmd = ['nmap', '-O', '--osscan-guess', self.target]
        
        output = self.run_command(cmd, timeout=120)
        
        in_os_section = False
        for line in output.split('\n'):
            if 'OS details:' in line or 'OS guesses:' in line:
                self.scan_results['os_info'].append(line.strip())
                self.print_progress(f"ℹ️  {line.strip()}")
    
    def vulnerability_scan(self):
        """Check for known vulnerabilities"""
        self.print_progress("Running vulnerability scripts...")
        
        # Run different vulnerability scripts
        vuln_scripts = ['vuln', 'vulners', 'exploit']
        
        for script in vuln_scripts:
            cmd = ['nmap', '-sV', '--script', script, self.target]
            output = self.run_command(cmd, timeout=300)
            
            # Parse vulnerabilities
            vuln_found = False
            for line in output.split('\n'):
                if 'VULNERABLE' in line or 'CVE-' in line:
                    vuln_found = True
                    self.scan_results['vulnerabilities'].append(line.strip())
                    
                    # Try to get next line for details
                    next_line_idx = output.split('\n').index(line) + 1
                    if next_line_idx < len(output.split('\n')):
                        next_line = output.split('\n')[next_line_idx]
                        if next_line.strip() and 'State' not in next_line:
                            self.scan_results['vulnerabilities'].append(f"  {next_line.strip()}")
            
            if vuln_found:
                self.print_progress(f"⚠️  Found vulnerabilities with {script} script")
        
        # Check for specific high-profile vulnerabilities
        self.check_specific_vulns()
    
    def check_specific_vulns(self):
        """Check for specific well-known vulnerabilities"""
        specific_checks = [
            ('Heartbleed', 'ssl-heartbleed'),
            ('EternalBlue', 'smb-vuln-ms17-010'),
            ('BlueKeep', 'rdp-vuln-ms12-020'),
            ('Shellshock', 'http-shellshock'),
            ('Log4Shell', 'http-vuln-cve2021-44228')
        ]
        
        for vuln_name, script in specific_checks:
            cmd = ['nmap', '-sV', '--script', script, self.target]
            output = self.run_command(cmd, timeout=60)
            
            if 'VULNERABLE' in output:
                self.scan_results['vulnerabilities'].append(f"⚠️  {vuln_name}: Target may be vulnerable")
    
    def security_checks(self):
        """Perform basic security checks"""
        
        # Check for common insecure services
        insecure_services = {
            'telnet': 'Telnet - unencrypted protocol',
            'ftp': 'FTP - transmits credentials in clear text',
            'http': 'HTTP - no encryption (consider HTTPS)'
        }
        
        for port_info in self.scan_results['open_ports']:
            service = port_info.get('service', '').lower()
            for insecure, warning in insecure_services.items():
                if insecure in service:
                    self.scan_results['warnings'].append(f"Port {port_info['port']}: {warning}")
        
        # Check for default ports
        default_services = {
            '3306': 'MySQL database - check for default credentials',
            '5432': 'PostgreSQL - check for default credentials',
            '27017': 'MongoDB - check for default credentials',
            '6379': 'Redis - check for default credentials',
            '22': 'SSH - ensure strong passwords/key authentication',
            '3389': 'RDP - ensure strong passwords and NLA'
        }
        
        for port_info in self.scan_results['open_ports']:
            if port_info['port'] in default_services:
                self.scan_results['warnings'].append(f"Port {port_info['port']}: {default_services[port_info['port']]}")
    
    def generate_report(self):
        """Generate comprehensive report"""
        report = []
        report.append("=" * 70)
        report.append("🔍 AUTO SCANNER - SECURITY REPORT")
        report.append("=" * 70)
        report.append(f"Target: {self.target}")
        report.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 70)
        
        # Basic Info
        report.append("\n📡 TARGET INFORMATION")
        report.append("-" * 40)
        report.append(f"Status: {self.scan_results['basic_info'].get('status', 'Unknown')}")
        
        if self.scan_results['os_info']:
            report.append(f"OS: {self.scan_results['os_info'][0]}")
        
        # Open Ports
        report.append("\n🔌 OPEN PORTS")
        report.append("-" * 40)
        if self.scan_results['open_ports']:
            for port in self.scan_results['open_ports']:
                version = port.get('version', '')
                report.append(f"  • Port {port['port']}: {port['service']} {version}")
        else:
            report.append("  No open ports found")
        
        # Vulnerabilities
        if self.scan_results['vulnerabilities']:
            report.append("\n⚠️  VULNERABILITIES FOUND")
            report.append("-" * 40)
            for vuln in self.scan_results['vulnerabilities'][:15]:  # Show first 15
                report.append(f"  • {vuln}")
            if len(self.scan_results['vulnerabilities']) > 15:
                report.append(f"  ... and {len(self.scan_results['vulnerabilities']) - 15} more")
        
        # Warnings
        if self.scan_results['warnings']:
            report.append("\n⚠️  SECURITY WARNINGS")
            report.append("-" * 40)
            for warning in self.scan_results['warnings']:
                report.append(f"  • {warning}")
        
        # Recommendations
        report.append("\n🔒 SECURITY RECOMMENDATIONS")
        report.append("-" * 40)
        
        if self.scan_results['open_ports']:
            report.append("  • Close unnecessary open ports")
        
        if self.scan_results['vulnerabilities']:
            report.append("  • Patch identified vulnerabilities immediately")
            report.append("  • Update all services to latest versions")
        
        report.append("  • Use strong passwords and change defaults")
        report.append("  • Enable firewall rules to restrict access")
        report.append("  • Use encryption (HTTPS, SSH, VPN) for all services")
        report.append("  • Regular security updates and monitoring")
        
        if not self.scan_results['vulnerabilities'] and not self.scan_results['warnings']:
            report.append("  ✅ Target appears reasonably secure!")
        
        report.append("\n" + "=" * 70)
        report.append("Report generated by AutoScanner")
        report.append("=" * 70)
        
        return '\n'.join(report)
    
    def save_report(self):
        """Save report to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self.target.replace('/', '_').replace('.', '_')
        filename = f"scan_report_{safe_target}_{timestamp}.txt"
        
        report = self.generate_report()
        
        try:
            with open(filename, 'w') as f:
                f.write(report)
            print(f"\n✅ Report saved to: {filename}")
            return filename
        except Exception as e:
            print(f"\n❌ Error saving report: {e}")
            return None
    
    def print_summary(self):
        """Print quick summary of findings"""
        print("\n" + "=" * 70)
        print("📊 SCAN SUMMARY")
        print("=" * 70)
        
        # Count findings
        vuln_count = len(self.scan_results['vulnerabilities'])
        port_count = len(self.scan_results['open_ports'])
        warning_count = len(self.scan_results['warnings'])
        
        print(f"Target: {self.target}")
        print(f"Open Ports: {port_count}")
        print(f"Vulnerabilities Found: {vuln_count}")
        print(f"Security Warnings: {warning_count}")
        
        if vuln_count > 0:
            print("\n⚠️  ACTION REQUIRED: Vulnerabilities detected!")
        elif warning_count > 0:
            print("\n⚠️  Review warnings for security improvements")
        else:
            print("\n✅ No critical issues found")
    
    def run_interactive(self):
        """Run interactive mode"""
        while True:
            print("\n" + "=" * 70)
            print("🔍 AUTO SCANNER - Just enter a target, I'll do the rest!")
            print("=" * 70)
            print("\n📝 HOW TO USE:")
            print("1. Enter an IP address (e.g., 192.168.1.1)")
            print("2. Enter a domain name (e.g., example.com)")
            print("3. Enter 'localhost' for local machine")
            print("4. Type 'exit' to quit")
            print("\nThe scanner will automatically:")
            print("  • Check if target is alive")
            print("  • Find open ports")
            print("  • Detect services and OS")
            print("  • Check for vulnerabilities")
            print("  • Generate security report")
            print("=" * 70)
            
            target = input("\n🎯 Enter target: ").strip()
            
            if target.lower() == 'exit':
                print("\n👋 Goodbye! Stay secure!\n")
                break
            
            if not self.validate_target(target):
                print("\n❌ Invalid target! Please enter a valid IP or domain name.")
                continue
            
            # Reset results for new scan
            self.scan_results = {
                'basic_info': {},
                'open_ports': [],
                'os_info': [],
                'vulnerabilities': [],
                'warnings': []
            }
            
            # Run the scan
            self.scan_target(target)
            
            # Show summary
            self.print_summary()
            
            # Show vulnerabilities if any
            if self.scan_results['vulnerabilities']:
                print("\n⚠️  TOP VULNERABILITIES:")
                for vuln in self.scan_results['vulnerabilities'][:5]:
                    print(f"  • {vuln}")
            
            # Ask to save report
            save = input("\n💾 Save full report to file? (y/n): ").strip().lower()
            if save == 'y':
                self.save_report()
            
            # Show full report in console?
            show = input("\n📄 Show full report in console? (y/n): ").strip().lower()
            if show == 'y':
                print("\n" + self.generate_report())
            
            print("\n" + "=" * 70)
            input("Press Enter to scan another target...")

def print_welcome():
    """Print welcome message"""
    welcome = """
    ╔══════════════════════════════════════════════════════════╗
    ║     🔍 AUTO SCANNER - One Command Network Security      ║
    ║         Just enter a target, I'll do the rest!          ║
    ╚══════════════════════════════════════════════════════════╝
    
    Features:
    • Automatic network scanning
    • Port discovery
    • Service detection
    • OS fingerprinting
    • Vulnerability checking
    • Security recommendations
    
    ⚠️  DISCLAIMER: Use only on systems you own or have permission to test!
    """
    print(welcome)

def main():
    print_welcome()
    
    scanner = AutoScanner()
    scanner.run_interactive()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Scan interrupted. Goodbye!\n")
    except Exception as e:
        print(f"\n❌ Error: {e}")