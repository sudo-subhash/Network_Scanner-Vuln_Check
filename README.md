# Network_Scanner-Vuln_Check
 - Complete Tool Documentation
Overview

   Network_Scanner-Vuln_Check is a powerful, user-friendly network security scanning tool that automates the entire process of network reconnaissance and vulnerability assessment. With just one command - entering a target IP or hostname - it performs comprehensive security analysis and provides actionable recommendations.

📖 HOW TO USE THIS TOOL
Step 1: Run the Tool
bash

python3 network_scanner.py

Step 2: Enter Your Target

Just type any of these:

    IP Address: 192.168.1.1

    Domain Name: example.com

    Local Machine: localhost

    Type exit to quit

Step 3: Wait for Results

The tool automatically does everything:
text

[14:30:22] 🎯 Starting automatic scan of: 192.168.1.1
[14:30:23] 📡 Checking if target is alive...
[14:30:25] ✅ Host is alive
[14:30:25] 🔍 Scanning for open ports...
[14:30:45] ✅ Found 5 open ports
[14:30:45] 🔎 Detecting services...
[14:31:15] 💻 Attempting OS detection...
[14:31:35] ⚠️  Checking for known vulnerabilities...
[14:32:05] ✅ Scan complete!

Step 4: Review Results

The tool shows you:

    📊 Summary - Quick overview of findings

    ⚠️ Vulnerabilities - Any security issues found

    🔌 Open Ports - What services are running

    🔒 Recommendations - How to fix problems

Step 5: Save Report

    Type y to save a detailed report

    Report includes all findings and recommendations

    Automatically timestamped: scan_report_192.168.1.1_20240101_143022.txt

What the Tool Automatically Does:
Step	What It Checks	Why It Matters
1	Host is alive	Confirms target exists
2	Open ports	Finds entry points
3	Service versions	Identifies what's running
4	Operating system	Knows the platform
5	Vulnerabilities	Checks for known issues
6	Security warnings	Finds misconfigurations
Examples:
Example 1: Scan a Local Router
text

🎯 Enter target: 192.168.1.1

Results:
✅ Found 3 open ports
⚠️  Found 2 vulnerabilities
🔒 Recommendations provided

Example 2: Scan a Website
text

🎯 Enter target: example.com

Results:
✅ Ports 80, 443 open
⚠️  Missing security headers
✅ No critical vulnerabilities

Features at a Glance:

✅ One Command - Just enter the target
✅ Automatic - No options to choose
✅ Comprehensive - Scans everything
✅ User-Friendly - Easy to understand results
✅ Portable - Works on Windows, Mac, Linux
✅ Safe - Uses standard nmap scripts
Requirements:

    Python 3.6+

    Nmap installed on your system

Installation:
bash

# Install nmap first, then:
python3 Network_Scanner-Vuln_Check

Sample Output:
text

╔══════════════════════════════════════════════════════════╗
║     🔍 AUTO SCANNER - One Command Network Security      ║
╚══════════════════════════════════════════════════════════╝

🎯 Enter target: scanme.nmap.org

[14:30:22] 🎯 Starting automatic scan...
[14:30:23] ✅ Host is alive
[14:30:45] ✅ Found 3 open ports
[14:31:15] 💻 OS: Linux 2.6.32
[14:32:05] ⚠️  Found 2 vulnerabilities

📊 SCAN SUMMARY
========================================
Target: scanme.nmap.org
Open Ports: 3
Vulnerabilities Found: 2
Security Warnings: 1

⚠️  VULNERABILITIES:
  • CVE-2014-0160 - Heartbleed
  • Weak cipher suites detected

💾 Save full report? (y/n): y
✅ Report saved to: scan_report_scanme.nmap.org_20240101_143022.txt

The tool is now extremely simple - just run it and enter your target. Everything else is automatic!

