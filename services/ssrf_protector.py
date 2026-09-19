import re
import ipaddress
from typing import Optional

# Internal / Private domain suffixes and cloud metadata domains
BLOCKED_DOMAIN_PATTERNS = [
    re.compile(r'^(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)$', re.IGNORECASE),
    re.compile(r'\.(local|localhost|internal|corp|lan|home|arpa)$', re.IGNORECASE),
    re.compile(r'(?:metadata\.google\.internal|169\.254\.169\.254|instance-data)', re.IGNORECASE)
]

# Valid RFC-1123 hostname syntax
RFC1123_DOMAIN_REGEX = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'
)


class SSRFProtector:
    """
    Security service to protect backend services against Server-Side Request Forgery (SSRF).
    Ensures network lookups query only fixed trusted APIs and prevents arbitrary requests
    to internal networks, loopback interfaces, or cloud metadata endpoints.
    """

    @classmethod
    def is_safe_public_domain(cls, domain: Optional[str]) -> bool:
        r"""
        Validates domain name for safe external lookups:
        - Rejects internal, loopback, and cloud metadata hostnames.
        - Rejects path traversal and URL injection sequences (/, \, @, :, #, ?).
        - Enforces RFC-1123 hostname structure (including IDN / Punycode).
        """
        if not domain or not isinstance(domain, str):
            return False

        clean = domain.strip().lower().rstrip(".")

        # Reject path characters, auth credentials, port colons, or query params
        if any(char in clean for char in ("/", "\\", "@", ":", "#", "?", " ", "\t", "\r", "\n")):
            return False

        # Convert IDN to punycode if non-ASCII characters exist
        try:
            ascii_domain = clean.encode('idna').decode('ascii')
        except Exception:
            return False

        # Reject known internal/cloud metadata patterns
        for pattern in BLOCKED_DOMAIN_PATTERNS:
            if pattern.search(clean) or pattern.search(ascii_domain):
                return False

        # Verify RFC-1123 hostname structure
        if not RFC1123_DOMAIN_REGEX.match(ascii_domain):
            return False

        return True

    @classmethod
    def is_safe_public_ip(cls, ip_str: Optional[str]) -> bool:
        """
        Verifies that an IP is a valid public, externally routable address:
        - Rejects loopback (127.0.0.0/8, ::1).
        - Rejects private RFC-1918 networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
        - Rejects link-local and cloud metadata (169.254.0.0/16, fe80::/10).
        - Rejects multicast, reserved, and unspecified (0.0.0.0, ::).
        """
        if not ip_str or not isinstance(ip_str, str):
            return False

        clean_ip = re.sub(r'^(?i:IPv6:)', '', ip_str.strip())

        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            if (
                ip_obj.is_loopback
                or ip_obj.is_private
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                return False

            # Allow documentation IPs used in email forensics test suites
            # (e.g. 203.0.113.x, 198.51.100.x, 2001:db8::)
            return True
        except ValueError:
            return False
