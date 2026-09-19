import asyncio
import re
import socket
from typing import Optional, List, Tuple

from backend.schemas.domain_intelligence import DomainRegistration


TLD_WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "biz": "whois.biz",
    "ru": "whois.nic.ru",
    "de": "whois.denic.de",
    "uk": "whois.nic.uk",
    "co.uk": "whois.nic.uk",
    "io": "whois.nic.io",
    "in": "whois.registry.in",
    "ca": "whois.cira.ca",
    "eu": "whois.eu",
    "fr": "whois.nic.fr",
    "nl": "whois.domain-registry.nl",
    "ch": "whois.nic.ch",
    "jp": "whois.jprs.jp",
    "cn": "whois.cnnic.cn",
    "gov": "whois.dotgov.gov",
    "edu": "whois.educause.edu",
    "us": "whois.nic.us",
    "cc": "whois.nic.cc",
    "me": "whois.nic.me",
    "tv": "whois.nic.tv"
}


class WHOISService:
    """Service to query domain registration via WHOIS protocol (RFC 3912) as fallback to RDAP."""

    def __init__(self, timeout_seconds: float = 3.5):
        self.timeout = timeout_seconds

    def _get_whois_server(self, domain: str) -> str:
        """Determines the authoritative WHOIS server for a domain's TLD."""
        parts = domain.lower().split(".")
        if len(parts) >= 2:
            two_part_tld = f"{parts[-2]}.{parts[-1]}"
            if two_part_tld in TLD_WHOIS_SERVERS:
                return TLD_WHOIS_SERVERS[two_part_tld]

        tld = parts[-1] if parts else ""
        if tld in TLD_WHOIS_SERVERS:
            return TLD_WHOIS_SERVERS[tld]

        # Query IANA to discover WHOIS server
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(("whois.iana.org", 43))
            s.send((tld + "\r\n").encode("utf-8"))
            resp = b""
            while len(resp) < 8192:
                chunk = s.recv(2048)
                if not chunk:
                    break
                resp += chunk
            s.close()
            iana_text = resp.decode("utf-8", errors="ignore")
            refer_match = re.search(r"refer:\s*([^\s]+)", iana_text, re.IGNORECASE)
            if refer_match:
                return refer_match.group(1).strip()
        except Exception:
            pass

        return f"whois.nic.{tld}" if tld else "whois.iana.org"

    def _sync_whois_query(self, domain: str) -> Optional[str]:
        """Performs synchronous TCP query to WHOIS server on port 43."""
        clean_domain = domain.strip().lower().rstrip(".")
        whois_server = self._get_whois_server(clean_domain)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((whois_server, 43))
            s.send((clean_domain + "\r\n").encode("utf-8"))
            response = b""
            while len(response) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            s.close()
            return response.decode("utf-8", errors="ignore")
        except Exception:
            return None

    def _parse_whois_response(self, text: str) -> Tuple[Optional[str], Optional[str], Optional[str], List[str], List[str]]:
        """
        Parses registration date, expiration date, registrar, nameservers, and statuses from WHOIS response text.
        """
        reg_date: Optional[str] = None
        exp_date: Optional[str] = None
        registrar: Optional[str] = None
        nameservers: List[str] = []
        statuses: List[str] = []

        # 1. Registration / Creation Date
        reg_patterns = [
            r"(?:Creation Date|Created on|Registration Date|created|registered|Domain Name Commencement Date|Registration Time)\s*:\s*([^\r\n]+)",
            r"(?:Created|Registered)\s*:\s*([^\r\n]+)"
        ]
        for p in reg_patterns:
            m = re.search(p, text, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                # Remove trailing comments/zones like (UTC) or #
                val = re.split(r"[\(\#]", val)[0].strip()
                if val:
                    reg_date = val
                    break

        # 2. Expiration Date
        exp_patterns = [
            r"(?:Registry Expiry Date|Expiration Date|paid-till|Registry Expiry|Expires on|expires|Domain Expiration Date)\s*:\s*([^\r\n]+)",
        ]
        for p in exp_patterns:
            m = re.search(p, text, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                val = re.split(r"[\(\#]", val)[0].strip()
                if val:
                    exp_date = val
                    break

        # 3. Registrar
        regis_patterns = [
            r"(?:Registrar Name|Sponsoring Registrar|Registrar|registrar)\s*:\s*([^\r\n]+)",
        ]
        for p in regis_patterns:
            m = re.search(p, text, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                if val and not val.lower().startswith("http") and not val.lower().startswith("whois"):
                    registrar = val
                    break

        # 4. Nameservers
        ns_matches = re.findall(r"(?:Name Server|nserver)\s*:\s*([^\r\n\s]+)", text, re.IGNORECASE)
        for ns in ns_matches:
            clean_ns = ns.strip().rstrip(".").lower()
            if clean_ns and clean_ns not in nameservers and "." in clean_ns:
                nameservers.append(clean_ns)

        # 5. Status
        status_matches = re.findall(r"(?:Domain Status|status|state)\s*:\s*([^\r\n]+)", text, re.IGNORECASE)
        for st in status_matches:
            clean_st = st.split("http")[0].strip()
            if clean_st and clean_st not in statuses:
                statuses.append(clean_st)

        return registrar, reg_date, exp_date, nameservers, statuses

    async def lookup_domain(self, domain: str) -> DomainRegistration:
        """
        Queries WHOIS asynchronously for domain registration metadata.
        """
        clean_domain = domain.strip().lower().rstrip(".")
        raw_text = await asyncio.to_thread(self._sync_whois_query, clean_domain)

        if not raw_text:
            return DomainRegistration(
                registration_source="unavailable",
                status=["WHOIS query timed out or connection failed"]
            )

        registrar, reg_date, exp_date, nameservers, statuses = self._parse_whois_response(raw_text)

        if not reg_date and not registrar and not nameservers:
            return DomainRegistration(
                registration_source="unavailable",
                status=["Domain registration details not found in WHOIS"]
            )

        return DomainRegistration(
            registrar=registrar,
            registration_date=reg_date,
            expiration_date=exp_date,
            nameservers=nameservers,
            status=statuses,
            registration_source="WHOIS"
        )
