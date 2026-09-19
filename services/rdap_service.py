import httpx
import tldextract
from typing import Optional, Dict, Any, List

from backend.schemas.domain_intelligence import DomainRegistration
from backend.services.whois_service import WHOISService


class RDAPService:
    """Service to query and parse domain registration data via RDAP (RFC 7480-7484) with WHOIS fallback."""

    def __init__(
        self,
        timeout_seconds: float = 3.5,
        rdap_base_url: str = "https://rdap.org/domain/",
        whois_service: Optional[WHOISService] = None
    ):
        self.timeout = timeout_seconds
        self.rdap_base_url = rdap_base_url
        self.whois_service = whois_service or WHOISService(timeout_seconds=timeout_seconds)

    @staticmethod
    def _extract_registrar(data: Dict[str, Any]) -> Optional[str]:
        """Extracts registrar organization name from RDAP entities vCard or handle."""
        entities = data.get("entities", [])
        for ent in entities:
            roles = [r.lower() for r in ent.get("roles", [])]
            if "registrar" in roles:
                vcard = ent.get("vcardArray", [])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for prop in vcard[1]:
                        if isinstance(prop, list) and len(prop) >= 4:
                            prop_name = prop[0].lower()
                            if prop_name in ("fn", "org"):
                                return str(prop[3]).strip()

                # Fallback to handle or entity name
                handle = ent.get("handle") or ent.get("name")
                if handle:
                    return str(handle).strip()

        return None

    @staticmethod
    def _extract_dates(data: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
        """Extracts creation/registration date and expiration date from RDAP events."""
        events = data.get("events", [])
        registration_date: Optional[str] = None
        expiration_date: Optional[str] = None

        for ev in events:
            action = str(ev.get("eventAction", "")).lower()
            date_str = ev.get("eventDate")
            if not date_str:
                continue

            if action in ("registration", "creation"):
                registration_date = str(date_str).strip()
            elif action == "expiration":
                expiration_date = str(date_str).strip()

        return registration_date, expiration_date

    @staticmethod
    def _extract_nameservers(data: Dict[str, Any]) -> List[str]:
        """Extracts nameserver hostnames from RDAP nameserver entries."""
        ns_list: List[str] = []
        for ns in data.get("nameservers", []):
            ldh = ns.get("ldhName") or ns.get("handle")
            if ldh:
                ns_list.append(str(ldh).strip().lower())
        return ns_list

    @staticmethod
    def _extract_statuses(data: Dict[str, Any]) -> List[str]:
        """Extracts domain status codes."""
        raw_statuses = data.get("status", [])
        if isinstance(raw_statuses, list):
            return [str(s).strip() for s in raw_statuses if s]
        return []

    async def _query_single_rdap(self, client: httpx.AsyncClient, target_domain: str) -> Optional[DomainRegistration]:
        """Queries RDAP endpoint for a specific domain."""
        url = f"{self.rdap_base_url.rstrip('/')}/{target_domain}"
        headers = {
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "MailTraceAI-Forensics/1.0"
        }
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                registrar = self._extract_registrar(data)
                reg_date, exp_date = self._extract_dates(data)
                nameservers = self._extract_nameservers(data)
                status_list = self._extract_statuses(data)

                return DomainRegistration(
                    registrar=registrar,
                    registration_date=reg_date,
                    expiration_date=exp_date,
                    nameservers=nameservers,
                    status=status_list,
                    registration_source="RDAP"
                )
        except Exception:
            return None
        return None

    async def lookup_domain(self, domain: str) -> DomainRegistration:
        """
        Queries RDAP for domain registration details.
        Falls back to apex domain query for subdomains, and to WHOIS if RDAP data is unavailable.
        """
        clean_domain = domain.strip().lower().rstrip(".")
        if not clean_domain:
            return DomainRegistration(
                registration_source="unavailable",
                status=["Invalid domain name"]
            )

        from backend.services.ssrf_protector import SSRFProtector
        if not SSRFProtector.is_safe_public_domain(clean_domain):
            return DomainRegistration(
                registration_source="unavailable",
                status=["Internal, loopback, or invalid domain rejected by SSRF protection"]
            )

        # 1. Attempt RDAP query for target domain
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                res = await self._query_single_rdap(client, clean_domain)
                if res and res.registration_date:
                    return res

                # If subdomain, try apex registered domain
                ext = tldextract.extract(clean_domain)
                apex = getattr(ext, 'top_domain_under_public_suffix', None) or clean_domain
                if apex and apex != clean_domain:
                    apex_res = await self._query_single_rdap(client, apex)
                    if apex_res and apex_res.registration_date:
                        return apex_res

                if res and (res.registrar or res.nameservers):
                    # Partial RDAP info, but let's check WHOIS for missing registration date
                    if self.whois_service:
                        whois_res = await self.whois_service.lookup_domain(apex or clean_domain)
                        if whois_res and whois_res.registration_date:
                            # Merge: keep RDAP nameservers/status if present, use WHOIS registration date
                            return DomainRegistration(
                                registrar=res.registrar or whois_res.registrar,
                                registration_date=whois_res.registration_date,
                                expiration_date=res.expiration_date or whois_res.expiration_date,
                                nameservers=res.nameservers or whois_res.nameservers,
                                status=res.status or whois_res.status,
                                registration_source="WHOIS"
                            )
                    return res

        except (httpx.TimeoutException, httpx.RequestError):
            pass
        except Exception:
            pass

        # 2. WHOIS Fallback
        if self.whois_service:
            ext = tldextract.extract(clean_domain)
            apex = getattr(ext, 'top_domain_under_public_suffix', None) or clean_domain
            whois_res = await self.whois_service.lookup_domain(apex)
            if whois_res and (whois_res.registration_date or whois_res.registrar):
                return whois_res

        return DomainRegistration(
            registration_source="unavailable",
            status=["Registration date unavailable in RDAP and WHOIS"]
        )
