import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional

from backend.schemas.domain_intelligence import DomainIntelligence, DomainRegistration, DNSRecords
from backend.services.dns_service import DNSService
from backend.services.rdap_service import RDAPService
from backend.services.domain_cache import DomainIntelligenceCache
from backend.services.lookalike_detector import LookalikeDetectorService


class DomainIntelligenceService:
    """Coordinates DNS resolution, RDAP registration lookups, and lookalike detection with thread-safe TTL caching."""

    def __init__(
        self,
        dns_service: Optional[DNSService] = None,
        rdap_service: Optional[RDAPService] = None,
        cache: Optional[DomainIntelligenceCache] = None,
        lookalike_detector: Optional[LookalikeDetectorService] = None,
        new_domain_threshold_days: int = 30
    ):
        self.dns_service = dns_service or DNSService()
        self.rdap_service = rdap_service or RDAPService()
        self.cache = cache if cache is not None else DomainIntelligenceCache()
        self.lookalike_detector = lookalike_detector or LookalikeDetectorService()
        self.new_domain_threshold_days = new_domain_threshold_days

    def _calculate_domain_age(self, reg_date_str: Optional[str]) -> tuple[Optional[int], Optional[bool]]:
        """
        Calculates domain age in days strictly from reliable creation/registration timestamp.
        Does not invent age if registration date is unavailable.
        Returns (domain_age_days, newly_registered_domain).
        """
        if not reg_date_str:
            return None, None

        s = reg_date_str.strip()
        if not s:
            return None, None

        import re

        # Normalize dot and slash separators
        if re.match(r"^\d{4}\.\d{2}\.\d{2}", s):
            s = s.replace(".", "-")
        elif re.match(r"^\d{4}/\d{2}/\d{2}", s):
            s = s.replace("/", "-")

        dt: Optional[datetime] = None

        # Try ISO 8601 parsing first
        try:
            clean_date = s.replace("Z", "+00:00")
            parsed = datetime.fromisoformat(clean_date)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            dt = parsed
        except Exception:
            pass

        # Try standard WHOIS and RFC date formats
        if dt is None:
            for fmt in [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S%z",
                "%Y-%m-%d",
                "%d-%b-%Y",
                "%d-%b-%Y %H:%M:%S",
                "%a %b %d %H:%M:%S %Z %Y",
                "%a %b %d %H:%M:%S %Y",
            ]:
                try:
                    parsed = datetime.strptime(s, fmt)
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    dt = parsed
                    break
                except Exception:
                    continue

        if dt is None:
            return None, None

        try:
            now = datetime.now(timezone.utc)
            delta = now - dt
            age_days = max(0, delta.days)

            # Neutral observation: True if age is less than or equal to threshold
            is_new = age_days <= self.new_domain_threshold_days
            return age_days, is_new
        except Exception:
            return None, None

    async def lookup_domain(self, domain: str) -> DomainIntelligence:
        """
        Performs contextual DNS and RDAP intelligence lookup for a single domain.
        Checks and populates TTL cache.
        """
        clean_domain = domain.strip().lower().rstrip(".")
        if not clean_domain:
            return DomainIntelligence(
                domain=domain,
                status_message="Invalid or empty domain"
            )

        # Check Cache
        cached = self.cache.get(clean_domain)
        if cached is not None:
            return cached

        # Execute DNS and RDAP concurrently
        dns_task = self.dns_service.resolve_records(clean_domain)
        rdap_task = self.rdap_service.lookup_domain(clean_domain)

        dns_result, rdap_result = await asyncio.gather(dns_task, rdap_task, return_exceptions=True)

        # Process DNS results
        if isinstance(dns_result, Exception):
            dns_records = DNSRecords()
            is_resolvable = False
            status_message = f"DNS resolution error: {str(dns_result)}"
            punycode = None
        else:
            dns_records, is_resolvable, status_message, punycode = dns_result

        # Process RDAP results
        if isinstance(rdap_result, Exception):
            registration = DomainRegistration(
                registration_source="unavailable",
                status=[f"RDAP query failed: {str(rdap_result)}"]
            )
        else:
            registration = rdap_result

        # Calculate Domain Age and Neutral Flag
        age_days, is_new = self._calculate_domain_age(registration.registration_date)

        # Detect Lookalike / Brand Impersonation
        lookalike_findings = self.lookalike_detector.detect_lookalike(clean_domain)

        intelligence = DomainIntelligence(
            domain=clean_domain,
            punycode=punycode,
            dns=dns_records,
            registration=registration,
            domain_age_days=age_days,
            newly_registered_domain=is_new,
            is_resolvable=is_resolvable,
            status_message=status_message,
            lookalike=lookalike_findings
        )

        # Update cache
        self.cache.set(clean_domain, intelligence)
        return intelligence

    async def enrich_domains_batch(
        self,
        domains: List[str],
        max_concurrency: int = 5,
        max_domains: int = 15
    ) -> Dict[str, DomainIntelligence]:
        """
        Batch enriches a list of domains concurrently with bounded parallelism.
        Limits lookup to top unique domains to prevent excessive network delays.
        """
        unique_domains: List[str] = []
        seen = set()
        for d in domains:
            norm = d.strip().lower().rstrip(".")
            if norm and norm not in seen and "." in norm and norm not in ("localhost", "local"):
                seen.add(norm)
                unique_domains.append(norm)

        # Cap at max_domains to prevent latency spikes during email analysis
        targets = unique_domains[:max_domains]
        if not targets:
            return {}

        semaphore = asyncio.Semaphore(max_concurrency)

        async def _bounded_lookup(d: str) -> tuple[str, DomainIntelligence]:
            async with semaphore:
                intel = await self.lookup_domain(d)
                return d, intel

        tasks = [_bounded_lookup(d) for d in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        enriched: Dict[str, DomainIntelligence] = {}
        for item in results:
            if isinstance(item, tuple):
                d_name, intel = item
                enriched[d_name] = intel

        return enriched
