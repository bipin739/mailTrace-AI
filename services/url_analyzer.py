import re
import ipaddress
from urllib.parse import urlsplit, unquote
from typing import List, Optional, Tuple, Set
import tldextract

from backend.schemas.url_analysis import URLFeatures, URLAnalysisResult
from backend.services.lookalike_detector import LookalikeDetectorService


class URLAnalyzerService:
    """
    Static, non-invasive forensic URL analyzer.
    Performs purely syntactic and structural inspection of URLs.
    Does NOT visit URLs, follow redirects, or download website content.
    """

    KNOWN_SHORTENERS: Set[str] = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "cutt.ly", "rebrand.ly", "tiny.cc", "shorturl.at",
        "adf.ly", "bit.do", "rb.gy", "lnkd.in", "snip.ly", "bl.ink",
        "qr.ae", "trib.al", "bc.vc", "shorte.st", "hyperurl.co"
    }

    SUSPICIOUS_KEYWORDS: List[str] = [
        "login", "verify", "secure", "password", "account",
        "update", "payment", "wallet", "invoice", "signin", "reset"
    ]

    def __init__(self, lookalike_detector: Optional[LookalikeDetectorService] = None):
        self.lookalike_detector = lookalike_detector or LookalikeDetectorService()
        self.tld_extractor = tldextract.TLDExtract(cache_dir=None)

    def analyze_url(
        self,
        url: str,
        visible_text: Optional[str] = None,
        display_link_mismatch: bool = False
    ) -> URLAnalysisResult:
        """
        Statically analyzes a single URL and extracts forensic features,
        identifies observations, and calculates an isolated suspicion score.
        """
        clean_url = url.strip()
        observations: List[str] = []
        score_reasons: List[str] = []
        suspicion_score = 0

        # Parse URL
        try:
            parsed = urlsplit(clean_url)
        except Exception:
            # Fallback for malformed URLs
            clean_with_scheme = "http://" + clean_url if not clean_url.startswith(("http://", "https://", "ftp://")) else clean_url
            try:
                parsed = urlsplit(clean_with_scheme)
            except Exception:
                parsed = urlsplit("")

        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        raw_netloc = parsed.netloc

        # Check for embedded credentials (user:pass@host)
        has_credentials = False
        authority_host = raw_netloc
        if "@" in raw_netloc:
            has_credentials = True
            authority_host = raw_netloc.split("@")[-1]

        # Separate port from hostname
        port: Optional[int] = None
        hostname = authority_host
        has_non_standard_port = False

        # Handle IPv6 bracketed syntax e.g. [2001:db8::1]:8080
        if authority_host.startswith("["):
            bracket_end = authority_host.find("]")
            if bracket_end != -1:
                hostname = authority_host[1:bracket_end]
                remainder = authority_host[bracket_end + 1:]
                if remainder.startswith(":"):
                    try:
                        port = int(remainder[1:])
                    except ValueError:
                        port = None
        elif ":" in authority_host:
            parts = authority_host.split(":")
            hostname = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                port = None
        else:
            hostname = authority_host

        hostname_clean = hostname.lower().strip()

        # Non-standard port detection
        if port is not None:
            if scheme == "http" and port != 80:
                has_non_standard_port = True
            elif scheme == "https" and port != 443:
                has_non_standard_port = True
            elif scheme not in ("http", "https"):
                has_non_standard_port = True

        # IP host detection (IPv4 / IPv6)
        is_ip_host = False
        ip_version: Optional[int] = None
        try:
            ip_obj = ipaddress.ip_address(hostname_clean)
            is_ip_host = True
            ip_version = ip_obj.version
        except ValueError:
            is_ip_host = False
            ip_version = None

        # Public-suffix registered domain and subdomains
        registered_domain = ""
        subdomain = ""
        subdomain_count = 0
        if not is_ip_host and hostname_clean:
            ext = self.tld_extractor(hostname_clean)
            registered_domain = ext.top_domain_under_public_suffix or ext.domain or hostname_clean
            subdomain = ext.subdomain
            if subdomain:
                subdomain_count = len([s for s in subdomain.split(".") if s])

        excessive_subdomains = subdomain_count >= 3

        # Punycode detection
        is_punycode = "xn--" in hostname_clean

        # Path and Query length
        path = parsed.path or ""
        path_length = len(path)
        query = parsed.query or ""
        query_length = len(query)
        total_length = len(clean_url)

        # Percent encoding detection
        percent_matches = re.findall(r'%[0-9a-fA-F]{2}', clean_url)
        percent_encoding_count = len(percent_matches)
        has_percent_encoding = percent_encoding_count > 0

        # Unusual character density
        special_chars = re.findall(r'[@\-_=&%?+$;:!~]', clean_url)
        special_char_count = len(special_chars)
        char_density_ratio = special_char_count / max(total_length, 1)
        unusual_char_density = char_density_ratio > 0.18 or special_char_count > 15

        # URL Shortener detection
        is_shortener = (
            registered_domain in self.KNOWN_SHORTENERS
            or hostname_clean in self.KNOWN_SHORTENERS
        )

        # Suspicious keywords in URL tokens (path, query, host)
        tokens = set(re.findall(r'[a-zA-Z0-9]+', clean_url.lower()))
        suspicious_keywords_found: List[str] = [
            kw for kw in self.SUSPICIOUS_KEYWORDS if kw in tokens
        ]

        # HTML link mismatch detection
        visible_text_domain: Optional[str] = None
        if visible_text and not display_link_mismatch:
            visible_text_clean = visible_text.strip()
            # Check if visible text looks like a domain or URL
            domain_in_text = self._extract_domain_from_text(visible_text_clean)
            if domain_in_text:
                visible_text_domain = domain_in_text
                # Compare registered domains
                ext_visible = self.tld_extractor(domain_in_text)
                vis_reg_dom = (ext_visible.top_domain_under_public_suffix or ext_visible.domain or domain_in_text).lower()
                actual_reg_dom = (registered_domain or hostname_clean).lower()

                if vis_reg_dom and actual_reg_dom and vis_reg_dom != actual_reg_dom:
                    display_link_mismatch = True

        # Lookalike domain detection
        lookalike_result = None
        domain_to_check = registered_domain or hostname_clean
        if domain_to_check and not is_ip_host:
            lookalike_result = self.lookalike_detector.detect_lookalike(domain_to_check)

        # Populate features
        features = URLFeatures(
            scheme=scheme,
            hostname=hostname_clean,
            registered_domain=registered_domain,
            subdomain=subdomain,
            subdomain_count=subdomain_count,
            port=port,
            has_non_standard_port=has_non_standard_port,
            path=path,
            path_length=path_length,
            query=query,
            query_length=query_length,
            total_length=total_length,
            is_ip_host=is_ip_host,
            ip_version=ip_version,
            is_punycode=is_punycode,
            excessive_subdomains=excessive_subdomains,
            has_credentials=has_credentials,
            suspicious_keywords=suspicious_keywords_found,
            has_percent_encoding=has_percent_encoding,
            percent_encoding_count=percent_encoding_count,
            unusual_char_density=unusual_char_density,
            is_shortener=is_shortener,
            display_link_mismatch=display_link_mismatch,
            visible_text=visible_text,
            visible_text_domain=visible_text_domain,
            lookalike=lookalike_result
        )

        # Compile Observations & Static URL Suspicion Score
        if display_link_mismatch:
            vis_label = f"'{visible_text_domain}'" if visible_text_domain else "trusted domain"
            actual_label = f"'{registered_domain or hostname_clean}'"
            obs = f"HTML display link mismatch: visible text claims {vis_label} but destination links to {actual_label}"
            observations.append(obs)
            suspicion_score += 35
            score_reasons.append("HTML display link mismatch (+35)")

        if has_credentials:
            observations.append("Embedded credentials found in URL authority segment (possible credential leak or deception)")
            suspicion_score += 25
            score_reasons.append("Embedded user credentials in authority (+25)")

        if is_ip_host:
            obs_ip = f"Direct IPv{ip_version or ''} address used as hostname instead of domain name"
            observations.append(obs_ip)
            suspicion_score += 25
            score_reasons.append(f"Direct IP address host IPv{ip_version or ''} (+25)")

        if is_shortener:
            observations.append(f"URL shortener domain detected ({registered_domain or hostname_clean}), which obscures the true destination")
            suspicion_score += 15
            score_reasons.append("Known URL shortener service (+15)")

        if has_non_standard_port:
            observations.append(f"Non-standard port ({port}) specified for {scheme.upper()} protocol")
            suspicion_score += 10
            score_reasons.append(f"Non-standard port {port} (+10)")

        if is_punycode:
            observations.append(f"Punycode domain detected ({hostname_clean}), potential Internationalized Domain Name (IDN) homoglyph spoofing")
            suspicion_score += 15
            score_reasons.append("Punycode domain indicator (+15)")

        if lookalike_result:
            obs_brand = f"Potential brand impersonation: similar to {lookalike_result.suspected_brand} ({int(lookalike_result.similarity * 100)}% match)"
            observations.append(obs_brand)
            suspicion_score += 20
            score_reasons.append(f"Lookalike brand similarity to {lookalike_result.suspected_brand} (+20)")

        if excessive_subdomains:
            observations.append(f"Excessive subdomain depth detected ({subdomain_count} labels)")
            suspicion_score += 10
            score_reasons.append(f"Excessive subdomains: {subdomain_count} levels (+10)")

        if total_length > 150:
            observations.append(f"Abnormally long URL ({total_length} characters)")
            suspicion_score += 10
            score_reasons.append(f"Abnormally long URL ({total_length} chars) (+10)")

        if suspicious_keywords_found:
            kw_str = ", ".join(suspicious_keywords_found)
            observations.append(f"Suspicious security/authentication keywords found: {kw_str}")
            kw_points = min(len(suspicious_keywords_found) * 5, 15)
            suspicion_score += kw_points
            score_reasons.append(f"Suspicious keywords ({kw_str}) (+{kw_points})")

        if percent_encoding_count >= 3:
            observations.append(f"Heavy percent-encoding ({percent_encoding_count} encoded sequences), possible evasion or obfuscation")
            suspicion_score += 10
            score_reasons.append(f"Multiple percent-encoded sequences ({percent_encoding_count}) (+10)")

        if unusual_char_density:
            observations.append(f"High special character density ({special_char_count} special characters)")
            suspicion_score += 10
            score_reasons.append("Unusual special character density (+10)")

        # Default observation if completely clean
        if not observations:
            observations.append("Standard URL structure with no immediate static anomalies detected")

        # Clamp score to 100
        clamped_score = min(suspicion_score, 100)

        # Classify suspicion level
        if clamped_score >= 60:
            suspicion_level = "high"
        elif clamped_score >= 25:
            suspicion_level = "suspicious"
        else:
            suspicion_level = "low"

        display_domain = registered_domain or hostname_clean or clean_url

        return URLAnalysisResult(
            url=clean_url,
            domain=display_domain,
            features=features,
            observations=observations,
            suspicion_score=clamped_score,
            suspicion_level=suspicion_level,
            score_reasons=score_reasons
        )

    def analyze_urls(
        self,
        urls: List[str],
        html_links: Optional[List[Tuple[str, str, bool]]] = None
    ) -> List[URLAnalysisResult]:
        """
        Batch analyzes a list of URLs, optionally taking HTML link context
        (href, visible_text, display_link_mismatch).
        """
        results: List[URLAnalysisResult] = []
        seen_urls: Set[str] = set()

        # Build lookup for html link metadata if available
        html_map = {}
        if html_links:
            for item in html_links:
                if len(item) == 2:
                    href, vis_text = item
                    html_map[href.strip()] = (vis_text, False)
                elif len(item) >= 3:
                    href, vis_text, mismatch = item[:3]
                    html_map[href.strip()] = (vis_text, mismatch)

        for u in urls:
            clean_u = u.strip()
            if not clean_u or clean_u in seen_urls:
                continue
            seen_urls.add(clean_u)

            vis_text, mismatch = html_map.get(clean_u, (None, False))
            res = self.analyze_url(clean_u, visible_text=vis_text, display_link_mismatch=mismatch)
            results.append(res)

        return results

    def _extract_domain_from_text(self, text: str) -> Optional[str]:
        """
        Extracts a potential domain or URL hostname from visible text.
        e.g. 'https://microsoft.com', 'microsoft.com', 'www.paypal.com/signin'
        """
        clean = text.strip().lower()
        if not clean:
            return None

        # Try parsing as URL first if it starts with http
        if clean.startswith(("http://", "https://")):
            try:
                parsed = urlsplit(clean)
                if parsed.hostname:
                    return parsed.hostname
            except Exception:
                pass

        # Look for domain pattern in text
        match = re.search(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b', clean)
        if match:
            candidate = match.group(0)
            # Ensure it's not a common file extension or non-domain
            ext = candidate.split(".")[-1]
            if ext in ("png", "jpg", "jpeg", "gif", "svg", "css", "js", "html", "php"):
                return None
            return candidate

        return None
