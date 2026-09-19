import time
from threading import Lock
from typing import Dict, Optional, Tuple

from backend.schemas.domain_intelligence import DomainIntelligence


class DomainIntelligenceCache:
    """Thread-safe TTL cache for domain intelligence results."""

    def __init__(self, default_ttl_seconds: float = 86400.0):
        self._cache: Dict[str, Tuple[DomainIntelligence, float]] = {}
        self._lock = Lock()
        self._default_ttl = default_ttl_seconds

    def get(self, domain: str) -> Optional[DomainIntelligence]:
        key = domain.lower().strip()
        with self._lock:
            if key not in self._cache:
                return None

            data, expiry = self._cache[key]
            if time.time() > expiry:
                del self._cache[key]
                return None

            return data

    def set(self, domain: str, intelligence: DomainIntelligence, ttl: Optional[float] = None) -> None:
        key = domain.lower().strip()
        duration = ttl if ttl is not None else self._default_ttl
        expiry = time.time() + duration

        with self._lock:
            self._cache[key] = (intelligence, expiry)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        with self._lock:
            now = time.time()
            return sum(1 for _, expiry in self._cache.values() if expiry > now)
