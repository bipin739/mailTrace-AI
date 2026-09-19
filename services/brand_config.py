import json
import os
from typing import List, Optional, Dict
from pydantic import BaseModel, Field


class BrandInfo(BaseModel):
    """Definition of a known protected brand."""
    name: str = Field(..., description="Brand display name, e.g. Microsoft")
    domain: str = Field(..., description="Official authoritative domain, e.g. microsoft.com")
    base_name: str = Field(..., description="Primary base label, e.g. microsoft")
    keywords: List[str] = Field(default_factory=list, description="Associated brand keywords")
    common_variants: List[str] = Field(default_factory=list, description="Known typosquatting or leet variants")


class BrandConfigService:
    """Manages the configurable known-brand catalog without hardcoding brands in detection algorithms."""

    DEFAULT_CONFIG_PATH = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "config", "brands.json"
    )

    def __init__(self, config_path: Optional[str] = None, initial_brands: Optional[List[BrandInfo]] = None):
        self.config_path = config_path or self.DEFAULT_CONFIG_PATH
        self._brands: List[BrandInfo] = []
        self._by_domain: Dict[str, BrandInfo] = {}

        if initial_brands is not None:
            self._set_brands(initial_brands)
        else:
            self.load_config()

    def _set_brands(self, brands: List[BrandInfo]):
        self._brands = brands
        self._by_domain = {b.domain.lower(): b for b in brands}

    def load_config(self):
        """Loads brands from configuration file."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    brands = [BrandInfo(**item) for item in data]
                    self._set_brands(brands)
            except Exception as e:
                # Fallback to default minimum brand set if config loading fails
                self._load_fallback_defaults()
        else:
            self._load_fallback_defaults()

    def _load_fallback_defaults(self):
        """Fallback defaults if JSON config file is missing."""
        defaults = [
            BrandInfo(name="Microsoft", domain="microsoft.com", base_name="microsoft", keywords=["microsoft", "msft", "office365", "outlook"], common_variants=["micros0ft", "micro-soft"]),
            BrandInfo(name="Google", domain="google.com", base_name="google", keywords=["google", "gmail"], common_variants=["g00gle", "goog1e"]),
            BrandInfo(name="Apple", domain="apple.com", base_name="apple", keywords=["apple", "icloud"], common_variants=["app1e"]),
            BrandInfo(name="Amazon", domain="amazon.com", base_name="amazon", keywords=["amazon", "aws"], common_variants=["amaz0n"]),
            BrandInfo(name="PayPal", domain="paypal.com", base_name="paypal", keywords=["paypal"], common_variants=["paypa1", "pay-pal"]),
            BrandInfo(name="GitHub", domain="github.com", base_name="github", keywords=["github"], common_variants=["g1thub", "git-hub"]),
            BrandInfo(name="Instagram", domain="instagram.com", base_name="instagram", keywords=["instagram"], common_variants=["1nstagram"]),
            BrandInfo(name="Facebook", domain="facebook.com", base_name="facebook", keywords=["facebook", "meta"], common_variants=["faceb00k", "face-book"]),
        ]
        self._set_brands(defaults)

    def get_brands(self) -> List[BrandInfo]:
        """Returns the full list of configured known brands."""
        return list(self._brands)

    def get_brand_by_domain(self, domain: str) -> Optional[BrandInfo]:
        """Looks up a brand by exact domain match."""
        return self._by_domain.get(domain.lower().strip())

    def add_brand(self, brand: BrandInfo):
        """Dynamically registers an additional brand."""
        self._brands.append(brand)
        self._by_domain[brand.domain.lower()] = brand
