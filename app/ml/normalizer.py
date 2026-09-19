import re
import unicodedata
from typing import Optional


class TextNormalizer:
    """
    Text normalization pipeline for NLP phishing classification.
    Processes subject and body text into a clean, normalized string
    ready for TF-IDF vectorization.
    """

    # URL matching pattern
    URL_REGEX = re.compile(
        r'(?:https?:\/\/|www\.)[^\s<>"\'{}|\\^`]+',
        re.IGNORECASE
    )

    # Email matching pattern
    EMAIL_REGEX = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        re.IGNORECASE
    )

    # IPv4 address matching pattern
    IP_REGEX = re.compile(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    )

    # Currency and monetary amount patterns
    MONEY_REGEX = re.compile(
        r'(?:[\$€£¥₹]\s*\d+(?:[.,]\d+)?|\b\d+(?:[.,]\d+)?\s*(?:usd|eur|gbp|inr|dollars|cents|bitcoin|btc)\b)',
        re.IGNORECASE
    )

    # Long digit sequences (phone numbers, account numbers, invoice IDs)
    NUM_REGEX = re.compile(
        r'\b\d{4,}\b'
    )

    # Repeated punctuation (e.g. !!!, ???, ...)
    REPEATED_PUNCT_REGEX = re.compile(r'([!?.]){2,}')

    # Excessive whitespace
    WHITESPACE_REGEX = re.compile(r'\s+')

    @classmethod
    def normalize(cls, subject: Optional[str] = None, body: Optional[str] = None) -> str:
        """
        Combines and normalizes subject and body text.
        Handles None, empty string, and non-English / unicode gracefully.
        """
        # 1. Combine subject and body safely
        parts = []
        if subject:
            parts.append(str(subject).strip())
        if body:
            parts.append(str(body).strip())

        raw_text = " ".join(parts).strip()
        if not raw_text:
            return ""

        # 2. Unicode normalization (NFKD decomposes accented characters cleanly)
        text = unicodedata.normalize('NFKD', raw_text)

        # 3. Lowercase
        text = text.lower()

        # 4. Canonical token substitutions
        text = cls.URL_REGEX.sub(' httpurl ', text)
        text = cls.EMAIL_REGEX.sub(' emailaddr ', text)
        text = cls.IP_REGEX.sub(' ipaddr ', text)
        text = cls.MONEY_REGEX.sub(' moneysym ', text)
        text = cls.NUM_REGEX.sub(' numtoken ', text)

        # 5. Compress repeated punctuation
        text = cls.REPEATED_PUNCT_REGEX.sub(r'\1', text)

        # 6. Normalize whitespace
        text = cls.WHITESPACE_REGEX.sub(' ', text).strip()

        return text
