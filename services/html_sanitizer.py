import re
from typing import Optional


class HTMLSanitizerService:
    """
    Forensic HTML Sanitization Service.
    Neutralizes active content, scripts, iframes, objects, forms, event handlers,
    and blocks automatic loading of remote tracking images.
    """

    # Elements strictly prohibited and completely stripped
    DANGEROUS_TAG_BLOCKS = [
        re.compile(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', re.IGNORECASE | re.DOTALL),
        re.compile(r'<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>', re.IGNORECASE | re.DOTALL),
        re.compile(r'<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>', re.IGNORECASE | re.DOTALL),
        re.compile(r'<embed\b[^>]*>', re.IGNORECASE),
        re.compile(r'<applet\b[^<]*(?:(?!<\/applet>)<[^<]*)*<\/applet>', re.IGNORECASE | re.DOTALL),
        re.compile(r'<form\b[^<]*(?:(?!<\/form>)<[^<]*)*<\/form>', re.IGNORECASE | re.DOTALL),
        re.compile(r'<base\b[^>]*>', re.IGNORECASE),
        re.compile(r'<meta\b[^>]*>', re.IGNORECASE),
        re.compile(r'<link\b[^>]*rel\s*=\s*["\']?(?:stylesheet|import)["\']?[^>]*>', re.IGNORECASE),
    ]

    # Standalone open/close tags for blocked elements in case of broken HTML
    STANDALONE_TAGS = re.compile(r'<\/?(?:script|iframe|object|embed|applet|form|base|meta)\b[^>]*>', re.IGNORECASE)

    # Inline event handlers (onload, onerror, onclick, onmouseover, etc.)
    EVENT_HANDLERS = re.compile(r'\bon\w+\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+)', re.IGNORECASE)

    # JavaScript / VBScript pseudo-protocols in links or source attributes
    JAVASCRIPT_URIS = re.compile(r'(?:href|src|action)\s*=\s*["\']?\s*(?:javascript|vbscript|data(?!\s*:\s*image\/)):[^"\' >]+["\']?', re.IGNORECASE)

    # Remote image sources (http/https URLs in img tags)
    REMOTE_IMG_SRC = re.compile(r'(<img\b[^>]*?)\bsrc\s*=\s*["\'](https?://[^"\']+)["\']', re.IGNORECASE)

    @classmethod
    def sanitize_html(cls, raw_html: Optional[str], block_remote_images: bool = True) -> str:
        """
        Sanitizes raw email HTML content:
        - Blocks all <script>, <iframe>, <object>, <embed>, <form>, <base>, <meta>.
        - Strips all 'on*' event handlers.
        - Neutralizes 'javascript:' / 'vbscript:' links.
        - Neutralizes automatic remote image fetches by transforming src to data-blocked-src.
        """
        if not raw_html:
            return ""

        clean = raw_html

        # 1. Strip dangerous tag blocks
        for pattern in cls.DANGEROUS_TAG_BLOCKS:
            clean = pattern.sub('', clean)

        # 2. Strip any dangling or malformed standalone dangerous tags
        clean = cls.STANDALONE_TAGS.sub('', clean)

        # 3. Strip all event handlers
        clean = cls.EVENT_HANDLERS.sub('', clean)

        # 4. Neutralize javascript: / vbscript: URIs
        clean = cls.JAVASCRIPT_URIS.sub('href="#"', clean)

        # 5. Block automatic loading of remote images
        if block_remote_images:
            clean = cls.REMOTE_IMG_SRC.sub(
                r'\1data-blocked-src="\2" alt="[Remote Image Blocked]"',
                clean
            )

        return clean
