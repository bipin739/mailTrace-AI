import re
import logging
from typing import Any

# Sensitive regex patterns to redact in server logs
SENSITIVE_PATTERNS = [
    (re.compile(r'Authorization\s*:\s*Bearer\s+[^\r\n\s]+', re.IGNORECASE), 'Authorization: Bearer [REDACTED]'),
    (re.compile(r'Authorization\s*:\s*[^\r\n]+', re.IGNORECASE), 'Authorization: [REDACTED]'),
    (re.compile(r'Bearer\s+[a-zA-Z0-9_\-\.]{8,}', re.IGNORECASE), 'Bearer [REDACTED]'),
    (re.compile(r'(?:api_key|apikey|key)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{8,}["\']?', re.IGNORECASE), 'api_key=[REDACTED]'),
    (re.compile(r'(?:password|secret|token)\s*[:=]\s*["\']?[^"\'\s,]+["\']?', re.IGNORECASE), 'password=[REDACTED]'),
    (re.compile(r'[?&](?:key|api_key|token)=[^&\s]+', re.IGNORECASE), '?key=[REDACTED]'),
]


def sanitize_log_text(text: str) -> str:
    """Sanitizes text string by redacting authorization tokens, API keys, and passwords."""
    if not isinstance(text, str):
        return str(text)

    clean = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        clean = pattern.sub(replacement, clean)
    return clean


class SensitiveLogFilter(logging.Filter):
    """
    Python logging filter that intercepts log records and redacts credentials,
    API keys, authorization headers, and raw secrets from log output.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = sanitize_log_text(record.msg)

        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: sanitize_log_text(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(sanitize_log_text(str(a)) for a in record.args)

        return True


def install_log_sanitizer():
    """Attaches SensitiveLogFilter to the root logging handler."""
    root_logger = logging.getLogger()
    log_filter = SensitiveLogFilter()
    root_logger.addFilter(log_filter)
    for handler in root_logger.handlers:
        handler.addFilter(log_filter)
