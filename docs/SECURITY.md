# MailTrace AI - Security Architecture & Hardening Guide

## Overview
MailTrace AI is designed for cyber forensic investigation of suspicious emails, RFC-822 headers, and malicious payloads. This document details the application security model, hardening controls, operational assumptions, and production limitations established in **Section 20: Application Security Hardening**.

---

## 1. Upload & File Ingestion Security
- **Strict Size Limits**: File uploads are capped at 10 MB (configurable via `MAX_UPLOAD_SIZE_MB`). Requests exceeding this limit return HTTP 413 `Payload Too Large`.
- **Path Traversal Prevention**: Filenames are sanitized via `UploadSecurityService.sanitize_filename` which strips directory traversal components (`../`, `..\`), removes null bytes (`\x00`), and truncates excessive lengths.
- **Random Internal Naming**: Files stored internally use UUID-generated identifiers (`eml_<uuid>.eml`). User-supplied paths are never used as filesystem targets.
- **MIME & Binary Validation**: Binary executable magic bytes (`MZ`, `\x7fELF`, Mach-O) and prohibited extensions (`.exe`, `.dll`, `.bat`, `.sh`, etc.) are immediately rejected with HTTP 400. Files must exhibit valid RFC-822 header tokens or mbox structure.

---

## 2. HTML Email Safety & Remote Resource Isolation
- **No Raw HTML Execution**: All email HTML content is sanitized before presentation via `HTMLSanitizerService` and sandboxed in the frontend.
- **Prohibited Elements Stripped**:
  - `<script>`
  - `<iframe>`
  - `<object>`
  - `<embed>`
  - `<applet>`
  - `<form>`
  - `<base>`, `<meta>`, `<link>`
- **No Inline JavaScript**: All inline `on*` event handlers (`onload`, `onerror`, `onclick`, `onmouseover`) and pseudo-protocol URIs (`javascript:`, `vbscript:`) are stripped.
- **Remote Tracking Pixel Isolation**: Remote `<img>` tags (`src="http(s)://..."`) are neutralized and blocked by default, preventing external servers from detecting when an email is viewed.
- **Iframe Sandboxing**: Rendered HTML is isolated inside an `<iframe>` with an empty `sandbox=""` attribute and strict Content-Security-Policy:
  ```http
  Content-Security-Policy: default-src 'none'; img-src 'none' data:; style-src 'unsafe-inline'; form-action 'none';
  ```

---

## 3. URL Safety & Non-Clickable Inspection
- **Non-Clickable URLs**: Extracted URLs in tables and forensic sections are rendered as unclickable text with an explicit "Copy URL" button.
- **Pointer Events Disabled**: Links inside sandboxed HTML email previews have `pointer-events: none !important` and `cursor: not-allowed !important` applied.
- **Static URL Analysis**: `URLAnalyzerService` inspects URL lexical syntax strictly offline without visiting or performing HTTP GET/POST requests against user-supplied URLs.

---

## 4. SSRF (Server-Side Request Forgery) Protections
- **Network Boundaries**: Outbound backend intelligence queries are restricted strictly to fixed trusted APIs:
  - IP Intelligence: `ip-api.com` / `pro.ip-api.com`
  - RDAP Lookups: `rdap.org`
  - WHOIS: Authoritative port 43 servers for recognized TLDs.
- **Private & Loopback Filtering**:
  - `SSRFProtector.is_safe_public_ip` blocks `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254` (cloud metadata), and IPv6 link-local/loopback addresses.
  - `SSRFProtector.is_safe_public_domain` blocks `localhost`, `*.internal`, `*.local`, `metadata.google.internal`, and path traversal injection strings.

---

## 5. Rate Limiting & Denial of Service Protection
- **Sliding-Window Rate Limiting**: An in-memory, thread-safe rate limiter throttles burst requests by client IP:
  - Email Upload & Analysis: 20 requests/minute
  - LLM Inference (`/ai-analyst`): 10 requests/minute
  - External Intelligence (`/lookup/*`): 60 requests/minute
  - General API endpoints: 120 requests/minute
- **Exceeded Thresholds**: Returns HTTP 429 `Too Many Requests` with a standard `Retry-After: 60` response header.

---

## 6. HTTP Security Headers
All FastAPI responses include defensive security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none';`

---

## 7. Secrets Management & Privacy in Logs
- **Environment Separation**: API keys (`GEMINI_API_KEY`, `OPENAI_API_KEY`, `IP_INTELLIGENCE_API_KEY`) are read strictly from environment variables.
- **Git Hygiene**: `.env` and `.env.*` are excluded via `.gitignore`. A documented reference is maintained in `.env.example`.
- **Log Sanitizer**: Sensitive tokens, Authorization Bearer credentials, raw passwords, and full email bodies are redacted (`[REDACTED]`) before writing to server logs or audit trails.

---

## 8. Security Assumptions & Remaining Production Limitations

### Assumptions
1. **Analyst Environment**: MailTrace AI is deployed within a secure enterprise SOC enclave (behind SSO/VPN/mTLS).
2. **Reverse Proxy Deployment**: In production, MailTrace AI should be placed behind a reverse proxy (e.g. Nginx, Cloudflare, or AWS ALB) to handle TLS termination, DDoS mitigation, and centralized WAF rules.

### Remaining Production Limitations
1. **In-Memory Rate Limiting**: The current rate limiter uses an in-memory sliding window. In a horizontally autoscaled multi-node deployment, an external Redis or Valkey cluster should be used to share rate-limiting state across worker pods.
2. **Dynamic Malware Sandboxing**: MailTrace AI performs static forensic inspection of attachments and headers. Executable attachments (`.exe`, `.scr`) are flagged and hashed, but dynamic detonations require integration with an external isolated malware sandbox (e.g., Cuckoo Sandbox or Any.Run).
3. **Database Encryption at Rest**: SQLite (`mailtrace.db`) is used for local storage. For enterprise high-concurrency environments, PostgreSQL with encrypted storage volumes (e.g. AWS RDS with KMS encryption) is recommended.
