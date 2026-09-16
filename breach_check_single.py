#!/usr/bin/env python3
"""Breach Check 2.0 -- a single-file, no-login email exposure checker.

Python 3.10+; uses only the Python standard library. No pip installation,
configuration file, API key, or Have I Been Pwned request is required.

Quick start:
    py breach_check_single.py
    py breach_check_single.py --email you@example.com --yes --output report.json
    py breach_check_single.py --list-sites
    py breach_check_single.py --self-test
    py breach_check_single.py --demo --output demo_report.json
    py breach_check_single.py --manual

The built-in lookups are XposedOrNot and LeakCheck Public. They are third-party
breach indexes, NOT the original breached organizations. A provider result is
reported as a provider assertion, never as independently verified evidence.
The program does not claim to search every breach or every website.

When available, XposedOrNot's public metadata is used to find publisher-host or
regulator-host reference pages automatically. Those pages are incident context,
NOT an independently authenticated list of affected accounts. No authentication,
CAPTCHA bypass, credential retrieval, or automatic leak-dump harvesting is implemented.

Existing authorized local/direct-source manifests from version 1 remain optional.
Run --manual for privacy, source provenance, limitations, and exit-code details.
Public API documentation reviewed 2026-09-15; live availability can change.
"""
from __future__ import annotations

import argparse
import codecs
import csv
import getpass
import hashlib
import http.client
import io
import ipaddress
import json
import logging
import math
import os
import re
import socket
import ssl
import sys
import tempfile
import time
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import (HTTPRedirectHandler, HTTPSHandler, ProxyHandler,
                            Request, build_opener)
from urllib.robotparser import RobotFileParser

VERSION = "2.0.0"
CATALOG_REVIEWED = "2026-09-15"
BOT = "DirectBreachCheck"
USER_AGENT = f"{BOT}/{VERSION} (single-email security check)"
LOG = logging.getLogger(BOT)
MAX_RECORD_CHARS = 2_000_000
MAX_EVIDENCE_LOCATIONS = 20
MAX_PROVIDER_ITEMS = 5000
RETRYABLE_HTTP = {408, 425, 500, 502, 503, 504}
# Never contact HIBP, its password service, or the Mozilla Monitor front ends.
# These are hostname checks, not a claim about all other services' upstream data.
EXCLUDED_HOSTS = {
    "haveibeenpwned.com", "pwnedpasswords.com", "monitor.mozilla.org",
    "monitor.firefox.com",
}
ATOM = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
LOCAL_RE = re.compile(rf"{ATOM}(?:\.{ATOM})*\Z")
DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
EMAIL_RE = re.compile(
    rf"(?<![\w.!#$%&'*+/=?^_`{{|}}~@-])"
    rf"{ATOM}(?:\.{ATOM})*@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
    r"(?![\w@-]|\.[\w-])"
)

class CheckError(Exception):
    """An expected failure safe to describe without exposing response bodies."""

    def __init__(self, message: str, code: str = "source_error") -> None:
        super().__init__(message)
        self.code = code


class ConfigurationError(CheckError):
    """Invalid input; the user can correct it without changing the program."""


class FetchError(CheckError):
    """Transport failure with optional bounded retry information."""

    def __init__(self, message: str, code: str = "network_error", *,
                 retryable: bool = False, retry_after: float = 0.0) -> None:
        super().__init__(message, code)
        self.retryable = retryable
        self.retry_after = retry_after


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_email(value: str, fold_local: bool = False) -> str:
    """Support ordinary dot-atom mailboxes; reject unsupported forms explicitly.

    Domain comparison is case-insensitive and IDNA-normalized. Local-part case
    is preserved unless explicitly requested. Do not strip plus-tags or dots.
    Quoted local parts, comments, address literals, and SMTPUTF8 local parts are
    intentionally unsupported instead of being silently misinterpreted.
    """
    if not isinstance(value, str):
        raise ConfigurationError("Email must be a string.", "invalid_email")
    value = value.strip()
    if value.count("@") != 1 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ConfigurationError("Invalid or unsupported email syntax.", "invalid_email")
    local, domain = value.rsplit("@", 1)
    if not LOCAL_RE.fullmatch(local) or len(local.encode("utf-8")) > 64:
        raise ConfigurationError("Unsupported email local part; use a dot-atom address.", "invalid_email")
    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ConfigurationError("Invalid internationalized email domain.", "invalid_email") from exc
    labels = domain.split(".")
    if len(labels) < 2 or len(domain) > 253 or any(not DOMAIN_LABEL_RE.fullmatch(x) for x in labels):
        raise ConfigurationError("Invalid email domain.", "invalid_email")
    result = f"{local.lower() if fold_local else local}@{domain}"
    if len(result.encode("utf-8")) > 254:
        raise ConfigurationError("Email address is too long.", "invalid_email")
    return result


def mask_email(email: str) -> str:
    local, domain = email.rsplit("@", 1)
    return f"{local[:1]}***@{domain}"


def safe_reference(value: str) -> str:
    """Remove URL queries, fragments, userinfo, and recognizable email addresses.

    Do not log arbitrary exception text: requests exceptions can contain URLs,
    API tokens, and other sensitive values. Paths and hostnames are still metadata.
    """
    try:
        if value.lower().startswith(("http://", "https://")):
            parts = urlsplit(value)
            value = urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[-1], parts.path, "", ""))
        value = unquote(value)
    except (ValueError, UnicodeError):
        return "[unavailable reference]"
    value = EMAIL_RE.sub("[email-redacted]", value)
    return "".join(c for c in value if unicodedata.category(c)[0] != "C")[:1500]


def validate_url(url: str, *, resolve: bool = True) -> str:
    """Allow public HTTPS URLs only; re-check every redirect.

    DNS checks are defense in depth, not DNS-pinned SSRF protection. Do not expose
    this CLI as a service accepting untrusted URLs without an egress sandbox.
    """
    if not isinstance(url, str) or len(url) > 8192 or "\\" in url or any(ord(c) <= 32 for c in url):
        raise FetchError("Malformed URL.", "invalid_url")
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        port = 443 if parts.port is None else parts.port
        if parts.scheme.lower() != "https" or not host or port != 443 or parts.username is not None or parts.password is not None:
            raise FetchError("Only HTTPS port 443 without embedded credentials is supported.", "url_policy")
    except (ValueError, UnicodeError) as exc:
        raise FetchError("Malformed URL host or port.", "invalid_url") from exc
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".onion")):
        raise FetchError("Non-public destinations are not supported.", "url_policy")
    if any(host == blocked or host.endswith("." + blocked) for blocked in EXCLUDED_HOSTS):
        raise FetchError("HIBP and specified HIBP front ends are excluded.", "hibp_excluded")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        raise FetchError("Non-public IP literals are not supported.", "url_policy")
    if resolve:
        try:
            records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addresses = {entry[4][0] for entry in records}
            if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
                raise FetchError("Destination resolves to a non-public address.", "url_policy")
        except (socket.gaierror, OSError, ValueError) as exc:
            raise FetchError("DNS resolution failed.", "dns_error") from exc
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


@dataclass(frozen=True)
class Settings:
    """Network and input limits; time budgets are best-effort, not hard deadlines."""
    max_bytes: int = 32 * 1024 * 1024
    timeout: float = 15.0
    source_seconds: float = 60.0
    attempts: int = 3
    interval: float = 1.1
    max_retry_wait: float = 15.0

    def __post_init__(self) -> None:
        if isinstance(self.max_bytes, bool) or not isinstance(self.max_bytes, int) or not 1 <= self.max_bytes <= 256 * 1024 * 1024:
            raise ConfigurationError("Byte limit must be 1 through 256 MiB.", "invalid_settings")
        if isinstance(self.attempts, bool) or not isinstance(self.attempts, int) or not 1 <= self.attempts <= 4:
            raise ConfigurationError("Attempts must be 1 through 4.", "invalid_settings")
        for name in ("timeout", "source_seconds", "interval", "max_retry_wait"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ConfigurationError("Network settings must be finite numbers.", "invalid_settings")
            if value < 0 or (name in {"timeout", "source_seconds"} and value == 0):
                raise ConfigurationError("Invalid timeout or delay.", "invalid_settings")


@dataclass(frozen=True)
class Source:
    id: str
    label: str
    location: str
    format: str
    kind: str = "breach_dataset"
    email_field: str = "email"
    delimiter: str = ","
    encoding: str = "utf-8-sig"
    breach_name: str = ""
    breach_date: str = ""
    data_classes: tuple[str, ...] = ()
    reviewed: bool = False
    review_note: str = ""
    provenance: str = ""
    expected_sha256: str = ""
    synthetic: bool = False


@dataclass
class Outcome:
    source_id: str
    label: str
    kind: str
    source: str
    checked_at: str = field(default_factory=utc_now)
    status: str = "ERROR"
    coverage: str = "not_checked"
    matching_records: int = 0
    records_checked: int = 0
    invalid_records: int = 0
    locations: list[str] = field(default_factory=list)
    sha256: str = ""
    retrieved_from: str = ""
    breach_name: str = ""
    breach_date: str = ""
    data_classes_declared: list[str] = field(default_factory=list)
    operator_reviewed: bool = False
    provenance: str = ""
    review_note: str = ""
    synthetic: bool = False
    error_code: str = ""
    error: str = ""


@dataclass(frozen=True)
class Download:
    body: bytes
    url: str
    content_type: str
    status: int = 200


class NoRedirect(HTTPRedirectHandler):
    """Prevent urllib from silently forwarding an email in a redirected API URL."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


class HttpClient:
    """Serial, bounded HTTPS GETs; no cookies, tokens, netrc, or implicit proxies.

    API requests use provider-documented endpoints, not scraped front-end forms.
    General source pages obey robots.txt and validate each redirect. DNS checks
    are defense in depth, not DNS-pinned SSRF protection. Do not expose this CLI
    as a public URL-fetching service without independent network isolation.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        context = ssl.create_default_context()
        self.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())
        self.last_request: dict[str, float] = {}
        self.robots: dict[str, RobotFileParser | None] = {}
        self.delays: dict[str, float] = {}

    def close(self) -> None:
        # Every individual HTTP response is closed in _request_once.
        self.opener.close()

    @staticmethod
    def _retry_after(value: str | None) -> float | None:
        if not value:
            return None
        try:
            seconds = float(value)
            return max(0.0, seconds) if math.isfinite(seconds) else None
        except ValueError:
            try:
                parsed = parsedate_to_datetime(value)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return max(0.0, (parsed - datetime.now(timezone.utc)).total_seconds())
            except (ValueError, TypeError, OverflowError):
                return None

    @staticmethod
    def _pause(seconds: float, deadline: float) -> None:
        if time.monotonic() + seconds >= deadline:
            raise FetchError("Source time budget exhausted.", "time_budget")
        if seconds > 0:
            time.sleep(seconds)

    def _request_once(self, url: str, limit: int, deadline: float,
                      accepted: set[int], api: bool) -> tuple[int, dict[str, str], bytes]:
        """Read only bounded data; never include a response or URL in an error."""
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        delay = self.delays.get(origin, self.settings.interval)
        wait = max(0.0, self.last_request.get(origin, 0.0) + delay - time.monotonic())
        self._pause(wait, deadline)
        self.last_request[origin] = time.monotonic()
        request = Request(url, method="GET", headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json" if api else "text/html,text/plain,application/xhtml+xml",
            # Explicitly refuse compressed content rather than risking a decompression bomb.
            "Accept-Encoding": "identity",
            "Cache-Control": "no-store",
        })
        response = None
        try:
            try:
                response = self.opener.open(
                    request, timeout=min(self.settings.timeout, max(0.01, deadline-time.monotonic())))
            except HTTPError as exc:
                # HTTPError is also a file-like response. Its body is used ONLY
                # for explicitly accepted statuses such as XON's structured 404.
                response = exc
            status = response.code
            headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
            if 300 <= status < 400:
                return status, headers, b""
            if status not in accepted:
                retry_after = self._retry_after(headers.get("retry-after"))
                if status == 429:
                    raise FetchError(
                        "Provider rate limit reached; coverage is incomplete.", "rate_limited",
                        retryable=retry_after is not None and retry_after <= self.settings.max_retry_wait,
                        retry_after=retry_after or 0.0)
                raise FetchError(f"Server returned HTTP {status}.", f"http_{status}",
                                 retryable=status in RETRYABLE_HTTP,
                                 retry_after=retry_after or 0.0)
            encoding = headers.get("content-encoding", "identity").strip().lower()
            if encoding not in {"", "identity"}:
                raise FetchError("Server ignored the identity-encoding request.", "unsupported_encoding")
            claimed = headers.get("content-length")
            length = None
            if claimed is not None:
                if not re.fullmatch(r"[0-9]{1,15}", claimed.strip()):
                    raise FetchError("Invalid Content-Length header.", "invalid_http_length")
                length = int(claimed)
                if length > limit:
                    raise FetchError("Response exceeds the configured byte limit.", "size_limit")
            chunks = bytearray()
            reader = getattr(response, "read1", response.read)
            while True:
                self._pause(0, deadline)
                chunk = reader(min(65536, limit + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
                if len(chunks) > limit:
                    raise FetchError("Response exceeds the configured byte limit.", "size_limit")
            if length is not None and len(chunks) != length:
                raise FetchError("Response ended before its declared length.", "truncated_response", retryable=True)
            return status, headers, bytes(chunks)
        except ssl.SSLCertVerificationError as exc:
            raise FetchError("TLS certificate verification failed.", "tls_error") from exc
        except ssl.SSLError as exc:
            raise FetchError("TLS handshake or certificate validation failed.", "tls_error") from exc
        except (TimeoutError, socket.timeout) as exc:
            raise FetchError("Connection or read timed out.", "timeout", retryable=True) from exc
        except URLError as exc:
            if isinstance(exc.reason, ssl.SSLError):
                raise FetchError("TLS verification or handshake failed.", "tls_error") from exc
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise FetchError("Connection or read timed out.", "timeout", retryable=True) from exc
            if isinstance(exc.reason, socket.gaierror):
                raise FetchError("DNS resolution failed.", "dns_error") from exc
            raise FetchError("Could not establish the HTTPS connection.", "connection_error", retryable=True) from exc
        except (http.client.HTTPException, ConnectionError, OSError) as exc:
            raise FetchError("Connection failed or response was truncated.", "connection_error", retryable=True) from exc
        finally:
            if response is not None:
                response.close()

    def _robots_allowed(self, url: str, deadline: float) -> None:
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin not in self.robots:
            try:
                doc = self.fetch(origin + "/robots.txt", limit=512000,
                                 obey_robots=False, deadline=deadline)
            except FetchError as exc:
                if exc.code in {"http_404", "http_410"}:
                    self.robots[origin] = None
                else:
                    raise FetchError("Could not establish robots.txt permission.", "robots_unavailable") from exc
            else:
                if "html" in doc.content_type:
                    raise FetchError("robots.txt returned HTML instead of rules.", "robots_unavailable")
                try:
                    parser = RobotFileParser()
                    parser.parse(doc.body.decode("utf-8-sig", errors="strict").splitlines())
                except (UnicodeError, ValueError) as exc:
                    raise FetchError("Could not parse robots.txt.", "robots_unavailable") from exc
                delay = parser.crawl_delay(BOT) or 0
                rate = parser.request_rate(BOT)
                if rate and rate.requests > 0:
                    delay = max(delay, rate.seconds / rate.requests)
                if delay > self.settings.max_retry_wait:
                    raise FetchError("Required crawl delay exceeds this run's budget.", "robots_delay")
                self.delays[origin] = max(self.settings.interval, delay)
                self.robots[origin] = parser
        rules = self.robots[origin]
        if rules is not None and not rules.can_fetch(BOT, url):
            raise FetchError("robots.txt disallows this page.", "robots_denied")

    def fetch(self, url: str, *, limit: int | None = None, obey_robots: bool = True,
              deadline: float | None = None, api: bool = False,
              accepted: set[int] | None = None,
              allowed_hosts: set[str] | None = None) -> Download:
        """No API redirects. Page redirects remain within any supplied host scope."""
        limit = self.settings.max_bytes if limit is None else limit
        deadline = time.monotonic() + self.settings.source_seconds if deadline is None else deadline
        accepted = {200} if accepted is None else accepted
        current = url
        for redirect in range(6):
            # Called on every destination, including redirects. APIs do not follow any.
            current = validate_url(current)
            if allowed_hosts is not None and urlsplit(current).hostname not in allowed_hosts:
                raise FetchError("Redirect left the approved reference hostname.", "redirect_scope")
            if obey_robots:
                self._robots_allowed(current, deadline)
            for attempt in range(self.settings.attempts):
                try:
                    status, headers, body = self._request_once(current, limit, deadline, accepted, api)
                    break
                except FetchError as exc:
                    if not exc.retryable or attempt + 1 >= self.settings.attempts:
                        raise
                    wait = max(2.0 ** attempt, exc.retry_after)
                    if wait > self.settings.max_retry_wait:
                        raise
                    self._pause(wait, deadline)
            if 300 <= status < 400:
                if api:
                    raise FetchError("API redirect refused to protect the query.", "api_redirect")
                location = headers.get("location")
                if not location or redirect == 5:
                    raise FetchError("Missing Location header or too many redirects.", "redirect_error")
                current = urljoin(current, location)
                continue
            content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
            return Download(body, current, content_type, status)
        raise FetchError("Too many redirects.", "redirect_error")


def decode_json(doc: Download) -> dict[str, Any]:
    """Reject HTML challenges, duplicate keys, nonfinite values, and schema drift."""
    if doc.content_type != "application/json" and not doc.content_type.endswith("+json"):
        raise CheckError("Expected JSON; received a challenge page or another format.", "non_json_response")
    try:
        def reject_constant(value: str) -> None:
            raise ValueError("Nonfinite JSON constant.")
        result = json.loads(doc.body.decode("utf-8-sig"),
                            object_pairs_hook=_reject_duplicate_keys,
                            parse_constant=reject_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise CheckError("Malformed, ambiguous, or excessively nested JSON.", "invalid_json") from exc
    if not isinstance(result, dict):
        raise CheckError("Expected a JSON object.", "schema_error")
    return result


def load_sources(path: Path) -> list[Source]:
    """Load an explicit manifest. Unknown keys fail rather than hide misspellings."""
    try:
        if path.stat().st_size > 1_000_000:
            raise ConfigurationError("Source manifest exceeds 1 MB.", "manifest_size")
        obj = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise ConfigurationError("Could not read the source manifest as UTF-8 JSON.", "manifest_error") from exc
    if not isinstance(obj, dict) or set(obj) != {"sources"} or not isinstance(obj["sources"], list):
        raise ConfigurationError('Manifest must contain exactly one key: "sources", an array.', "manifest_schema")
    if len(obj["sources"]) > 200:
        raise ConfigurationError("At most 200 explicit sources are allowed per run.", "manifest_size")
    allowed = set(Source.__dataclass_fields__)
    ids: set[str] = set()
    sources: list[Source] = []
    for index, item in enumerate(obj["sources"], 1):
        prefix = f"Manifest source {index}: "
        if not isinstance(item, dict) or set(item) - allowed:
            raise ConfigurationError(prefix + "unknown field or invalid object.", "manifest_schema")
        for required in ("id", "label", "location", "format"):
            if not isinstance(item.get(required), str) or not item[required].strip():
                raise ConfigurationError(prefix + f"{required} must be a non-empty string.", "manifest_schema")
        values = dict(item)
        for name in ("reviewed", "synthetic"):
            if name in values and not isinstance(values[name], bool):
                raise ConfigurationError(prefix + f"{name} must be a JSON boolean.", "manifest_schema")
        classes = values.get("data_classes", [])
        if not isinstance(classes, list) or any(not isinstance(x, str) for x in classes):
            raise ConfigurationError(prefix + "data_classes must be an array of strings.", "manifest_schema")
        values["data_classes"] = tuple(classes)
        for key, value in values.items():
            if key not in {"reviewed", "synthetic", "data_classes"} and not isinstance(value, str):
                raise ConfigurationError(prefix + f"{key} must be a string.", "manifest_schema")
        source = Source(**values)
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", source.id) or source.id in ids:
            raise ConfigurationError(prefix + "id must be unique and use letters, digits, _, ., or -.", "manifest_schema")
        ids.add(source.id)
        if source.format not in {"csv", "jsonl", "txt", "html"}:
            raise ConfigurationError(prefix + "supported formats: csv, jsonl, txt, html.", "manifest_schema")
        if source.kind not in {"breach_dataset", "web_page"}:
            raise ConfigurationError(prefix + "kind must be breach_dataset or web_page.", "manifest_schema")
        if (source.format == "html") != (source.kind == "web_page"):
            raise ConfigurationError(prefix + "HTML must be a web_page; datasets must be structured/email-list files.", "manifest_schema")
        if len(source.delimiter) != 1 or source.delimiter in {"\r", "\n", '"', "\x00"} or not source.email_field:
            raise ConfigurationError(prefix + "invalid delimiter or email_field.", "manifest_schema")
        try:
            codecs.lookup(source.encoding)
        except LookupError as exc:
            raise ConfigurationError(prefix + "unknown text encoding.", "manifest_schema") from exc
        if source.expected_sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", source.expected_sha256):
            raise ConfigurationError(prefix + "expected_sha256 must contain 64 hexadecimal characters.", "manifest_schema")
        if source.breach_date:
            try:
                datetime.strptime(source.breach_date, "%Y-%m-%d")
            except ValueError as exc:
                raise ConfigurationError(prefix + "breach_date must be YYYY-MM-DD.", "manifest_schema") from exc
        if source.reviewed and (
            source.kind != "breach_dataset" or not source.breach_name.strip()
            or not source.review_note.strip() or not source.provenance.strip()
            or not source.expected_sha256
        ):
            raise ConfigurationError(prefix + "reviewed datasets require breach_name, provenance, review_note, and expected_sha256.", "manifest_schema")
        if source.location.lower().startswith(("https://", "http://")):
            values["location"] = validate_url(source.location, resolve=False)
            source = Source(**values)
        else:
            if "://" in source.location:
                raise ConfigurationError(prefix + "unsupported location scheme.", "manifest_schema")
            values["location"] = str((path.resolve().parent / source.location).resolve())
            source = Source(**values)
        sources.append(source)
    return sources


class PageText(HTMLParser):
    """Extract static HTML text, not scripts, CSS, attributes, or linked documents."""

    SKIP = {"script", "style", "template", "noscript"}
    BLOCK = {"p", "div", "br", "li", "tr", "td", "h1", "h2", "h3", "section", "article", "body"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip_depth = 0
        self.in_title = False
        self.title: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.SKIP:
            self.skip_depth += 1
        if tag == "title":
            self.in_title = True
        if not self.skip_depth and tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self.SKIP:
            self.skip_depth = max(0, self.skip_depth - 1)
        if tag == "title":
            self.in_title = False
        if not self.skip_depth and tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title.append(data)
        if not self.skip_depth:
            self.parts.append(data)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate JSON object key.")
        obj[key] = value
    return obj


def scan_content(source: Source, body: bytes, target: str, outcome: Outcome,
                 fold_local: bool) -> None:
    """Parse only the configured email field; count malformed records explicitly."""
    digest = hashlib.sha256(body).hexdigest()
    outcome.sha256 = digest
    if source.expected_sha256 and digest != source.expected_sha256.lower():
        raise CheckError("Content hash does not match the reviewed/pinned file.", "hash_mismatch")
    if not body:
        raise CheckError("Source is empty; its completeness cannot be established.", "empty_source")
    try:
        text = body.decode(source.encoding, errors="strict")
    except UnicodeError as exc:
        raise CheckError("Text decoding failed; check the manifest encoding.", "encoding_error") from exc
    if "\x00" in text:
        raise CheckError("Unexpected NUL bytes; source may not be a supported text file.", "unsupported_content")

    def record(value: Any, location: str) -> None:
        outcome.records_checked += 1
        try:
            candidate = normalize_email(value, fold_local)
        except ConfigurationError:
            outcome.invalid_records += 1
            return
        if candidate == target:
            outcome.matching_records += 1
            if len(outcome.locations) < MAX_EVIDENCE_LOCATIONS:
                outcome.locations.append(location)

    try:
        if source.format == "csv":
            csv.field_size_limit(MAX_RECORD_CHARS)
            reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=source.delimiter, strict=True)
            columns = reader.fieldnames
            if not columns or source.email_field not in columns or len(columns) != len(set(columns)):
                raise CheckError("Missing email column or duplicate CSV column names.", "csv_schema")
            for row in reader:
                if None in row or any(value is None for value in row.values()):
                    outcome.records_checked += 1
                    outcome.invalid_records += 1
                    continue
                record(row.get(source.email_field), f"CSV physical line ending {reader.line_num}")
        elif source.format == "jsonl":
            for number, line in enumerate(io.StringIO(text), 1):
                if not line.strip():
                    continue
                if len(line) > MAX_RECORD_CHARS:
                    raise CheckError("JSONL record exceeds the record-size limit.", "record_limit")
                try:
                    row = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
                except (json.JSONDecodeError, ValueError, RecursionError):
                    outcome.records_checked += 1
                    outcome.invalid_records += 1
                    continue
                record(row.get(source.email_field) if isinstance(row, dict) else None, f"JSONL line {number}")
        elif source.format == "txt":
            # Exactly one email per non-blank line. This does not parse credentials.
            for number, line in enumerate(io.StringIO(text), 1):
                if line.strip():
                    if len(line) > MAX_RECORD_CHARS:
                        raise CheckError("TXT record exceeds the record-size limit.", "record_limit")
                    record(line.strip(), f"TXT line {number}")
        else:
            page = PageText()
            page.feed(text)
            page.close()
            title = "".join(page.title).strip().lower()
            if any(x in title for x in ("just a moment", "access denied", "verify you are human", "captcha", "sign in", "log in")):
                raise CheckError("Page appears to be a login, challenge, or access-denied page.", "page_unavailable")
            visible = "".join(page.parts)
            if not visible.strip():
                raise CheckError("No static page text available; JavaScript is not executed.", "no_static_text")
            for number, match in enumerate(EMAIL_RE.finditer(visible), 1):
                record(match.group(0), f"Static HTML email occurrence {number}")
    except csv.Error as exc:
        raise CheckError("Malformed CSV; parsing stopped before end of source.", "csv_parse_error") from exc
    if outcome.records_checked == 0 and source.kind == "breach_dataset":
        raise CheckError("Dataset contained no email records; completeness is unknown.", "empty_dataset")
    outcome.coverage = "partial" if outcome.invalid_records else "complete_for_checked_content"
    if outcome.invalid_records:
        outcome.error_code = "invalid_records"
        outcome.error = "One or more records could not be checked; no clean negative conclusion is possible."


def finish_status(source: Source, outcome: Outcome) -> None:
    """Never conflate an error or a public mention with a verified breach."""
    if outcome.matching_records:
        if source.synthetic:
            outcome.status = "SYNTHETIC_MATCH"
        elif source.kind == "web_page":
            outcome.status = "PUBLIC_MENTION"
        elif source.reviewed:
            outcome.status = "MATCH_OPERATOR_REVIEWED_DATASET"
        else:
            outcome.status = "MATCH_UNVERIFIED_DATASET"
    elif outcome.coverage == "complete_for_checked_content":
        outcome.status = "NO_MATCH_IN_CHECKED_CONTENT"
    elif outcome.coverage == "partial":
        outcome.status = "INCOMPLETE"
    else:
        outcome.status = "ERROR"


def check_source(source: Source, target: str, client: HttpClient,
                 fold_local: bool = False) -> Outcome:
    outcome = Outcome(
        source_id=source.id, label=safe_reference(source.label), kind=source.kind,
        source=safe_reference(source.location), breach_name=safe_reference(source.breach_name),
        breach_date=source.breach_date, data_classes_declared=[safe_reference(x) for x in source.data_classes],
        operator_reviewed=source.reviewed, provenance=safe_reference(source.provenance),
        review_note=safe_reference(source.review_note), synthetic=source.synthetic,
    )
    try:
        if source.location.startswith("https://"):
            doc = client.fetch(source.location)
            outcome.retrieved_from = safe_reference(doc.url)
            if source.format != "html" and "html" in doc.content_type:
                raise CheckError("Expected dataset but server returned an HTML page.", "unexpected_content_type")
            if source.format == "html" and doc.content_type not in {"text/html", "application/xhtml+xml", "text/plain", ""}:
                raise CheckError("Page has an unsupported content type; PDF and binaries are not parsed.", "unsupported_content_type")
            body = doc.body
        else:
            path = Path(source.location)
            if not path.is_file():
                raise CheckError("Local source does not exist or is not a regular file.", "file_unavailable")
            if path.stat().st_size > client.settings.max_bytes:
                raise CheckError("Local source exceeds the configured byte limit.", "size_limit")
            with path.open("rb") as handle:
                body = handle.read(client.settings.max_bytes + 1)
            if len(body) > client.settings.max_bytes:
                raise CheckError("Local source grew beyond the byte limit.", "size_limit")
        scan_content(source, body, target, outcome, fold_local)
    except CheckError as exc:
        outcome.error_code, outcome.error = exc.code, str(exc)
        outcome.coverage = "partial" if outcome.records_checked else "not_checked"
    except PermissionError:
        outcome.error_code, outcome.error = "permission_denied", "Permission denied while reading the source."
    except OSError:
        outcome.error_code, outcome.error = "io_error", "File or operating-system I/O error."
    except (ValueError, LookupError, RecursionError):
        outcome.error_code, outcome.error = "parse_error", "Could not parse the source safely."
        outcome.coverage = "partial" if outcome.records_checked else "not_checked"
    except Exception as exc:
        # Boundary-only safety net: continue other sources, but expose the failure.
        # Do not suppress KeyboardInterrupt/SystemExit or print sensitive tracebacks.
        outcome.error_code = "unexpected_error"
        outcome.error = f"Unexpected {type(exc).__name__}; source was not fully checked."
        outcome.coverage = "partial" if outcome.records_checked else "not_checked"
    finish_status(source, outcome)
    return outcome


def write_report(path: Path, report: dict[str, Any]) -> None:
    """Replace atomically; use restrictive permissions for the temporary report."""
    temp_name: str | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temp_name = tempfile.mkstemp(prefix=".breach-report-", suffix=".tmp", dir=path.parent)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if temp_name:
            try:
                Path(temp_name).unlink(missing_ok=True)
            except OSError:
                LOG.warning("Could not remove a temporary report file.")


def positive_number(value: str) -> float:
    try:
        result = float(value)
        if not math.isfinite(result) or result <= 0:
            raise ValueError
        return result
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Must be a finite positive number.") from exc


# ---------------------------------------------------------------------------
# Built-in source catalog. Add providers here AND implement a strict parser.
# Do not add a login-only site, guessed endpoint, borrowed API key, or HIBP proxy.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProviderSpec:
    id: str
    label: str
    homepage: str
    documentation: str
    endpoint: str
    disclosure: str
    notes: str


PROVIDERS: dict[str, ProviderSpec] = {
    "xposedornot": ProviderSpec(
        "xposedornot", "XposedOrNot", "https://xposedornot.com/",
        "https://xposedornot.com/api_doc",
        "https://api.xposedornot.com/v1/check-email/{email}",
        "The full email address is sent to api.xposedornot.com over HTTPS.",
        "Public breach index; no key. Public search may omit privacy-shielded or sensitive records. "
        "Documented free limits at review: 2/s, 25/hour, 100/day for this endpoint."),
    "leakcheck": ProviderSpec(
        "leakcheck", "LeakCheck Public", "https://leakcheck.io/",
        "https://docs.leakcheck.io/public-api/lookup",
        "https://leakcheck.io/api/public",
        "The first 24 hexadecimal characters of SHA-256(lowercase email) are sent to leakcheck.io. "
        "This deterministic identifier is NOT anonymity or a guarantee against identification.",
        "Public breach-source and exposed-category lookup; no key and no raw records. "
        "Documented limit at review: 1 request/second. Powered by LeakCheck."),
}

# These are REVIEWED CANDIDATES, NOT checked sources. The catalog distinguishes
# 'documented without login' from 'a home page exists' and from 'an old script
# contains an endpoint'. Inclusion in this list never inflates coverage counts.
NOT_AUTOMATED: tuple[dict[str, str], ...] = (
    {"site": "Have I Been Pwned / Pwned Passwords",
     "reason": "Excluded by the user's requirement; hostnames are blocked in the transport.",
     "reference": "https://haveibeenpwned.com/API/v3"},
    {"site": "HackCheck (Woven Teams)",
     "reason": "A public API is documented, but current operation and upstream independence from HIBP "
               "were not established during this review. Not silently used as an HIBP replacement.",
     "reference": "https://hackcheck.woventeams.com/api/v4"},
    {"site": "Hudson Rock",
     "reason": "Current documented email-search API requires authorization. Older free OSINT endpoint "
               "availability and a current supported no-key contract were not verified.",
     "reference": "https://docs.hudsonrock.com/docs/email-search"},
    {"site": "Snusbase",
     "reason": "Email search/count requires an activation code. Public database statistics do not "
               "establish whether a particular email is present.",
     "reference": "https://docs.snusbase.com/"},
    {"site": "Leak-Lookup",
     "reason": "The documented search API requires the client's API key; no embedded shared keys are used.",
     "reference": "https://leak-lookup.com/docs/search"},
    {"site": "Intelligence X",
     "reason": "Has a non-registered-user instance, but its documentation requires an API license "
               "or higher for third-party integrations. No borrowed browser keys are used.",
     "reference": "https://help.intelx.io/api/"},
    {"site": "Breachsense",
     "reason": "Documented search endpoints use a license key; not a no-credential provider for this tool.",
     "reference": "https://www.breachsense.com/documentation/"},
    {"site": "California Attorney General breach notices",
     "reason": "Original notification material, not an affected-email membership database. "
               "Qualifying notice URLs discovered in metadata may be retrieved as context only.",
     "reference": "https://oag.ca.gov/privacy/databreach/list"},
)

# This is a reference-host allowlist, NOT eight extra account lookup services.
REGULATOR_HOSTS = {
    "oag.ca.gov", "www.oag.ca.gov", "www.maine.gov", "maine.gov",
    "www.doj.nh.gov", "doj.nh.gov", "www.mass.gov", "mass.gov",
    "ago.vermont.gov", "www.iowaattorneygeneral.gov", "attorneygeneral.nd.gov",
    "www.texasattorneygeneral.gov", "www.hhs.gov", "ocrportal.hhs.gov",
}


@dataclass
class BreachFinding:
    name: str
    date: str = ""
    domain: str = ""
    data_classes: list[str] = field(default_factory=list)
    provider_verified: bool | None = None
    reference_urls: list[str] = field(default_factory=list)
    # For LeakCheck, 'fields' is query-wide, not per-breach. Keep it on the
    # ProviderResult rather than falsely copying every field onto every breach.


@dataclass
class ProviderResult:
    provider_id: str
    label: str
    documentation: str
    disclosure: str
    checked_at: str = field(default_factory=utc_now)
    status: str = "ERROR"
    coverage: str = "not_checked"
    match_reported: bool = False
    reported_record_count: int | None = None
    findings: list[BreachFinding] = field(default_factory=list)
    data_classes_across_results: list[str] = field(default_factory=list)
    response_sha256: str = ""
    error_code: str = ""
    error: str = ""
    warnings: list[str] = field(default_factory=list)
    synthetic: bool = False
    evidence_level: str = "provider_reported_not_independently_verified"


def new_provider_result(spec: ProviderSpec) -> ProviderResult:
    return ProviderResult(spec.id, spec.label, spec.documentation, spec.disclosure)


def metadata_text(value: Any, limit: int = 250, *, optional: bool = False) -> str:
    """Validate short public metadata, strip terminal controls, and redact emails."""
    if optional and value is None:
        return ""
    if not isinstance(value, str) or len(value) > 10000:
        raise CheckError("Provider returned an invalid metadata field.", "schema_error")
    value = safe_reference(value).strip()
    if not value and not optional:
        raise CheckError("Provider returned an empty required metadata field.", "schema_error")
    return value[:limit]


def public_fields(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > 200:
        raise CheckError("Expected an array of exposed-data category labels.", "schema_error")
    return list(dict.fromkeys(metadata_text(x, 100) for x in value))


def _complete_provider(result: ProviderResult, *, partial: bool = False) -> None:
    if partial:
        result.status = "INCOMPLETE"
        result.coverage = "partial_provider_response"
        result.error_code = "schema_error"
        result.error = "Some provider data was missing or malformed; usable positive findings were retained."
    else:
        result.status = "MATCH_REPORTED" if result.match_reported else "NO_MATCH_REPORTED"
        result.coverage = "complete_for_provider_response"
    if result.synthetic and result.match_reported:
        result.status = "SYNTHETIC_MATCH"


def parse_xposedornot(doc: Download, target: str, result: ProviderResult) -> None:
    """Only the documented JSON not-found contract can turn a 404 into no match."""
    data = decode_json(doc)
    result.response_sha256 = hashlib.sha256(doc.body).hexdigest()
    echo = data.get("email")
    if echo is not None:
        try:
            same = normalize_email(echo, True) == normalize_email(target, True)
        except ConfigurationError as exc:
            raise CheckError("Provider returned an invalid email echo.", "query_mismatch") from exc
        if not same:
            raise CheckError("Provider response belongs to another query.", "query_mismatch")
    if data.get("Error") == "Not found" and doc.status in {200, 404}:
        if data.get("breaches") not in (None, [], [[]]):
            raise CheckError("Contradictory match and not-found fields.", "schema_error")
        result.match_reported = False
        _complete_provider(result)
        return
    if doc.status != 200 or "Error" in data or "error" in data:
        raise CheckError("Provider did not return a recognized success response.", "provider_error")
    entries = data.get("breaches")
    if data.get("status") not in (None, "success") or not isinstance(entries, list):
        raise CheckError("The provider's breach-list schema changed.", "schema_error")
    if len(entries) > MAX_PROVIDER_ITEMS:
        raise CheckError("Provider item limit exceeded.", "provider_item_limit")
    names: list[str] = []
    invalid = 0
    total = 0
    for entry in entries:
        batch = entry if isinstance(entry, list) else [entry]
        for name in batch:
            total += 1
            if total > MAX_PROVIDER_ITEMS:
                raise CheckError("Provider item limit exceeded.", "provider_item_limit")
            try:
                names.append(metadata_text(name))
            except CheckError:
                invalid += 1
    result.findings = [BreachFinding(name) for name in dict.fromkeys(names)]
    result.match_reported = bool(result.findings)
    # Empty lists without an explicit success marker are ambiguous, not a clean negative.
    partial = bool(invalid or (not names and data.get("status") != "success"))
    _complete_provider(result, partial=partial)


def parse_leakcheck(doc: Download, target: str, result: ProviderResult) -> None:
    """Keep breach-record count separate from incident count and query-wide fields."""
    data = decode_json(doc)
    result.response_sha256 = hashlib.sha256(doc.body).hexdigest()
    if doc.status != 200 or data.get("success") is not True:
        raise CheckError("LeakCheck did not return a recognized success response.", "provider_error")
    found = data.get("found")
    if isinstance(found, bool) or not isinstance(found, int) or found < 0:
        raise CheckError("LeakCheck returned an invalid found count.", "schema_error")
    sources = data.get("sources")
    if found == 0 and sources not in (None, []):
        raise CheckError("Contradictory zero count and nonempty source list.", "schema_error")
    result.reported_record_count = found
    result.match_reported = found > 0
    partial = False
    try:
        result.data_classes_across_results = public_fields(data.get("fields", []))
    except CheckError:
        partial = True
    if not isinstance(sources, list) or len(sources) > MAX_PROVIDER_ITEMS:
        _complete_provider(result, partial=True)
        return
    seen: set[tuple[str, str]] = set()
    for source in sources:
        try:
            if not isinstance(source, dict):
                raise CheckError("Invalid source entry.", "schema_error")
            name = metadata_text(source.get("name"))
            date = metadata_text(source.get("date"), 40, optional=True)
            key = (name, date)
            if key not in seen:
                seen.add(key)
                result.findings.append(BreachFinding(name=name, date=date))
        except CheckError:
            partial = True
    if found > 0 and not result.findings:
        partial = True
    _complete_provider(result, partial=partial)


def provider_request(spec: ProviderSpec, target: str) -> tuple[str, set[int]]:
    """Build only approved public endpoints. No endpoint is guessed at runtime."""
    if spec.id == "xposedornot":
        return spec.endpoint.format(email=quote(target, safe="")), {200, 404}
    if spec.id == "leakcheck":
        # LeakCheck supports a 24-hex-character SHA-256 email identifier.
        # Lowercasing is a provider-query convention, not local RFC mailbox identity.
        digest = hashlib.sha256(target.lower().encode("utf-8")).hexdigest()[:24]
        return spec.endpoint + "?" + urlencode({"check": digest}), {200}
    raise ConfigurationError("No adapter exists for this source.", "unknown_provider")


def check_provider(spec: ProviderSpec, target: str, client: HttpClient) -> ProviderResult:
    result = new_provider_result(spec)
    try:
        url, accepted = provider_request(spec, target)
        doc = client.fetch(url, api=True, obey_robots=False, accepted=accepted,
                           limit=min(client.settings.max_bytes, 4 * 1024 * 1024),
                           allowed_hosts={urlsplit(url).hostname or ""})
        parsers: dict[str, Callable[[Download, str, ProviderResult], None]] = {
            "xposedornot": parse_xposedornot, "leakcheck": parse_leakcheck}
        parsers[spec.id](doc, target, result)
    except CheckError as exc:
        result.error_code, result.error = exc.code, str(exc)
        result.status = "INCOMPLETE" if result.match_reported else "ERROR"
        result.coverage = "partial_provider_response" if result.match_reported else "not_checked"
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        result.error_code = "provider_processing_error"
        result.error = f"Could not process this source ({type(exc).__name__}); it was not fully checked."
        result.status = "INCOMPLETE" if result.match_reported else "ERROR"
        result.coverage = "partial_provider_response" if result.match_reported else "not_checked"
    except Exception as exc:
        # A boundary safety net keeps the next source running without hiding this failure.
        result.error_code = "unexpected_error"
        result.error = f"Unexpected {type(exc).__name__}; source was not fully checked."
        result.status = "INCOMPLETE" if result.match_reported else "ERROR"
        result.coverage = "partial_provider_response" if result.match_reported else "not_checked"
    return result


def enrich_xposedornot(result: ProviderResult, client: HttpClient) -> dict[str, Any]:
    """Get public incident metadata, without sending the email a second time.

    Join on an exact case-insensitive breach ID, never a fuzzy company-name guess.
    A metadata failure cannot erase an already-observed account lookup result.
    """
    state: dict[str, Any] = {"status": "not_needed", "matched_metadata_entries": 0,
                             "endpoint": "https://api.xposedornot.com/v1/breaches"}
    if not result.match_reported or not result.findings:
        return state
    try:
        doc = client.fetch(state["endpoint"], api=True, obey_robots=False,
                           limit=min(client.settings.max_bytes, 8 * 1024 * 1024),
                           allowed_hosts={"api.xposedornot.com"})
        data = decode_json(doc)
        entries = data.get("exposedBreaches")
        if not isinstance(entries, list) or len(entries) > MAX_PROVIDER_ITEMS:
            raise CheckError("The public metadata catalog schema changed.", "metadata_schema")
        by_id: dict[str, dict[str, Any]] = {}
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("breachID"), str):
                key = entry["breachID"].casefold()
                if key in by_id:
                    raise CheckError("Duplicate breach IDs in metadata catalog.", "metadata_schema")
                by_id[key] = entry
        invalid = 0
        for finding in result.findings:
            entry = by_id.get(finding.name.casefold())
            if entry is None:
                continue
            try:
                date = metadata_text(entry.get("breachedDate"), 50, optional=True)
                domain = metadata_text(entry.get("domain"), 253, optional=True)
                if domain:
                    domain = normalize_email("check@" + domain).split("@", 1)[1]
                classes = public_fields(entry.get("exposedData", []))
                reference = entry.get("referenceURL", "")
                if reference is None:
                    reference = ""
                if not isinstance(reference, str) or len(reference) > 8192:
                    raise CheckError("Invalid metadata reference.", "metadata_schema")
                verified = entry.get("verified")
                finding.date, finding.domain, finding.data_classes = date, domain, classes
                finding.provider_verified = verified if isinstance(verified, bool) else None
                # A raw reference is held only to apply strict URL/privacy checks.
                # Report generation sanitizes it, whether fetched or skipped.
                finding.reference_urls = [reference] if reference else []
                state["matched_metadata_entries"] += 1
            except CheckError:
                invalid += 1
        state.update(status="partial" if invalid else "complete_for_returned_catalog",
                     response_sha256=hashlib.sha256(doc.body).hexdigest(),
                     invalid_matching_entries=invalid)
    except CheckError as exc:
        state.update(status="error", error_code=exc.code, error=str(exc))
    except Exception as exc:
        state.update(status="error", error_code="unexpected_metadata_error",
                     error=f"Metadata lookup failed ({type(exc).__name__}).")
    return state


def qualify_reference(url: str, domain: str, target: str) -> tuple[str, str]:
    """Use publisher-host matches or known regulator hosts, not arbitrary leak sites.

    Host matching is only a routing heuristic. It does not authenticate the source,
    prove a breach, or establish that the email is among affected accounts.
    """
    normalized = validate_url(url, resolve=False)
    parts = urlsplit(normalized)
    host = parts.hostname or ""
    decoded = normalized
    for _ in range(8):
        new_decoded = unquote(decoded)
        if new_decoded == decoded:
            break
        decoded = new_decoded
    if parts.query or EMAIL_RE.search(decoded) or target.lower() in decoded.lower():
        raise CheckError("Reference has a query string or email-bearing URL; not fetched.", "reference_privacy")
    suffix = Path(parts.path.lower()).suffix
    if suffix in {".pdf", ".zip", ".gz", ".tgz", ".7z", ".rar", ".csv", ".jsonl", ".xlsx", ".docx", ".exe"}:
        raise CheckError("Automatic references are HTML/text only; no PDFs, archives, or datasets.", "reference_format")
    if host in REGULATOR_HOSTS:
        return normalized, "regulator_host_context"
    if domain:
        domain = normalize_email("check@" + domain).split("@", 1)[1]
        if host == domain or host.endswith("." + domain):
            return normalized, "publisher_host_match_context"
    raise CheckError("Reference is not on the named publisher or an approved regulator host.", "not_primary_host")


def check_references(results: list[ProviderResult], target: str, client: HttpClient,
                     limit: int) -> list[dict[str, Any]]:
    """Automatically visit qualifying incident references; never claim membership."""
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    attempted = 0
    for result in results:
        for finding in result.findings:
            for original in finding.reference_urls:
                if original in seen:
                    continue
                seen.add(original)
                row: dict[str, Any] = {
                    "provider": result.provider_id, "breach_label": finding.name,
                    "url": safe_reference(original), "checked_at": utc_now(),
                    "status": "SKIPPED", "email_membership_established": False,
                    "warning": "Incident context only; hostname similarity and an email mention do not prove breach inclusion."}
                try:
                    url, classification = qualify_reference(original, finding.domain, target)
                    row["classification"] = classification
                    if attempted >= limit:
                        row.update(reason="reference_limit", detail="Per-run reference-page limit reached.")
                        output.append(row)
                        continue
                    attempted += 1
                    host = urlsplit(url).hostname or ""
                    hosts = {host, host[4:]} if host.startswith("www.") else {host, "www." + host}
                    doc = client.fetch(url, limit=min(client.settings.max_bytes, 4 * 1024 * 1024),
                                       allowed_hosts=hosts)
                    if doc.content_type not in {"text/html", "application/xhtml+xml", "text/plain"}:
                        raise CheckError("Reference is not supported HTML or plain text.", "reference_content_type")
                    source = Source("auto-reference", "Automatic reference", url, "html", kind="web_page")
                    inspected = Outcome(source.id, source.label, source.kind, safe_reference(url))
                    scan_content(source, doc.body, target, inspected, False)
                    page = PageText()
                    page.feed(doc.body.decode("utf-8-sig", errors="strict"))
                    page.close()
                    row.update(status="CONTEXT_PAGE_RETRIEVED", retrieved_from=safe_reference(doc.url),
                               response_sha256=inspected.sha256,
                               title=safe_reference("".join(page.title))[:250],
                               exact_email_mentioned=bool(inspected.matching_records))
                except CheckError as exc:
                    row.update(reason=exc.code, detail=str(exc))
                    if exc.code not in {"reference_privacy", "reference_format", "not_primary_host", "hibp_excluded"}:
                        row["status"] = "UNAVAILABLE"
                except Exception as exc:
                    row.update(status="UNAVAILABLE", reason="unexpected_reference_error",
                               detail=f"Could not inspect this reference ({type(exc).__name__}).")
                output.append(row)
    return output


# ---------------------------------------------------------------------------
# Reports, command line, and built-in documentation.
# ---------------------------------------------------------------------------

MANUAL = r"""
BREACH CHECK -- SINGLE FILE
==========================
Python 3.10+; standard library only. No pip, API keys, account, manifest, or ZIP
extraction is required for the default check.

START
    py breach_check_single.py
    py breach_check_single.py --email you@example.com --yes --output report.json
On Linux/macOS use python3 in place of py. Omitting --email prompts without echo
and avoids putting the email in shell history. --yes acknowledges authorized use
and the network disclosure explained below; it does not bypass provider access
controls. Interactive use otherwise asks for that acknowledgment.

DEFAULT AUTOMATIC SOURCES
    XposedOrNot: public check-email endpoint, followed by public breach metadata
                when needed. No API key. Full email is sent over HTTPS.
    LeakCheck Public: no API key; sends a deterministic 24-hex-character SHA-256
                identifier derived from the lowercase email. No password lookup.
These are third-party indexes, not original-source datasets. The code calls
neither HIBP nor Pwned Passwords. Providers may share underlying incidents or
records, so agreement is not necessarily independent corroboration.

    py breach_check_single.py --list-sites
This prints active sources plus reviewed candidates NOT included, with reasons.
The disabled entries do NOT count as checked sources. This catalog is finite,
not a claim to include every current or future breach site. Review date: 2026-09-15.

    py breach_check_single.py --providers leakcheck --yes
Select a subset. The default is both supported public providers. No front-end
scraping, leaked shared keys, CAPTCHAs, sign-ins, email-verification messages,
raw-credential API queries, or automatic incident-dump harvesting is implemented.

AUTOMATIC ORIGINAL-REFERENCE FOLLOW-UP
On an XposedOrNot match, the tool retrieves its public metadata catalog. It uses
exact breach IDs, not fuzzy names, to add dates, domains, exposed-data categories,
and reference links. It visits at most 10 qualifying HTML/plain-text references
on the incident publisher's domain or known regulator hosts. It obeys robots.txt,
limits redirects to the reference's hostname/www variant, and does not put the
email into these requests. Query-bearing or email-bearing reference URLs, PDFs,
archives, third-party news hosts, and dataset files are not automatically fetched.
A publisher-host match is a routing heuristic, not source authentication. The
result is CONTEXT_PAGE_RETRIEVED, never 'verified affected account'. Merely
finding an email in a notice could identify a contact, not a victim.

    py breach_check_single.py --no-references --yes
    py breach_check_single.py --max-reference-pages 5 --yes
--no-references still allows public metadata enrichment; it disables visiting
linked pages. A notice site is not counted as an account lookup service.

OPTIONAL AUTHORIZED DIRECT DATA (NOT NEEDED FOR DEFAULT OPERATION)
    py breach_check_single.py --no-builtins --file affected.csv --output local.json
    py breach_check_single.py --no-builtins --file records.jsonl --email-field email
    py breach_check_single.py --no-builtins --sources sources.json
    py breach_check_single.py --no-builtins --url https://example.com/notice
--file may be repeated. CSV/JSONL inspect only --email-field (default email).
TXT means exactly one email per line, not email:password pairs. Static HTML
matches are public mentions, not proof of a breach. No JavaScript is executed.
--no-builtins disables provider queries; an explicit HTTPS --url or manifest
source still uses the network. Local files alone require no network approval.
The version-1 sources.json manifest format is still accepted, with optional
reviewed/provenance/review_note/expected_sha256 fields. Reviewed=true requires
a breach_name, provenance, review_note and SHA-256 pin; it is your assertion,
not independent authentication by the program. No manifest is created or needed
for the default provider check.

PRIVACY
Use your own email or an address you are authorized to assess. XposedOrNot sees
the full address and both providers can see your IP address. LeakCheck's short
hash is a deterministic identifier, not k-anonymity; it can be linked or tested
against candidate addresses. Provider policies govern their handling of queries.
The program does not log raw query URLs, matching rows, response bodies,
passwords, tokens, or contact details. JSON output masks the target by default;
--include-email intentionally includes it. Reports still contain sensitive
exposure metadata: store them securely. This is not a secure memory-erasure tool.
Reference-page requests do not contain the target email or a Referer header.

INTERPRETATION
MATCH_REPORTED: provider reports exposure; not independently verified.
NO_MATCH_REPORTED: no match returned by that provider, not 'never breached'.
ERROR / INCOMPLETE: query or parsing failed; never counted as a clean negative.
MATCH_OPERATOR_REVIEWED_DATASET: local/direct match in a dataset you reviewed.
MATCH_UNVERIFIED_DATASET: a direct dataset contains the email; origin unverified.
PUBLIC_MENTION: an HTML page mentions the email; not proof of breach inclusion.
SYNTHETIC_MATCH: a demonstration only, excluded from real-world conclusions.
LeakCheck's found value counts matching records, not necessarily distinct
incidents. Its exposed field categories apply across the returned results and
are not assigned to each incident. Each provider remains separately attributed.
A breach date is provider-supplied metadata and may be approximate. Privacy
shielding, deletion requests, withheld incidents, indexing delays, and differing
corpora can all limit public results. Nothing establishes universal coverage.

FAILURE HANDLING
TLS validation, public-address checks, per-origin pacing, bounded retries,
Retry-After handling, byte caps, JSON validation, per-source exception isolation,
atomic report replacement, and explicit coverage status are implemented.
A 429 with no short Retry-After is reported without repeatedly hammering the API.
No proxies or netrc credentials are inherited from the environment. Consequently,
a network that requires an enterprise proxy may need a reviewed code adaptation;
TLS verification must not be disabled. DNS checks are not DNS-pinned SSRF defense.
Do not deploy this script as an unauthenticated public web service.
Socket timeouts and the best-effort source budget are not hard wall-clock
process deadlines: operating-system DNS and some blocking I/O can take longer.

    py breach_check_single.py --timeout 20 --source-seconds 75 --attempts 2 --yes
Response/input cap is --max-mb (default 32 MiB), with lower caps for API and
reference responses. Large original corpora need a separately managed index.

TESTING
    py breach_check_single.py --self-test
    py breach_check_single.py --demo --output demo_report.json
Both are offline. Demo uses only fictional example-domain data and is explicitly
labeled synthetic. Tests cover parsers, privacy, HTTP failures, limits, retries,
reference routing, local scans, and reporting. Passing offline tests does not
prove that a live service is reachable or its current data is accurate.

EXIT CODES
0: Requested account/direct checks completed (positive matches also return 0).
1: At least one requested account/direct check was incomplete or failed.
2: Invalid input/configuration, report-writing failure, or top-level failure.
130: Cancelled. Optional metadata/reference failures are reported separately
     and do not overturn a completed account lookup or erase a match.

PRIMARY DOCUMENTATION
XposedOrNot API: https://xposedornot.com/api_doc
XposedOrNot methodology: https://xposedornot.com/methodology
LeakCheck Public: https://docs.leakcheck.io/public-api/lookup
LeakCheck privacy: https://leakcheck.io/privacy
Powered by LeakCheck. A website embedding its API results must provide the
provider attribution link required by its documented terms.
"""


def summarize_run(providers: list[ProviderResult], direct: list[Outcome],
                  *, synthetic: bool = False) -> dict[str, Any]:
    positives = sum(r.match_reported and not r.synthetic for r in providers)
    failed = sum(r.coverage != "complete_for_provider_response" for r in providers)
    direct_failed = sum(r.coverage != "complete_for_checked_content" for r in direct)
    reviewed = sum(r.status == "MATCH_OPERATOR_REVIEWED_DATASET" for r in direct)
    unverified = sum(r.status == "MATCH_UNVERIFIED_DATASET" for r in direct)
    mentions = sum(r.status == "PUBLIC_MENTION" for r in direct)
    if synthetic:
        conclusion = "DEMONSTRATION_ONLY_NO_REAL_LOOKUP_PERFORMED"
    elif reviewed:
        conclusion = "MATCH_IN_OPERATOR_REVIEWED_DATASET"
    elif positives:
        conclusion = "EXPOSURE_REPORTED_BY_PUBLIC_INDEX"
    elif unverified:
        conclusion = "UNVERIFIED_DATASET_MATCH_REQUIRES_REVIEW"
    elif mentions:
        conclusion = "PUBLIC_MENTION_ONLY_NOT_BREACH_CONFIRMATION"
    elif failed or direct_failed:
        conclusion = "NO_DETERMINATION_INCOMPLETE_COVERAGE"
    else:
        conclusion = "NO_MATCH_IN_CHECKED_SOURCES"
    return {
        "conclusion": conclusion,
        "providers_attempted": len(providers),
        "providers_with_reported_matches": positives,
        "provider_queries_incomplete_or_failed": failed,
        "direct_sources_attempted": len(direct),
        "direct_sources_incomplete_or_failed": direct_failed,
        "reviewed_dataset_matches": reviewed,
        "unverified_dataset_matches": unverified,
        "public_mentions": mentions,
        "run_incomplete": bool(failed or direct_failed),
        "warning": "No match does not mean never breached. Public index results are provider assertions, "
                   "not independent source authentication. Reference pages are context, not account-membership evidence."
    }


def build_report(target: str, providers: list[ProviderResult], direct: list[Outcome],
                 metadata: dict[str, Any], references: list[dict[str, Any]],
                 *, include_email: bool = False, fold_local: bool = False,
                 synthetic: bool = False) -> dict[str, Any]:
    provider_rows = []
    for result in providers:
        row = asdict(result)
        for finding in row["findings"]:
            finding["reference_urls"] = [safe_reference(url) for url in finding["reference_urls"]]
        provider_rows.append(row)
    report: dict[str, Any] = {
        "tool": BOT, "version": VERSION, "generated_at": utc_now(),
        "catalog_documentation_reviewed": CATALOG_REVIEWED,
        "synthetic": synthetic, "target_masked": mask_email(target),
        "summary": summarize_run(providers, direct, synthetic=synthetic),
        "matching_policy": {
            "direct_domain_case_insensitive": True,
            "direct_local_part_case_insensitive": fold_local,
            "plus_tags_preserved": True, "dots_preserved": True,
            "provider_matching": "Provider-defined; LeakCheck query hashes the lowercase email.",
        },
        "providers": provider_rows, "direct_sources": [asdict(r) for r in direct],
        "incident_metadata": metadata, "reference_pages": references,
        "reference_pages_are_membership_evidence": False,
        "attribution": [{"name": "Powered by " + r.label,
                         "homepage": PROVIDERS[r.provider_id].homepage} for r in providers],
        "coverage_note": "Only selected supported providers and supplied direct sources were queried. "
                         "Candidates printed by --list-sites as not automated were NOT checked."
    }
    if include_email:
        report["target_email"] = target
    return report


def print_report(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print(f"\nBreach Check {VERSION} | {report['target_masked']}")
    print("Conclusion: " + summary["conclusion"])
    if report["synthetic"]:
        print("SYNTHETIC DEMONSTRATION: no real email lookup or network access was performed.")
    print(f"Account providers attempted: {summary['providers_attempted']}; "
          f"incomplete/failed: {summary['provider_queries_incomplete_or_failed']}")
    for result in report["providers"]:
        print(f"\n{result['label']}: {result['status']}")
        if result["reported_record_count"] is not None:
            print(f"  Provider-reported matching records: {result['reported_record_count']}")
        for finding in result["findings"][:50]:
            date = f" | date: {finding['date']}" if finding["date"] else ""
            print(f"  {finding['name']}{date}")
            if finding["data_classes"]:
                print("    Data categories: " + ", ".join(finding["data_classes"]))
        if len(result["findings"]) > 50:
            print("  Additional findings are available in the JSON report (--output).")
        if result["data_classes_across_results"]:
            print("  Categories across these results (not per incident): " +
                  ", ".join(result["data_classes_across_results"]))
        if result["error_code"]:
            print(f"  {result['error_code']}: {result['error']}")
    for source in report["direct_sources"]:
        print(f"\nDirect source {source['source_id']}: {source['status']} | "
              f"matching records={source['matching_records']} | {source['coverage']}")
        if source["error_code"]:
            print(f"  {source['error_code']}: {source['error']}")
    metadata = report["incident_metadata"]
    if metadata.get("status") in {"error", "partial"}:
        print("\nIncident metadata enrichment was incomplete; account findings above were retained.")
        if metadata.get("error_code"):
            print("  " + metadata["error_code"] + ": " + metadata.get("error", ""))
    refs = report["reference_pages"]
    if refs:
        retrieved = sum(r["status"] == "CONTEXT_PAGE_RETRIEVED" for r in refs)
        print(f"\nReference pages: {retrieved} retrieved; {len(refs) - retrieved} skipped/unavailable.")
        print("  These are context pages, not independently verified affected-email lists.")
        for ref in refs[:10]:
            print(f"  {ref['status']}: {ref['url']}")
            if ref.get("reason"):
                print("    " + ref["reason"])
    print("\n" + summary["warning"])
    if any(r["provider_id"] == "leakcheck" for r in report["providers"]):
        print("Powered by LeakCheck (https://leakcheck.io/).")


def show_sites() -> None:
    print(f"Built-in catalog | documentation reviewed {CATALOG_REVIEWED}\n")
    for spec in PROVIDERS.values():
        print(f"AUTOMATIC: {spec.label} [{spec.id}]")
        print("  " + spec.documentation)
        print("  " + spec.notes)
        print("  Disclosure: " + spec.disclosure + "\n")
    print("REVIEWED CANDIDATES NOT AUTOMATED (not included in check counts):\n")
    for item in NOT_AUTOMATED:
        print(item["site"] + ": " + item["reason"])
        print("  " + item["reference"])
    print("\nOriginal-reference pages, when available, are context only, not additional account providers.")


def arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Single-file no-login email exposure checker; default: XposedOrNot and LeakCheck Public.",
        epilog="No HIBP calls. Public index results are assertions, not independent verification. See --manual.")
    parser.add_argument("--email", help="Email to check. Omit for a non-echoing interactive prompt.")
    parser.add_argument("--yes", action="store_true", help="Acknowledge authorized use and the documented network disclosure.")
    parser.add_argument("--providers", nargs="+", choices=list(PROVIDERS), help="Select providers; default is all supported providers.")
    parser.add_argument("--no-builtins", action="store_true", help="Disable built-in APIs; check only explicit files/URLs/manifest.")
    parser.add_argument("--no-references", action="store_true", help="Do not retrieve incident reference pages.")
    parser.add_argument("--max-reference-pages", type=int, default=10, choices=range(0, 26), metavar="0-25")
    parser.add_argument("--list-sites", "--list-sources", action="store_true", help="Show the built-in catalog and exclusions, then exit.")
    parser.add_argument("--file", type=Path, action="append", default=[], help="Optional authorized local CSV/JSONL/TXT/HTML; repeatable.")
    parser.add_argument("--email-field", default="email", help="Email column/key for --file CSV/JSONL inputs.")
    parser.add_argument("--sources", type=Path, help="Optional version-1 source manifest; not required for default operation.")
    parser.add_argument("--url", action="append", default=[], help="Optional explicit public HTTPS static page; repeatable.")
    parser.add_argument("--case-insensitive-local", action="store_true", help="Fold local-part case in direct-source comparisons.")
    parser.add_argument("--timeout", type=positive_number, default=15.0, help="Socket timeout in seconds; default 15.")
    parser.add_argument("--source-seconds", type=positive_number, default=60.0, help="Best-effort per-fetch budget, not a hard deadline.")
    parser.add_argument("--attempts", type=int, default=3, choices=range(1, 5), metavar="1-4")
    parser.add_argument("--max-mb", type=positive_number, default=32.0, help="Input/response cap in MiB; default 32, maximum 256.")
    parser.add_argument("--output", type=Path, help="Write a sanitized JSON report, atomically replacing an existing report.")
    parser.add_argument("--include-email", action="store_true", help="Intentionally include the full email in the JSON report.")
    parser.add_argument("--self-test", action="store_true", help="Run embedded offline tests; no network calls.")
    parser.add_argument("--demo", action="store_true", help="Run an embedded synthetic offline demonstration.")
    parser.add_argument("--manual", action="store_true", help="Print detailed built-in instructions.")
    parser.add_argument("--version", action="version", version=VERSION)
    return parser.parse_args(argv)


def explicit_sources(args: argparse.Namespace) -> list[Source]:
    sources = load_sources(args.sources) if args.sources else []
    if len(args.file) + len(args.url) + len(sources) > 200:
        raise ConfigurationError("At most 200 explicit sources are supported.", "input_limit")
    formats = {".csv": "csv", ".jsonl": "jsonl", ".txt": "txt", ".html": "html", ".htm": "html"}
    if not args.email_field.strip() or len(args.email_field) > 200:
        raise ConfigurationError("Invalid --email-field value.", "invalid_option")
    for index, path in enumerate(args.file, 1):
        fmt = formats.get(path.suffix.lower())
        if fmt is None:
            raise ConfigurationError("--file supports CSV, JSONL, TXT, HTML, and HTM only.", "file_format")
        sources.append(Source(f"file-{index}", path.name, str(path.resolve()), fmt,
                              kind="web_page" if fmt == "html" else "breach_dataset",
                              email_field=args.email_field))
    for index, url in enumerate(args.url, 1):
        sources.append(Source(f"url-{index}", f"Explicit page {index}", validate_url(url, resolve=False),
                              "html", kind="web_page"))
    ids = [source.id for source in sources]
    if len(ids) != len(set(ids)):
        raise ConfigurationError("Manifest IDs conflict with generated file-N/url-N IDs.", "duplicate_id")
    return sources


def protect_output(path: Path | None, sources: list[Source], manifest: Path | None) -> None:
    if path is None:
        return
    protected = {Path(__file__).resolve()}
    protected.update(Path(s.location).resolve() for s in sources if not s.location.startswith("https://"))
    if manifest:
        protected.add(manifest.resolve())
    if path.resolve() in protected:
        raise ConfigurationError("Report output would replace the script or an input file.", "output_collision")


def save_requested_report(path: Path | None, report: dict[str, Any]) -> None:
    if path is not None:
        try:
            write_report(path, report)
        except (OSError, ValueError) as exc:
            raise CheckError("Could not write the JSON report; console results remain available.", "report_write_error") from exc
        print("Report: " + safe_reference(str(path)))


def demonstration(include_email: bool = False) -> dict[str, Any]:
    """Fully offline fixtures; never query a provider for a demonstration address."""
    class DemoClient:
        settings = Settings()

        def fetch(self, url: str, **kwargs: Any) -> Download:
            if "/check-email/" in url:
                data = {"status": "success", "email": "student@example.com",
                        "breaches": [["Fictional Forum", "Fictional Training Site"]]}
            elif "leakcheck.io/api/public" in url:
                data = {"success": True, "found": 3, "fields": ["email", "username"],
                        "sources": [{"name": "Fictional Forum", "date": "2024-06"}]}
            elif url.endswith("/v1/breaches"):
                data = {"exposedBreaches": [
                    {"breachID": "Fictional Forum", "breachedDate": "2024-06-01", "domain": "example.com",
                     "exposedData": ["Email addresses", "Usernames"], "verified": False,
                     "referenceURL": "https://example.com/synthetic-security-notice.html"}]}
            elif url == "https://example.com/synthetic-security-notice.html":
                return Download(b"<html><title>Synthetic incident notice</title><p>Fictional training example.</p></html>",
                                url, "text/html")
            else:
                raise FetchError("No synthetic fixture for this URL.", "demo_fixture_missing")
            return Download(json.dumps(data).encode(), url, "application/json")

    target = "student@example.com"
    client = DemoClient()
    providers = [check_provider(spec, target, client) for spec in PROVIDERS.values()]  # type: ignore[arg-type]
    for result in providers:
        result.synthetic = True
        _complete_provider(result)
    metadata = enrich_xposedornot(providers[0], client)  # type: ignore[arg-type]
    references = check_references(providers, target, client, 10)  # type: ignore[arg-type]
    for row in references:
        row["synthetic"] = True
    source = Source("demo-local", "Synthetic local CSV", "[in-memory demo]", "csv", synthetic=True)
    local = Outcome(source.id, source.label, source.kind, source.location, synthetic=True)
    scan_content(source, b"email,example_field\nstudent@example.com,training\nother@example.com,training\n",
                 target, local, False)
    finish_status(source, local)
    return build_report(target, providers, [local], metadata, references,
                        include_email=include_email, synthetic=True)


def main(argv: list[str] | None = None) -> int:
    args = arguments(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    if args.list_sites:
        show_sites()
        return 0
    if args.manual:
        print(MANUAL)
        return 0
    if args.self_test:
        return run_self_tests()
    protect_output(args.output, [], None)
    if args.demo:
        if args.email or args.file or args.url or args.sources or args.providers:
            raise ConfigurationError("--demo uses fictional embedded data; do not combine it with real inputs.", "demo_input")
        report = demonstration(args.include_email)
        print_report(report)
        save_requested_report(args.output, report)
        return 0
    if args.max_mb > 256 or args.timeout > 300 or args.source_seconds > 900:
        raise ConfigurationError("Limits: --max-mb <= 256, --timeout <= 300, --source-seconds <= 900.", "input_limit")
    if args.no_builtins and args.providers:
        raise ConfigurationError("Do not combine --no-builtins with --providers.", "invalid_option")
    chosen = [] if args.no_builtins else list(dict.fromkeys(args.providers or PROVIDERS))
    sources = explicit_sources(args)
    if not chosen and not sources:
        raise ConfigurationError("No sources selected. Omit --no-builtins or supply an optional file/URL.", "no_sources")
    protect_output(args.output, sources, args.sources)
    if args.email is None:
        if not sys.stdin.isatty():
            raise ConfigurationError("No interactive terminal. Supply --email (visible in process/shell history).", "email_required")
        raw_email = getpass.getpass("Email address to check: ")
    else:
        raw_email = args.email
    target = normalize_email(raw_email, args.case_insensitive_local)
    uses_network = bool(chosen or any(s.location.startswith("https://") for s in sources))
    if uses_network:
        print("Network disclosure:")
        for name in chosen:
            print("  " + PROVIDERS[name].label + ": " + PROVIDERS[name].disclosure)
        if sources:
            print("  Explicit HTTPS sources, if any, are fetched directly; the email is matched locally.")
        if not args.no_references and "xposedornot" in chosen:
            print("  Qualifying publisher/regulator reference pages may also be visited without sending the email.")
        if not args.yes:
            if not sys.stdin.isatty():
                raise ConfigurationError("Network disclosure acknowledgment required. Review --manual, then use --yes.", "disclosure_required")
            answer = input("Own/authorized address, and proceed with these disclosures? [y/N] ").strip().lower()
            if answer not in {"y", "yes"}:
                print("Cancelled before any network requests.")
                return 130
    settings = Settings(max_bytes=max(1, int(args.max_mb * 1024 * 1024)), timeout=args.timeout,
                        source_seconds=args.source_seconds, attempts=args.attempts)
    client = HttpClient(settings)
    providers: list[ProviderResult] = []
    direct: list[Outcome] = []
    metadata: dict[str, Any] = {"status": "not_requested"}
    references: list[dict[str, Any]] = []
    try:
        for name in chosen:
            print("Checking " + PROVIDERS[name].label + "...", flush=True)
            providers.append(check_provider(PROVIDERS[name], target, client))
        for source in sources:
            print("Checking direct source " + source.id + "...", flush=True)
            direct.append(check_source(source, target, client, args.case_insensitive_local))
        xon = next((r for r in providers if r.provider_id == "xposedornot"), None)
        if xon is not None:
            if xon.match_reported:
                print("Retrieving public incident metadata...", flush=True)
            metadata = enrich_xposedornot(xon, client)
            if not args.no_references and args.max_reference_pages:
                references = check_references([xon], target, client, args.max_reference_pages)
    finally:
        client.close()
    report = build_report(target, providers, direct, metadata, references,
                          include_email=args.include_email, fold_local=args.case_insensitive_local)
    print_report(report)
    save_requested_report(args.output, report)
    return 1 if report["summary"]["run_incomplete"] else 0


def entrypoint() -> int:
    try:
        return main()
    except (ConfigurationError, CheckError) as exc:
        print(f"ERROR [{exc.code}]: {exc}", file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled; no complete report was produced.", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 1
    except MemoryError:
        print("ERROR: Insufficient memory. Reduce --max-mb or split the local dataset.", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"ERROR: Unexpected {type(exc).__name__}; do not infer a clean result.", file=sys.stderr)
        return 2


# ---------------------------------------------------------------------------
# Embedded offline regression tests. Imports are lazy; normal runs do not need
# any external testing package or fixture files. No test contacts the Internet.
# ---------------------------------------------------------------------------

def run_self_tests() -> int:
    import unittest
    from contextlib import redirect_stdout
    from unittest.mock import Mock, patch

    module = sys.modules[__name__]
    target = "student@example.com"

    def json_doc(value: Any, status: int = 200) -> Download:
        return Download(json.dumps(value).encode(), "https://example.com/", "application/json", status)

    class StubClient:
        settings = Settings()

        def __init__(self, response: Download | Exception) -> None:
            self.response = response
            self.calls: list[tuple[str, dict[str, Any]]] = []

        def fetch(self, url: str, **kwargs: Any) -> Download:
            self.calls.append((url, kwargs))
            if isinstance(self.response, Exception):
                raise self.response
            return self.response

    def provider_result(name: str, value: Any, status: int = 200) -> ProviderResult:
        return check_provider(PROVIDERS[name], target, StubClient(json_doc(value, status)))  # type: ignore[arg-type]

    class FakeResponse:
        def __init__(self, body: bytes = b"{}", code: int = 200,
                     headers: dict[str, str] | None = None) -> None:
            self.code = code
            self.headers = headers if headers is not None else {"Content-Type": "application/json"}
            self.buffer = io.BytesIO(body)
            self.closed = False

        def read(self, n: int = -1) -> bytes:
            return self.buffer.read(n)

        read1 = read

        def close(self) -> None:
            self.closed = True

    class InputAndPrivacyTests(unittest.TestCase):
        def test_domain_case(self) -> None:
            self.assertEqual(normalize_email("Student@EXAMPLE.COM"), "Student@example.com")

        def test_local_case_preserved(self) -> None:
            self.assertNotEqual(normalize_email("Student@example.com"), normalize_email(target))

        def test_local_case_optional_fold(self) -> None:
            self.assertEqual(normalize_email("Student@EXAMPLE.COM", True), target)

        def test_plus_and_dots_preserved(self) -> None:
            self.assertEqual(normalize_email("s.tudent+tag@example.com"), "s.tudent+tag@example.com")

        def test_unsupported_mailboxes(self) -> None:
            for value in ("not-an-email", "a@@example.com", "a@localhost", "a..b@example.com",
                          '"quoted"@example.com', "a@example..com", "a\n@example.com", 5):
                with self.subTest(value=str(value)):
                    with self.assertRaises(ConfigurationError):
                        normalize_email(value)  # type: ignore[arg-type]

        def test_idna_domain(self) -> None:
            self.assertEqual(normalize_email("user@b\u00fccher.example"), "user@xn--bcher-kva.example")

        def test_masking(self) -> None:
            self.assertEqual(mask_email(target), "s***@example.com")

        def test_reference_redacts_query_email_controls(self) -> None:
            value = safe_reference("https://example.com/student%40example.com?token=SECRET#frag")
            self.assertNotIn(target, value)
            self.assertNotIn("SECRET", value)
            self.assertNotIn("\x1b", safe_reference("safe\x1b[31m"))
            self.assertNotIn("\u202e", safe_reference("safe\u202e"))

        def test_invalid_settings(self) -> None:
            for kwargs in ({"attempts": 0}, {"timeout": 0}, {"interval": -1},
                           {"max_bytes": True}, {"timeout": float("nan")}):
                with self.subTest(kwargs=kwargs):
                    with self.assertRaises(ConfigurationError):
                        Settings(**kwargs)

        def test_invalid_number(self) -> None:
            for value in ("nan", "inf", "0", "-1", "x"):
                with self.assertRaises(argparse.ArgumentTypeError):
                    positive_number(value)

        def test_hibp_hosts_blocked(self) -> None:
            for host in ("haveibeenpwned.com", "api.haveibeenpwned.com", "api.pwnedpasswords.com",
                         "haveibeenpwned.com."):
                with self.assertRaises(FetchError):
                    validate_url("https://" + host + "/", resolve=False)

        def test_url_scheme_port_userinfo(self) -> None:
            for url in ("http://example.com/", "file:///etc/passwd", "https://example.com:0/",
                        "https://example.com:444/", "https://name:secret@example.com/",
                        "https://example.com/a b", "https://localhost/", "https://host.onion/"):
                with self.subTest(url=url):
                    with self.assertRaises(FetchError):
                        validate_url(url, resolve=False)

        def test_private_literal_rejected_without_dns(self) -> None:
            for host in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "[::1]"):
                with self.assertRaises(FetchError):
                    validate_url("https://" + host + "/", resolve=False)

        def test_dns_private_answer_rejected(self) -> None:
            answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
            with patch.object(socket, "getaddrinfo", return_value=answer):
                with self.assertRaises(FetchError) as caught:
                    validate_url("https://example.com/")
            self.assertEqual(caught.exception.code, "url_policy")

        def test_dns_failure_explicit(self) -> None:
            with patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("private-detail")):
                with self.assertRaises(FetchError) as caught:
                    validate_url("https://example.com/")
            self.assertEqual(caught.exception.code, "dns_error")
            self.assertNotIn("private-detail", str(caught.exception))

        def test_provider_default_no_configuration(self) -> None:
            args = arguments([])
            self.assertIsNone(args.sources)
            self.assertFalse(args.no_builtins)
            self.assertEqual(set(PROVIDERS), {"xposedornot", "leakcheck"})

        def test_leakcheck_hash_request(self) -> None:
            url, statuses = provider_request(PROVIDERS["leakcheck"], "Student@EXAMPLE.COM")
            digest = hashlib.sha256(target.encode()).hexdigest()[:24]
            self.assertEqual(url, "https://leakcheck.io/api/public?check=" + digest)
            self.assertNotIn(target, url)
            self.assertEqual(statuses, {200})

        def test_xon_path_escaping(self) -> None:
            value = "a+b/c?d#e@example.com"
            url, _ = provider_request(PROVIDERS["xposedornot"], value)
            self.assertIn("%2F", url)
            self.assertIn("%3F", url)
            self.assertIn("%23", url)
            self.assertEqual(urlsplit(url).query, "")

    class ProviderParserTests(unittest.TestCase):
        def test_xon_match(self) -> None:
            result = provider_result("xposedornot", {"breaches": [["Example A", "Example B"]],
                                                        "email": target, "status": "success"})
            self.assertEqual(result.status, "MATCH_REPORTED")
            self.assertEqual(len(result.findings), 2)
            self.assertIsNone(result.reported_record_count)

        def test_xon_flat_names(self) -> None:
            result = provider_result("xposedornot", {"breaches": ["Example A"], "status": "success"})
            self.assertEqual(result.status, "MATCH_REPORTED")

        def test_xon_deduplicate_exact_names(self) -> None:
            result = provider_result("xposedornot", {"breaches": [["Example A", "Example A"]]})
            self.assertEqual(len(result.findings), 1)

        def test_xon_structured_404(self) -> None:
            result = provider_result("xposedornot", {"Error": "Not found", "email": None}, 404)
            self.assertEqual(result.status, "NO_MATCH_REPORTED")

        def test_xon_structured_200_notfound(self) -> None:
            result = provider_result("xposedornot", {"Error": "Not found"})
            self.assertEqual(result.status, "NO_MATCH_REPORTED")

        def test_generic_404_not_negative(self) -> None:
            result = provider_result("xposedornot", {"message": "route missing"}, 404)
            self.assertEqual(result.status, "ERROR")
            self.assertEqual(result.coverage, "not_checked")

        def test_xon_empty_success(self) -> None:
            result = provider_result("xposedornot", {"breaches": [], "status": "success"})
            self.assertEqual(result.status, "NO_MATCH_REPORTED")

        def test_xon_ambiguous_empty(self) -> None:
            result = provider_result("xposedornot", {"breaches": []})
            self.assertEqual(result.status, "INCOMPLETE")

        def test_xon_partial_retains_match(self) -> None:
            result = provider_result("xposedornot", {"breaches": [["Example A", {"unexpected": True}]]})
            self.assertEqual(result.status, "INCOMPLETE")
            self.assertTrue(result.match_reported)
            self.assertEqual(result.findings[0].name, "Example A")

        def test_xon_wrong_email_echo(self) -> None:
            result = provider_result("xposedornot", {"email": "someone@example.com", "breaches": [["Example A"]]})
            self.assertEqual(result.error_code, "query_mismatch")
            self.assertFalse(result.match_reported)

        def test_xon_contradiction(self) -> None:
            result = provider_result("xposedornot", {"Error": "Not found", "breaches": [["Example A"]]})
            self.assertEqual(result.status, "ERROR")

        def test_html_challenge_not_negative(self) -> None:
            client = StubClient(Download(b"<title>Just a moment</title>", "https://example.com/", "text/html", 404))
            result = check_provider(PROVIDERS["xposedornot"], target, client)  # type: ignore[arg-type]
            self.assertEqual(result.status, "ERROR")
            self.assertEqual(result.error_code, "non_json_response")

        def test_duplicate_json_keys(self) -> None:
            doc = Download(b'{"found":0,"found":1}', "https://example.com/", "application/json")
            with self.assertRaises(CheckError):
                decode_json(doc)

        def test_nonfinite_json(self) -> None:
            doc = Download(b'{"value":NaN}', "https://example.com/", "application/json")
            with self.assertRaises(CheckError):
                decode_json(doc)

        def test_json_not_object(self) -> None:
            with self.assertRaises(CheckError):
                decode_json(json_doc([]))

        def test_leakcheck_match(self) -> None:
            result = provider_result("leakcheck", {"success": True, "found": 3, "fields": ["username"],
                                                       "sources": [{"name": "Example A", "date": "2024-06"}]})
            self.assertEqual(result.status, "MATCH_REPORTED")
            self.assertEqual(result.reported_record_count, 3)
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.data_classes_across_results, ["username"])
            self.assertEqual(result.findings[0].data_classes, [])

        def test_leakcheck_zero(self) -> None:
            result = provider_result("leakcheck", {"success": True, "found": 0, "fields": [], "sources": []})
            self.assertEqual(result.status, "NO_MATCH_REPORTED")

        def test_leakcheck_missing_sources_not_negative(self) -> None:
            result = provider_result("leakcheck", {"success": True, "found": 0})
            self.assertEqual(result.status, "INCOMPLETE")

        def test_leakcheck_boolean_count_rejected(self) -> None:
            result = provider_result("leakcheck", {"success": True, "found": True, "sources": []})
            self.assertEqual(result.status, "ERROR")

        def test_leakcheck_string_count_rejected(self) -> None:
            result = provider_result("leakcheck", {"success": True, "found": "2", "sources": []})
            self.assertEqual(result.status, "ERROR")

        def test_leakcheck_failed_success(self) -> None:
            result = provider_result("leakcheck", {"success": False, "error": "SECRET"})
            self.assertEqual(result.status, "ERROR")
            self.assertNotIn("SECRET", result.error)

        def test_leakcheck_partial_positive_retained(self) -> None:
            result = provider_result("leakcheck", {"success": True, "found": 2, "sources": [
                {"name": "Example A", "date": "2024"}, {"invalid": "field"}]})
            self.assertTrue(result.match_reported)
            self.assertEqual(result.status, "INCOMPLETE")
            self.assertEqual(len(result.findings), 1)

        def test_leakcheck_count_positive_details_absent(self) -> None:
            result = provider_result("leakcheck", {"success": True, "found": 3})
            self.assertTrue(result.match_reported)
            self.assertEqual(result.status, "INCOMPLETE")

        def test_leakcheck_contradictory_zero(self) -> None:
            result = provider_result("leakcheck", {"success": True, "found": 0, "sources": [{"name": "A"}]})
            self.assertEqual(result.status, "ERROR")
            self.assertFalse(result.match_reported)

        def test_no_sensitive_extra_fields_exported(self) -> None:
            result = provider_result("leakcheck", {"success": True, "found": 1,
                "sources": [{"name": "Example A", "date": "2024", "password": "NEVER-EXPORT-ME"}],
                "passwords": ["NEVER-EXPORT-ME"]})
            self.assertNotIn("NEVER-EXPORT-ME", json.dumps(asdict(result)))

        def test_network_failure_not_negative(self) -> None:
            client = StubClient(FetchError("DNS resolution failed.", "dns_error"))
            result = check_provider(PROVIDERS["leakcheck"], target, client)  # type: ignore[arg-type]
            self.assertEqual(result.status, "ERROR")
            self.assertFalse(result.match_reported)

        def test_unexpected_exception_isolated(self) -> None:
            client = StubClient(RuntimeError("SECRET-URL"))
            result = check_provider(PROVIDERS["leakcheck"], target, client)  # type: ignore[arg-type]
            self.assertEqual(result.error_code, "unexpected_error")
            self.assertNotIn("SECRET-URL", result.error)

        def test_actual_api_request_options(self) -> None:
            client = StubClient(json_doc({"success": True, "found": 0, "sources": []}))
            check_provider(PROVIDERS["leakcheck"], target, client)  # type: ignore[arg-type]
            self.assertTrue(client.calls[0][1]["api"])
            self.assertFalse(client.calls[0][1]["obey_robots"])
            self.assertEqual(client.calls[0][1]["allowed_hosts"], {"leakcheck.io"})

    class ReferenceTests(unittest.TestCase):
        def test_publisher_reference(self) -> None:
            url, kind = qualify_reference("https://security.example.com/notice", "example.com", target)
            self.assertEqual(kind, "publisher_host_match_context")
            self.assertTrue(url.startswith("https://"))

        def test_regulator_reference(self) -> None:
            _, kind = qualify_reference("https://oag.ca.gov/privacy/notice", "example.com", target)
            self.assertEqual(kind, "regulator_host_context")

        def test_fake_domain_suffix_not_approved(self) -> None:
            with self.assertRaises(CheckError):
                qualify_reference("https://notexample.com/notice", "example.com", target)

        def test_hibp_reference_not_followed(self) -> None:
            with self.assertRaises(CheckError):
                qualify_reference("https://haveibeenpwned.com/", "haveibeenpwned.com", target)

        def test_reference_query_not_sent(self) -> None:
            with self.assertRaises(CheckError) as caught:
                qualify_reference("https://example.com/notice?email=" + target, "example.com", target)
            self.assertEqual(caught.exception.code, "reference_privacy")

        def test_double_encoded_email_not_sent(self) -> None:
            with self.assertRaises(CheckError):
                qualify_reference("https://example.com/student%2540example.com", "example.com", target)

        def test_reference_pdf_skipped(self) -> None:
            with self.assertRaises(CheckError) as caught:
                qualify_reference("https://example.com/notice.pdf", "example.com", target)
            self.assertEqual(caught.exception.code, "reference_format")

        def test_metadata_enrichment(self) -> None:
            result = provider_result("xposedornot", {"breaches": [["Example A"]]})
            client = StubClient(json_doc({"exposedBreaches": [{"breachID": "Example A", "domain": "example.com",
                "breachedDate": "2024-06-01", "exposedData": ["Emails"], "verified": True,
                "referenceURL": "https://example.com/notice"}]}))
            state = enrich_xposedornot(result, client)  # type: ignore[arg-type]
            self.assertEqual(state["matched_metadata_entries"], 1)
            self.assertTrue(result.findings[0].provider_verified)
            self.assertEqual(result.status, "MATCH_REPORTED")
            self.assertNotIn(target, client.calls[0][0])

        def test_metadata_not_fuzzy_matched(self) -> None:
            result = provider_result("xposedornot", {"breaches": [["Example A"]]})
            state = enrich_xposedornot(result, StubClient(json_doc({"exposedBreaches": [
                {"breachID": "Example-A", "domain": "example.com"}]})))  # type: ignore[arg-type]
            self.assertEqual(state["matched_metadata_entries"], 0)

        def test_metadata_failure_preserves_match(self) -> None:
            result = provider_result("xposedornot", {"breaches": [["Example A"]]})
            state = enrich_xposedornot(result, StubClient(FetchError("Timed out", "timeout")))  # type: ignore[arg-type]
            self.assertEqual(state["status"], "error")
            self.assertEqual(result.status, "MATCH_REPORTED")
            self.assertTrue(result.match_reported)

        def test_reference_is_context_even_with_email(self) -> None:
            result = provider_result("xposedornot", {"breaches": [["Example A"]]})
            result.findings[0].domain = "example.com"
            result.findings[0].reference_urls = ["https://example.com/notice"]
            client = StubClient(Download(b"<title>Notice</title><p>Contact: student@example.com</p>",
                                         "https://example.com/notice", "text/html"))
            rows = check_references([result], target, client, 10)  # type: ignore[arg-type]
            self.assertEqual(rows[0]["status"], "CONTEXT_PAGE_RETRIEVED")
            self.assertTrue(rows[0]["exact_email_mentioned"])
            self.assertFalse(rows[0]["email_membership_established"])

        def test_reference_limit(self) -> None:
            result = provider_result("xposedornot", {"breaches": [["Example A"]]})
            result.findings[0].domain = "example.com"
            result.findings[0].reference_urls = ["https://example.com/a", "https://example.com/b"]
            client = StubClient(Download(b"<p>Notice</p>", "https://example.com/a", "text/html"))
            rows = check_references([result], target, client, 1)  # type: ignore[arg-type]
            self.assertEqual(len(client.calls), 1)
            self.assertEqual(rows[1]["reason"], "reference_limit")

    class DirectAndReportTests(unittest.TestCase):
        def scan(self, fmt: str, body: bytes, **kwargs: Any) -> Outcome:
            source = Source("test", "Test", "test." + fmt, fmt,
                            kind="web_page" if fmt == "html" else "breach_dataset", **kwargs)
            outcome = Outcome(source.id, source.label, source.kind, source.location)
            scan_content(source, body, target, outcome, False)
            finish_status(source, outcome)
            return outcome

        def test_csv_exact_field_only(self) -> None:
            result = self.scan("csv", b"email,contact\nother@example.com,student@example.com\n")
            self.assertEqual(result.status, "NO_MATCH_IN_CHECKED_CONTENT")

        def test_csv_match(self) -> None:
            result = self.scan("csv", b"email\nstudent@example.com\n")
            self.assertEqual(result.status, "MATCH_UNVERIFIED_DATASET")

        def test_jsonl_partial(self) -> None:
            result = self.scan("jsonl", b'{"email":"student@example.com"}\n{bad}\n')
            self.assertEqual(result.matching_records, 1)
            self.assertEqual(result.coverage, "partial")

        def test_txt_no_credential_parser(self) -> None:
            result = self.scan("txt", b"student@example.com:SECRET\n")
            self.assertEqual(result.status, "INCOMPLETE")
            self.assertEqual(result.matching_records, 0)

        def test_html_not_breach(self) -> None:
            result = self.scan("html", b"<p>student@example.com</p>")
            self.assertEqual(result.status, "PUBLIC_MENTION")

        def test_html_scripts_ignored(self) -> None:
            result = self.scan("html", b'<p>Notice</p><script>"student@example.com"</script>')
            self.assertEqual(result.matching_records, 0)

        def test_no_substring_email_match(self) -> None:
            result = self.scan("html", b"<p>notstudent@example.com student@example.com.other</p>")
            self.assertEqual(result.matching_records, 0)

        def test_hash_mismatch_blocks_content(self) -> None:
            with self.assertRaises(CheckError) as caught:
                self.scan("txt", b"student@example.com\n", expected_sha256="0" * 64)
            self.assertEqual(caught.exception.code, "hash_mismatch")

        def test_missing_file_outcome(self) -> None:
            source = Source("missing", "Missing", "/not-a-real-breach-test-file-7f82c.txt", "txt")
            result = check_source(source, target, StubClient(json_doc({})))  # type: ignore[arg-type]
            self.assertEqual(result.status, "ERROR")

        def test_manifest_duplicate_keys_rejected(self) -> None:
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "sources.json"
                path.write_text('{"sources":[],"sources":[]}', encoding="utf-8")
                with self.assertRaises(ConfigurationError):
                    load_sources(path)

        def test_manifest_review_requires_pin(self) -> None:
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "sources.json"
                path.write_text(json.dumps({"sources": [{"id": "a", "label": "a", "location": "a.csv",
                    "format": "csv", "reviewed": True}]}), encoding="utf-8")
                with self.assertRaises(ConfigurationError):
                    load_sources(path)

        def test_local_main_no_network(self) -> None:
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "a.txt"
                path.write_text(target + "\n", encoding="utf-8")
                with patch.object(HttpClient, "fetch", side_effect=AssertionError("NETWORK")):
                    with redirect_stdout(io.StringIO()):
                        code = main(["--no-builtins", "--file", str(path), "--email", target])
                self.assertEqual(code, 0)

        def test_report_masks_email_and_no_sensitive_rows(self) -> None:
            result = provider_result("xposedornot", {"email": target, "breaches": [["Example A"]]})
            report = build_report(target, [result], [], {}, [])
            self.assertNotIn(target, json.dumps(report))
            self.assertEqual(report["target_masked"], "s***@example.com")

        def test_report_include_email_explicit(self) -> None:
            report = build_report(target, [], [], {}, [], include_email=True)
            self.assertEqual(report["target_email"], target)

        def test_report_reference_query_redaction(self) -> None:
            result = provider_result("xposedornot", {"breaches": [["Example A"]]})
            result.findings[0].reference_urls = ["https://example.com/notice?token=SECRET"]
            report = build_report(target, [result], [], {}, [])
            self.assertNotIn("SECRET", json.dumps(report))

        def test_summary_failure_not_negative(self) -> None:
            result = new_provider_result(PROVIDERS["xposedornot"])
            summary = summarize_run([result], [])
            self.assertEqual(summary["conclusion"], "NO_DETERMINATION_INCOMPLETE_COVERAGE")
            self.assertTrue(summary["run_incomplete"])

        def test_summary_positive_and_failure(self) -> None:
            positive = provider_result("xposedornot", {"breaches": [["Example A"]]})
            failed = new_provider_result(PROVIDERS["leakcheck"])
            summary = summarize_run([positive, failed], [])
            self.assertEqual(summary["conclusion"], "EXPOSURE_REPORTED_BY_PUBLIC_INDEX")
            self.assertTrue(summary["run_incomplete"])

        def test_summary_records_not_summed_as_incidents(self) -> None:
            result = provider_result("leakcheck", {"success": True, "found": 50,
                "sources": [{"name": "Example A", "date": "2024"}]})
            self.assertEqual(summarize_run([result], [])["providers_with_reported_matches"], 1)

        def test_atomic_write(self) -> None:
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "nested" / "report.json"
                write_report(path, {"check": 1})
                write_report(path, {"check": 2})
                self.assertEqual(json.loads(path.read_text())["check"], 2)
                self.assertEqual(len(list(path.parent.glob("*.tmp"))), 0)

        def test_output_cannot_replace_script(self) -> None:
            with self.assertRaises(ConfigurationError):
                protect_output(Path(__file__), [], None)

        def test_output_cannot_replace_input(self) -> None:
            source = Source("s", "s", "some-input.csv", "csv")
            with self.assertRaises(ConfigurationError):
                protect_output(Path("some-input.csv"), [source], None)

        def test_demo_is_offline_and_synthetic(self) -> None:
            with patch.object(HttpClient, "fetch", side_effect=AssertionError("NETWORK")):
                report = demonstration()
            self.assertTrue(report["synthetic"])
            self.assertEqual(report["summary"]["providers_with_reported_matches"], 0)
            self.assertEqual(report["summary"]["conclusion"], "DEMONSTRATION_ONLY_NO_REAL_LOOKUP_PERFORMED")
            self.assertTrue(all(p["status"] == "SYNTHETIC_MATCH" for p in report["providers"]))

        def test_demo_rejects_real_email(self) -> None:
            with self.assertRaises(ConfigurationError):
                main(["--demo", "--email", target])

    class HttpTests(unittest.TestCase):
        def setUp(self) -> None:
            self.client = HttpClient(Settings(interval=0, attempts=2, timeout=1))
            self.deadline = time.monotonic() + 60

        def tearDown(self) -> None:
            self.client.close()

        def request(self, response: FakeResponse, limit: int = 1000) -> tuple[int, dict[str, str], bytes]:
            with patch.object(self.client.opener, "open", return_value=response):
                return self.client._request_once("https://example.com/", limit, self.deadline, {200}, True)

        def test_response_closed(self) -> None:
            response = FakeResponse()
            _, _, body = self.request(response)
            self.assertEqual(body, b"{}")
            self.assertTrue(response.closed)

        def test_claimed_size_limit(self) -> None:
            response = FakeResponse(headers={"Content-Length": "1001"})
            with self.assertRaises(FetchError) as caught:
                self.request(response)
            self.assertEqual(caught.exception.code, "size_limit")
            self.assertTrue(response.closed)

        def test_streaming_size_limit(self) -> None:
            with self.assertRaises(FetchError) as caught:
                self.request(FakeResponse(b"12345"), 4)
            self.assertEqual(caught.exception.code, "size_limit")

        def test_truncated_content(self) -> None:
            with self.assertRaises(FetchError) as caught:
                self.request(FakeResponse(b"{}", headers={"Content-Length": "10"}))
            self.assertEqual(caught.exception.code, "truncated_response")

        def test_invalid_content_length(self) -> None:
            with self.assertRaises(FetchError) as caught:
                self.request(FakeResponse(headers={"Content-Length": "-1"}))
            self.assertEqual(caught.exception.code, "invalid_http_length")

        def test_unexpected_compression(self) -> None:
            with self.assertRaises(FetchError) as caught:
                self.request(FakeResponse(headers={"Content-Encoding": "gzip"}))
            self.assertEqual(caught.exception.code, "unsupported_encoding")

        def test_partial_http_is_error(self) -> None:
            with self.assertRaises(FetchError) as caught:
                self.request(FakeResponse(code=206))
            self.assertEqual(caught.exception.code, "http_206")

        def test_429_without_retry_after_stops(self) -> None:
            with self.assertRaises(FetchError) as caught:
                self.request(FakeResponse(code=429))
            self.assertEqual(caught.exception.code, "rate_limited")
            self.assertFalse(caught.exception.retryable)

        def test_429_long_retry_after_stops(self) -> None:
            with self.assertRaises(FetchError) as caught:
                self.request(FakeResponse(code=429, headers={"Retry-After": "3600"}))
            self.assertFalse(caught.exception.retryable)

        def test_429_short_retry_after(self) -> None:
            with self.assertRaises(FetchError) as caught:
                self.request(FakeResponse(code=429, headers={"Retry-After": "2"}))
            self.assertTrue(caught.exception.retryable)
            self.assertEqual(caught.exception.retry_after, 2)

        def test_timeout_sanitized(self) -> None:
            with patch.object(self.client.opener, "open", side_effect=TimeoutError("SECRET")):
                with self.assertRaises(FetchError) as caught:
                    self.client._request_once("https://example.com/", 1000, self.deadline, {200}, True)
            self.assertEqual(caught.exception.code, "timeout")
            self.assertNotIn("SECRET", str(caught.exception))

        def test_tls_error_not_retried(self) -> None:
            with patch.object(self.client.opener, "open", side_effect=URLError(ssl.SSLError("SECRET"))):
                with self.assertRaises(FetchError) as caught:
                    self.client._request_once("https://example.com/", 1000, self.deadline, {200}, True)
            self.assertEqual(caught.exception.code, "tls_error")
            self.assertFalse(caught.exception.retryable)

        def test_no_cookies_or_authorization_headers(self) -> None:
            with patch.object(self.client.opener, "open", return_value=FakeResponse()) as mocked:
                self.client._request_once("https://example.com/", 1000, self.deadline, {200}, True)
            headers = {k.lower(): v for k, v in mocked.call_args.args[0].header_items()}
            self.assertNotIn("authorization", headers)
            self.assertNotIn("cookie", headers)
            self.assertNotIn("referer", headers)
            self.assertEqual(headers["accept-encoding"], "identity")

        def test_api_redirect_blocked(self) -> None:
            with patch.object(module, "validate_url", side_effect=lambda url, **kwargs: url):
                with patch.object(self.client, "_request_once", return_value=(302, {"location": "https://elsewhere.example/"}, b"")) as mocked:
                    with self.assertRaises(FetchError) as caught:
                        self.client.fetch("https://example.com/", api=True, obey_robots=False)
            self.assertEqual(caught.exception.code, "api_redirect")
            self.assertEqual(mocked.call_count, 1)

        def test_reference_redirect_scope(self) -> None:
            with patch.object(module, "validate_url", side_effect=lambda url, **kwargs: url):
                with patch.object(self.client, "_request_once", return_value=(302, {"location": "https://elsewhere.example/"}, b"")) as mocked:
                    with self.assertRaises(FetchError) as caught:
                        self.client.fetch("https://example.com/", obey_robots=False, allowed_hosts={"example.com"})
            self.assertEqual(caught.exception.code, "redirect_scope")
            self.assertEqual(mocked.call_count, 1)

        def test_transient_retry_is_bounded(self) -> None:
            error = FetchError("Temporary", "http_503", retryable=True)
            with patch.object(module, "validate_url", side_effect=lambda url, **kwargs: url):
                with patch.object(self.client, "_pause"):
                    with patch.object(self.client, "_request_once", side_effect=[error, (200, {"content-type": "application/json"}, b"{}")]) as mocked:
                        doc = self.client.fetch("https://example.com/", api=True, obey_robots=False)
            self.assertEqual(doc.status, 200)
            self.assertEqual(mocked.call_count, 2)

        def test_retry_exhaustion(self) -> None:
            error = FetchError("Temporary", "http_503", retryable=True)
            with patch.object(module, "validate_url", side_effect=lambda url, **kwargs: url):
                with patch.object(self.client, "_pause"):
                    with patch.object(self.client, "_request_once", side_effect=error) as mocked:
                        with self.assertRaises(FetchError):
                            self.client.fetch("https://example.com/", api=True, obey_robots=False)
            self.assertEqual(mocked.call_count, 2)

        def test_robots_denial(self) -> None:
            parser = RobotFileParser()
            parser.parse(["User-agent: *", "Disallow: /"])
            self.client.robots["https://example.com"] = parser
            with self.assertRaises(FetchError) as caught:
                self.client._robots_allowed("https://example.com/notice", self.deadline)
            self.assertEqual(caught.exception.code, "robots_denied")

        def test_robots_missing_allowed(self) -> None:
            with patch.object(self.client, "fetch", side_effect=FetchError("Missing", "http_404")):
                self.client._robots_allowed("https://example.com/notice", self.deadline)
            self.assertIsNone(self.client.robots["https://example.com"])

        def test_robots_unavailable_not_silently_ignored(self) -> None:
            with patch.object(self.client, "fetch", side_effect=FetchError("Denied", "http_403")):
                with self.assertRaises(FetchError) as caught:
                    self.client._robots_allowed("https://example.com/notice", self.deadline)
            self.assertEqual(caught.exception.code, "robots_unavailable")

        def test_time_budget(self) -> None:
            with self.assertRaises(FetchError) as caught:
                self.client._pause(10, time.monotonic() + 1)
            self.assertEqual(caught.exception.code, "time_budget")

        def test_retry_after_bad_values(self) -> None:
            for value in (None, "nonsense", "nan", "inf"):
                self.assertIsNone(self.client._retry_after(value))
            self.assertEqual(self.client._retry_after("5"), 5.0)

    suite = unittest.TestSuite()
    for case in (InputAndPrivacyTests, ProviderParserTests, ReferenceTests,
                 DirectAndReportTests, HttpTests):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(case))
    print("Running embedded OFFLINE tests; no live service validation is implied.", flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(entrypoint())
