"""What attack traffic looks like: probe paths, payloads, login endpoints and tool names."""

from __future__ import annotations

import re
from functools import lru_cache
from urllib.parse import unquote_plus

# Paths that a visitor to a normal site never asks for: leaked secrets, backups,
# admin panels of software the site may not even run, and router/IoT exploits.
# Matched against the lower-cased path without its query string.
PROBE_RE = re.compile(
    r"""
      /\.(?:env|git|svn|hg|aws|ssh|docker|vscode|idea|ds_store|htpasswd|htaccess)(?:[/.]|$)
    | /wp-(?:login\.php|config\.php|admin/setup-config\.php|content/plugins/)
    | /xmlrpc\.php$
    | /(?:phpmyadmin|pma|myadmin|adminer)(?:[/.]|$)
    | /cgi-bin/
    | /vendor/phpunit/
    | /eval-stdin\.php
    | /actuator(?:/|$)
    | /(?:boaform|hnap1|goform)(?:/|$)
    | /setup\.cgi
    | /server-status
    | /_ignition/
    | /telescope/
    | /(?:solr|jenkins|manager/html)(?:/|$)
    | /config\.(?:json|php|yml|yaml)$
    | /(?:backup|dump|db|database|site|www)\.(?:sql|zip|tar|tar\.gz|tgz|rar|7z)$
    | \.(?:bak|old|orig|swp|save)$
    """,
    re.VERBOSE,
)

# A POST here is a login attempt.
LOGIN_RE = re.compile(
    r"(?:^|/)(?:wp-login\.php|xmlrpc\.php|login|signin|sign-in|log-in|logon"
    r"|administrator/index\.php|auth/login|user/login|api/login)$"
)

# Payloads in the URL: path traversal, SQL injection, XSS, Log4Shell, command injection.
# Matched against the URL-decoded, lower-cased request target.
PAYLOAD_RE = re.compile(
    r"""
      \.\./
    | \bunion\b.{0,20}\bselect\b
    | \b(?:or|and)\b\s*['"]?\d+['"]?\s*=\s*['"]?\d+
    | \b(?:sleep|benchmark|pg_sleep)\s*\(
    | \binformation_schema\b
    | <script | javascript: | \bon(?:error|load)\s*=
    | \$\{jndi:
    | /etc/passwd | /proc/self/ | \bcmd\.exe\b | /bin/(?:ba)?sh\b
    | \b(?:wget|curl)\s+https?://
    """,
    re.VERBOSE,
)

# Offensive tools that name themselves in the User-Agent.
SCANNER_RE = re.compile(
    r"\b(sqlmap|nikto|nmap|masscan|zgrab|nuclei|wpscan|dirbuster|gobuster|ffuf|feroxbuster"
    r"|wfuzz|acunetix|netsparker|nessus|openvas|hydra|whatweb|jaeles|l9explore)\b",
    re.IGNORECASE,
)

# HTTP libraries: fine for scripts and health checks, unusual for a person.
SCRIPT_RE = re.compile(
    r"^(python-requests|python-urllib|python-httpx|aiohttp|go-http-client|curl|wget|libwww-perl"
    r"|java|okhttp|axios|node-fetch|undici|scrapy|httpclient|apache-httpclient)\b",
    re.IGNORECASE,
)


# Real traffic repeats the same few thousand paths, so the regex checks are cached.
@lru_cache(maxsize=65536)
def is_probe(path: str) -> bool:
    return PROBE_RE.search(path.lower()) is not None


def is_login(path: str) -> bool:
    return LOGIN_RE.search(path.lower()) is not None


@lru_cache(maxsize=65536)
def has_payload(target: str) -> bool:
    if "%" in target or "+" in target:
        # Decode twice: attackers double-encode (%252e%252e%252f) to slip past one decode.
        for _ in range(2):
            decoded = unquote_plus(target)
            if decoded == target:
                break
            target = decoded
    return PAYLOAD_RE.search(target.lower()) is not None


def scanner_name(agent: str) -> str | None:
    match = SCANNER_RE.search(agent)
    return match.group(1).lower() if match else None


def script_name(agent: str) -> str | None:
    match = SCRIPT_RE.match(agent)
    return match.group(1) if match else None
