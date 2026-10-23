from __future__ import annotations

import json

from conftest import entry

from loghunt.hunt import hunt
from loghunt.report import terminal, to_blocklist, to_html, to_json

XSS = "<script>alert(1)</script>"


def hostile_result():
    lines = [
        entry("203.0.113.7", f"/{XSS}", agent=f'sqlmap {XSS} "><img src=x onerror=alert(2)>'),
        entry("203.0.113.7", "/.env", status=404, agent=f"sqlmap {XSS}"),
    ]
    return hunt(lines)


def test_html_escapes_everything_from_the_log():
    html = to_html(hostile_result(), ["access.log"])
    assert XSS not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    # One inline script of our own and nothing else.
    assert html.count("<script>") == 1


def test_html_loads_nothing_from_the_network(sample):
    html = to_html(sample, ["access.log.gz"])
    assert "default-src 'none'" in html
    assert "http://" not in html.split("<main>")[0]
    assert "https://" not in html.split("<main>")[0]


def test_json_is_valid_and_complete(sample):
    data = json.loads(to_json(sample))
    assert data["lines"] == sample.lines
    assert len(data["suspects"]) == len(sample.suspects)
    assert data["campaigns"][0]["total_requests"] == 152
    first = data["suspects"][0]
    assert {"ip", "score", "findings", "first_seen", "user_agent"} <= first.keys()


def test_blocklist_is_one_ip_per_line(sample):
    lines = to_blocklist(sample).splitlines()
    assert lines == [s.ip for s in sample.suspects]


def test_terminal_groups_campaign_members(sample):
    text = terminal(sample, top=50)
    assert "19 IPs (C1)" in text
    assert "198.18." not in text.split("Campaign C1")[0]


def test_terminal_without_suspects():
    assert "No suspicious IPs found." in terminal(hunt([entry("100.64.0.1")]))


def test_terminal_neutralises_control_characters():
    esc = "\x1b"
    line = (
        f'1.2.3.4{esc}[31m - - [20/Oct/2026:08:00:01 +0000] "GET /.env HTTP/1.1" 404 1 "-" '
        f'"sqlmap {esc}]0;pwned\x07"'
    )
    text = terminal(hunt([line]), color=False)
    assert esc not in text
    assert "\x07" not in text
    assert "1.2.3.4\\x1b[31m" in text


def test_period_shows_the_date_again_across_midnight():
    lines = [entry("100.64.0.1", second=0), entry("100.64.0.1", second=20 * 3600)]
    assert "(2026-10-20 01:00 → 21:00 UTC)" in terminal(hunt(lines))
    lines = [entry("100.64.0.1", second=0), entry("100.64.0.1", second=26 * 3600)]
    assert "2026-10-20 01:00 → 2026-10-21 03:00" in terminal(hunt(lines))


def test_timeline_accounts_for_every_request(sample):
    rows = sample.timeline()
    assert 0 < len(rows) <= 120
    assert sum(total for _, total, _ in rows) == sample.parsed
    assert sum(flagged for _, _, flagged in rows) == sample.flagged_requests


def test_blocklist_keeps_only_real_addresses():
    # With X-Forwarded-For logging, the client writes the IP column.
    lines = [
        entry(ip, "/", agent="sqlmap/1.8")
        for ip in ("203.0.113.5", "2001:db8::7", "1.2.3.4;include", "-", "evil.example")
    ]
    assert to_blocklist(hunt(lines)).splitlines() == ["2001:db8::7", "203.0.113.5"]


def test_html_caps_rows_but_says_so(monkeypatch):
    import loghunt.report as report

    monkeypatch.setattr(report, "HTML_ROW_CAP", 2)
    lines = [entry(f"203.0.113.{n}", "/", agent="sqlmap/1.8") for n in range(1, 6)]
    html = report.to_html(hunt(lines), ["x.log"])
    assert html.count('<tr><td><span class="score') == 2
    assert "3 more suspicious IPs are left out" in html
    assert 'id="shown">2<' in html
