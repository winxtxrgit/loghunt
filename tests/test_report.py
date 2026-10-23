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
