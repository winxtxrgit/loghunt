from __future__ import annotations

import gzip

from loghunt.parser import parse_line, parse_time, read_lines


def test_combined_format():
    line = (
        '203.0.113.9 - alice [20/Oct/2026:08:00:01 +0700] "GET /search?q=a%20b HTTP/1.1" '
        '200 512 "https://example.com/" "curl/8.5.0"'
    )
    request = parse_line(line)
    assert request is not None
    assert request.ip == "203.0.113.9"
    assert request.method == "GET"
    assert request.path == "/search"
    assert request.target == "/search?q=a%20b"
    assert request.status == 200
    assert request.agent == "curl/8.5.0"
    assert request.time == 1792458001  # 2026-10-20 01:00:01 UTC


def test_common_format_has_no_agent():
    request = parse_line('192.0.2.1 - - [20/Oct/2026:08:00:01 +0000] "GET / HTTP/1.0" 304 -')
    assert request is not None
    assert request.agent is None
    assert request.status == 304


def test_ipv6_and_escaped_quotes():
    line = (
        '2001:db8::1 - - [20/Oct/2026:08:00:01 +0000] "GET /a HTTP/2.0" 200 1 "-" '
        '"agent with \\"quotes\\" inside"'
    )
    request = parse_line(line)
    assert request is not None
    assert request.ip == "2001:db8::1"
    assert request.agent == 'agent with \\"quotes\\" inside'


def test_non_http_request_line_is_kept_as_malformed():
    line = '192.0.2.5 - - [20/Oct/2026:08:00:01 +0000] "\\x16\\x03\\x01\\x02" 400 157 "-" "-"'
    request = parse_line(line)
    assert request is not None
    assert request.method == "-"
    assert request.path == ""


def test_garbage_lines_are_rejected():
    assert parse_line("") is None
    assert parse_line("not a log line") is None
    assert parse_line('1.2.3.4 - - [99/Foo/2026:08:00:01 +0000] "GET / HTTP/1.1" 200 1') is None


def test_time_zones():
    assert parse_time("20/Oct/2026:08:00:00 +0700") == parse_time("20/Oct/2026:01:00:00 +0000")
    assert parse_time("19/Oct/2026:20:00:00 -0500") == parse_time("20/Oct/2026:01:00:00 +0000")


def test_read_lines_detects_gzip_by_content(tmp_path):
    plain = tmp_path / "access.log"
    plain.write_text("one\ntwo\n")
    packed = tmp_path / "rotated.1"  # logrotate names do not always end in .gz
    with gzip.open(packed, "wt") as handle:
        handle.write("three\n")
    assert [line.strip() for line in read_lines([str(plain), str(packed)])] == [
        "one",
        "two",
        "three",
    ]
