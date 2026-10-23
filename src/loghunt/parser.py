"""Read nginx/apache access logs in the combined and common formats."""

from __future__ import annotations

import calendar
import gzip
import io
import re
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from functools import lru_cache

# 203.0.113.9 - - [20/Oct/2026:08:00:01 +0700] "GET /a?b=1 HTTP/1.1" 200 512 "-" "curl/8.5.0"
# Quotes inside a field arrive escaped (\" from apache, \x22 from nginx). The field
# pattern is the "unrolled loop" form, which is several times faster than (?:[^"\\]|\\.)*.
_FIELD = r'[^"\\]*(?:\\.[^"\\]*)*'
LINE_RE = re.compile(
    rf'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>{_FIELD})" '
    rf'(?P<status>\d{{3}}) \S+(?: "{_FIELD}" "(?P<agent>{_FIELD})")?'
)

_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}


@dataclass(frozen=True, slots=True)
class Request:
    ip: str
    time: int  # Unix seconds
    method: str  # "-" when the request line is not HTTP (TLS bytes, garbage)
    path: str  # without the query string
    target: str  # as sent, query string included
    status: int
    agent: str | None  # None in the common format, which has no User-Agent


@lru_cache(maxsize=8192)
def _minute(stamp: str, zone: str) -> int:
    day, month, rest = stamp.split("/")
    year, hour, minute = rest.split(":")
    offset = int(zone[1:3]) * 3600 + int(zone[3:5]) * 60
    if zone[0] == "-":
        offset = -offset
    moment = (int(year), _MONTHS[month], int(day), int(hour), int(minute), 0)
    # A corrupt line dated 1970 or 9999 would stretch the timeline over decades.
    if not (
        1990 <= moment[0] <= 2100 and 1 <= moment[2] <= 31 and moment[3] < 24 and moment[4] < 60
    ):
        raise ValueError(f"timestamp out of range: {stamp}")
    return calendar.timegm(moment) - offset


def parse_time(value: str) -> int:
    """``20/Oct/2026:08:00:01 +0700`` as Unix seconds."""
    # Lines from the same minute differ only in the seconds, so cache per minute.
    second = int(value[18:20])
    if not 0 <= second <= 60 or value[17] != ":" or value[20] != " ":
        raise ValueError(f"not a log timestamp: {value}")
    return _minute(value[:17], value[21:26]) + second


def parse_line(line: str) -> Request | None:
    """The request on *line*, or ``None`` when the line is not an access log entry."""
    match = LINE_RE.match(line)
    if match is None:
        return None
    try:
        time = parse_time(match["time"])
    except (ValueError, KeyError, IndexError):
        return None

    request = match["request"]
    parts = request.split(" ")
    if len(parts) >= 2 and parts[0].isalpha() and parts[0].isupper():
        method, target = parts[0], parts[1]
    else:
        method, target = "-", request
    path = target.split("?", 1)[0] if method != "-" else ""
    return Request(match["ip"], time, method, path, target, int(match["status"]), match["agent"])


def read_lines(sources: Iterable[str]) -> Iterator[str]:
    """Lines from each file in *sources*; gzip is detected by content, ``-`` is stdin."""
    for source in sources:
        if source == "-":
            yield from _decode(sys.stdin.buffer)
            continue
        with open(source, "rb") as raw:
            yield from _decode(raw)


def _decode(raw) -> Iterator[str]:
    # Peek rather than read, so a pipe or FIFO (`loghunt <(zcat x.gz)`) keeps its first bytes.
    buffered = raw if hasattr(raw, "peek") else io.BufferedReader(raw)
    if buffered.peek(2)[:2] == b"\x1f\x8b":
        buffered = gzip.GzipFile(fileobj=buffered)
    yield from io.TextIOWrapper(buffered, encoding="utf-8", errors="replace")
