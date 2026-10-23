from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loghunt.hunt import Result, hunt
from loghunt.parser import read_lines

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "access.log.gz"
BASE = datetime(2026, 10, 20, 8, 0, tzinfo=timezone(timedelta(hours=7)))
FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0"


def entry(
    ip: str,
    target: str = "/",
    *,
    second: int = 0,
    method: str = "GET",
    status: int = 200,
    agent: str = FIREFOX,
) -> str:
    """One combined-format log line, *second* seconds after 08:00 Bangkok time."""
    stamp = (BASE + timedelta(seconds=second)).strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{ip} - - [{stamp}] "{method} {target} HTTP/1.1" {status} 512 "-" "{agent}"'


@pytest.fixture(scope="session")
def sample() -> Result:
    return hunt(read_lines([str(SAMPLE)]))
