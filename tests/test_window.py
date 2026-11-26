from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from conftest import SAMPLE, entry

from loghunt.cli import main
from loghunt.hunt import hunt

# conftest.entry() writes 08:00 Bangkok time, which is 01:00 UTC.
START = int(datetime(2026, 10, 20, 1, 0, tzinfo=timezone.utc).timestamp())
PROBES = ("/.env", "/.git/config", "/phpmyadmin/")


def prober(ip, second):
    return [entry(ip, path, second=second, status=404) for path in PROBES]


def test_window_keeps_only_requests_inside_it():
    lines = prober("203.0.113.1", 0) + prober("203.0.113.2", 3600)
    result = hunt(lines, since=START + 1800)
    assert [s.ip for s in result.suspects] == ["203.0.113.2"]
    assert result.outside == 3
    assert result.parsed == 3


def test_since_is_inclusive_and_until_is_exclusive():
    lines = [entry("100.64.0.1", second=0), entry("100.64.0.1", second=60)]
    result = hunt(lines, since=START, until=START + 60)
    assert result.parsed == 1
    assert result.start == result.end == START


def test_requests_split_by_the_window_no_longer_add_up():
    # 30 login attempts, 15 on each side of 01:30 UTC: brute-force only without a window.
    lines = [
        entry("192.0.2.9", "/login", method="POST", second=1790 + i * 2) for i in range(-10, 20)
    ]
    assert hunt(lines).suspects
    assert not hunt(lines, since=START + 1800).suspects


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-20 01:30",
        "2026-10-20T01:30:00",
        "2026-10-20T01:30Z",
        "2026-10-20T08:30+07:00",
        "2026-10-20 08:30 +0700",
        "2026-10-19T20:30-05:00",
    ],
)
def test_time_formats_and_offsets(value, capsys):
    assert main([str(SAMPLE), "--since", value, "--json", "-"]) == 0
    window = json.loads(capsys.readouterr().out)["window"]
    assert window["since"] == "2026-10-20T01:30:00Z"
    assert window["until"] is None
    assert window["outside"] > 0


def test_date_only_means_midnight_utc(capsys):
    assert main([str(SAMPLE), "--until", "2026-10-20", "--json", "-"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["window"]["until"] == "2026-10-20T00:00:00Z"
    assert payload["suspects"] == []  # the whole sample is later than that


def test_terminal_and_html_name_the_window(tmp_path, capsys):
    report = tmp_path / "r.html"
    args = [
        str(SAMPLE),
        "-o",
        str(report),
        "--since",
        "2026-10-20 01:30",
        "--until",
        "2026-10-20 02:00",
    ]
    assert main(args) == 0
    assert "window 2026-10-20 01:30 → 02:00 UTC" in capsys.readouterr().out
    assert "Only requests 2026-10-20 01:30 → 02:00 UTC were analysed" in report.read_text()


def test_no_window_note_without_a_window(capsys):
    assert main([str(SAMPLE)]) == 0
    assert "window" not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--since", "yesterday"], "not a date or time"),
        (["--since", "2026-02-30"], "not a valid time"),
        (["--since", "2026-10-20 02:00", "--until", "2026-10-20 01:00"], "must be earlier"),
    ],
)
def test_bad_windows_are_rejected(args, message, capsys):
    with pytest.raises(SystemExit) as exit:
        main([str(SAMPLE), *args])
    assert exit.value.code == 2
    assert message in capsys.readouterr().err
