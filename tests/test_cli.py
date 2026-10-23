from __future__ import annotations

import io
import json
import sys

from conftest import SAMPLE, entry

from loghunt.cli import main


def test_writes_every_output(tmp_path, capsys):
    report, blocklist, data = tmp_path / "r.html", tmp_path / "b.txt", tmp_path / "f.json"
    code = main(
        [str(SAMPLE), "-o", str(report), "--blocklist", str(blocklist), "--json", str(data)]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "suspicious IPs" in out
    assert "Campaign C1" in out
    assert report.read_text().startswith("<!doctype html>")
    assert "203.0.113.66" in blocklist.read_text().splitlines()
    assert json.loads(data.read_text())["campaigns"]


def test_json_to_stdout_stays_parseable(capsys):
    assert main([str(SAMPLE), "--json", "-"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["suspects"]
    assert "suspicious IPs" in captured.err


def test_fail_flag(tmp_path):
    quiet = tmp_path / "quiet.log"
    quiet.write_text(entry("100.64.0.1") + "\n")
    assert main([str(quiet), "--fail"]) == 0
    assert main([str(SAMPLE), "--fail"]) == 1


def test_reads_stdin(monkeypatch, capsys):
    text = "\n".join(entry("203.0.113.1", p, status=404) for p in ("/.env", "/.git/HEAD", "/pma/"))
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(text.encode())))
    assert main(["-"]) == 0
    assert "203.0.113.1" in capsys.readouterr().out


def test_missing_file(capsys):
    assert main(["/no/such/access.log"]) == 2
    assert "loghunt:" in capsys.readouterr().err
