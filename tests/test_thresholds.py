from __future__ import annotations

import json

import pytest
from conftest import SAMPLE, entry

from loghunt.cli import main
from loghunt.rules import Thresholds


def login_posts(ip, count):
    return [entry(ip, "/wp-login.php", method="POST", second=i * 3) for i in range(count)]


def write(tmp_path, lines):
    log = tmp_path / "access.log"
    log.write_text("\n".join(lines) + "\n")
    return str(log)


def suspects(args, capsys):
    assert main([*args, "--json", "-"]) == 0
    return {
        s["ip"]: {f["rule"] for f in s["findings"]}
        for s in json.loads(capsys.readouterr().out)["suspects"]
    }


def test_login_posts_threshold(tmp_path, capsys):
    log = write(tmp_path, login_posts("192.0.2.9", 25))
    assert "brute-force" in suspects([log], capsys)["192.0.2.9"]
    assert "192.0.2.9" not in suspects([log, "--login-posts", "30"], capsys)


def test_probes_threshold(tmp_path, capsys):
    lines = [entry("203.0.113.3", p, status=404) for p in ("/.env", "/.git/config")]
    log = write(tmp_path, lines)
    assert "203.0.113.3" not in suspects([log], capsys)
    assert suspects([log, "--probes", "2"], capsys)["203.0.113.3"] == {"probe-paths"}


def test_burst_and_flood_thresholds(tmp_path, capsys):
    lines = [entry("198.51.100.5", f"/item/{i}", second=i % 60) for i in range(200)]
    log = write(tmp_path, lines)
    # 200 in one minute: a burst by default (30 points, under the 40 needed to report).
    assert "198.51.100.5" not in suspects([log], capsys)
    assert suspects([log, "--flood", "150"], capsys)["198.51.100.5"] == {"flood"}
    assert "198.51.100.5" not in suspects([log, "--burst", "300", "--flood", "300"], capsys)


def test_campaigns_use_the_login_threshold(tmp_path, capsys):
    # 19 IPs x 8 logins = 152 together: a campaign by default, not with --login-posts 200.
    lines = [line for n in range(1, 20) for line in login_posts(f"100.64.0.{n}", 8)]
    log = write(tmp_path, lines)
    assert len(suspects([log], capsys)) == 19
    assert suspects([log, "--login-posts", "200"], capsys) == {}


def test_json_records_the_thresholds(capsys):
    assert main([str(SAMPLE), "--json", "-", "--burst", "200", "--flood", "900"]) == 0
    used = json.loads(capsys.readouterr().out)["thresholds"]
    assert used["burst"] == 200 and used["flood"] == 900
    assert used["login_posts"] == Thresholds.login_posts


def test_html_footer_shows_the_thresholds(tmp_path):
    report = tmp_path / "r.html"
    assert main([str(SAMPLE), "-o", str(report), "--login-posts", "77"]) == 0
    assert "77 login POSTs" in report.read_text()


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--burst", "0"], "must be between"),
        (["--probes", "1001"], "must be between"),
        (["--burst", "500", "--flood", "400"], "must be at least --burst"),
    ],
)
def test_bad_thresholds_are_rejected(args, message, capsys):
    with pytest.raises(SystemExit) as exit:
        main([str(SAMPLE), *args])
    assert exit.value.code == 2
    assert message in capsys.readouterr().err
