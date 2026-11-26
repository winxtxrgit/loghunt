from __future__ import annotations

import ipaddress
import json

import pytest
from conftest import SAMPLE, entry

from loghunt.cli import main
from loghunt.hunt import hunt, is_allowed

PROBES = ("/.env", "/.git/config", "/phpmyadmin/")


def net(*values):
    return [ipaddress.ip_network(v) for v in values]


def prober(ip):
    return [entry(ip, path, status=404) for path in PROBES]


def test_allowed_ip_is_not_flagged_but_still_counted():
    lines = prober("203.0.113.1") + prober("203.0.113.2")
    result = hunt(lines, allow=net("203.0.113.1/32"))
    assert [s.ip for s in result.suspects] == ["203.0.113.2"]
    assert result.allowed == 1
    assert "203.0.113.1" in result.stats  # traffic totals still include it


def test_cidr_and_ipv6_ranges():
    allow = net("198.51.100.0/24", "2001:db8::/32")
    assert is_allowed("198.51.100.77", allow)
    assert is_allowed("2001:db8:1::5", allow)
    assert not is_allowed("198.51.101.1", allow)
    assert not is_allowed("2001:db9::1", allow)


def test_ipv4_mapped_ipv6_matches_the_ipv4_range():
    assert is_allowed("::ffff:198.51.100.7", net("198.51.100.0/24"))


def test_a_value_that_is_not_an_ip_never_matches():
    assert not is_allowed("unknown", net("0.0.0.0/0"))


def test_allowed_ips_do_not_form_a_campaign():
    # Three monitors running the same login check: a campaign unless they are allowed.
    lines = [
        entry(f"192.0.2.{n}", "/login", method="POST", second=i, agent="monitor/1.0")
        for n in (1, 2, 3)
        for i in range(8)
    ]
    assert hunt(lines).campaigns
    allowed = hunt(lines, allow=net("192.0.2.0/24"))
    assert not allowed.campaigns
    assert not allowed.suspects


def test_cli_allow_keeps_ip_out_of_every_output(tmp_path, capsys):
    blocklist, data = tmp_path / "b.txt", tmp_path / "f.json"
    args = [str(SAMPLE), "--blocklist", str(blocklist), "--json", str(data)]
    assert main(args) == 0
    assert "203.0.113.66" in blocklist.read_text(encoding="utf-8").splitlines()
    assert main([*args, "--allow", "203.0.113.66"]) == 0
    assert "203.0.113.66" not in blocklist.read_text(encoding="utf-8")
    payload = json.loads(data.read_text(encoding="utf-8"))
    assert payload["allowed"] == 1
    assert "203.0.113.66" not in {s["ip"] for s in payload["suspects"]}
    assert "1 allowlisted IP was not checked" in capsys.readouterr().out


def test_cli_allow_file(tmp_path, capsys):
    allow = tmp_path / "allow.txt"
    allow.write_text("# uptime checks\n203.0.113.66   # the prober\n\n198.51.100.0/24\n")
    blocklist = tmp_path / "b.txt"
    assert main([str(SAMPLE), "--allow", f"@{allow}", "--blocklist", str(blocklist)]) == 0
    assert "203.0.113.66" not in blocklist.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("value", "message"),
    [("not-an-ip", "not an IP address"), ("@/no/such/allow.txt", "cannot read")],
)
def test_cli_rejects_bad_allow_values(value, message, capsys):
    with pytest.raises(SystemExit) as exit:
        main([str(SAMPLE), "--allow", value])
    assert exit.value.code == 2
    assert message in capsys.readouterr().err


def test_cli_reports_the_bad_line_of_an_allow_file(tmp_path, capsys):
    allow = tmp_path / "allow.txt"
    allow.write_text("203.0.113.1\n203.0.113.999\n")
    with pytest.raises(SystemExit):
        main([str(SAMPLE), "--allow", f"@{allow}"])
    assert "line 2" in capsys.readouterr().err
