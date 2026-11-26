from __future__ import annotations

import pytest
from conftest import SAMPLE, entry

from loghunt.cli import main
from loghunt.hunt import hunt
from loghunt.report import BLOCKLIST_FORMATS, to_blocklist

PROBES = ("/.env", "/.git/config", "/phpmyadmin/")


@pytest.fixture(scope="module")
def mixed():
    """Two IPv4 probers, one IPv6, and the first IPv4 again as an IPv4-mapped IPv6."""
    ips = ("203.0.113.5", "198.51.100.9", "2001:db8::7", "::ffff:203.0.113.5")
    return hunt([entry(ip, p, status=404) for ip in ips for p in PROBES])


def test_plain_is_unchanged_and_maps_ipv4_in_ipv6(mixed):
    assert sorted(to_blocklist(mixed).splitlines()) == [
        "198.51.100.9",
        "2001:db8::7",
        "203.0.113.5",
    ]


def test_nginx(mixed):
    lines = to_blocklist(mixed, "nginx").splitlines()
    assert lines[0].startswith("# loghunt")
    assert sorted(lines[1:]) == ["deny 198.51.100.9;", "deny 2001:db8::7;", "deny 203.0.113.5;"]


def test_apache(mixed):
    text = to_blocklist(mixed, "apache")
    assert "<RequireAll>\n    Require all granted\n" in text
    assert "    Require not ip 2001:db8::7\n" in text
    assert text.endswith("</RequireAll>\n")


def test_ipset_splits_families_and_flushes(mixed):
    lines = to_blocklist(mixed, "ipset").splitlines()
    assert lines[:2] == ["create loghunt4 hash:ip family inet -exist", "flush loghunt4"]
    assert "add loghunt4 203.0.113.5 -exist" in lines
    assert "add loghunt6 2001:db8::7 -exist" in lines
    assert not any(line.startswith("#") for line in lines)  # ipset restore reads commands only


def test_nftables_replaces_its_own_table(mixed):
    text = to_blocklist(mixed, "nftables")
    assert "table inet loghunt {}\ndelete table inet loghunt\n" in text
    assert "elements = { 2001:db8::7 }" in text
    assert "203.0.113.5" in text.split("set blocked4")[1].split("}")[0]


def test_empty_nftables_sets_have_no_elements_line():
    # nft rejects `elements = { }`.
    text = to_blocklist(hunt([]), "nftables")
    assert "elements" not in text
    assert "set blocked4" in text


@pytest.mark.parametrize("fmt", BLOCKLIST_FORMATS)
def test_only_real_addresses_reach_any_format(fmt):
    # With X-Forwarded-For logging, the client writes the IP column.
    lines = [entry(ip, "/", agent="sqlmap/1.8") for ip in ("1.2.3.4;include", "evil.example")]
    result = hunt(lines)
    assert len(result.suspects) == 2  # flagged, so the test reaches the blocklist
    text = to_blocklist(result, fmt)
    assert "include" not in text and "evil" not in text


def test_cli_blocklist_format(tmp_path):
    target = tmp_path / "deny.conf"
    assert main([str(SAMPLE), "--blocklist", str(target), "--blocklist-format", "nginx"]) == 0
    assert "deny 203.0.113.66;" in target.read_text().splitlines()


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--blocklist-format", "nginx"], "needs --blocklist FILE"),
        (["--blocklist", "-", "--blocklist-format", "iptables"], "invalid choice"),
    ],
)
def test_cli_rejects_bad_format_use(args, message, capsys):
    with pytest.raises(SystemExit) as exit:
        main([str(SAMPLE), *args])
    assert exit.value.code == 2
    assert message in capsys.readouterr().err


def test_cli_does_not_count_a_merged_mapped_ip_as_left_out(tmp_path, capsys):
    log = tmp_path / "access.log"
    lines = [
        entry(ip, p, status=404) for ip in ("203.0.113.5", "::ffff:203.0.113.5") for p in PROBES
    ]
    log.write_text("\n".join(lines) + "\n")
    target = tmp_path / "b.txt"
    assert main([str(log), "--blocklist", str(target)]) == 0
    assert target.read_text() == "203.0.113.5\n"
    assert "left out" not in capsys.readouterr().out
