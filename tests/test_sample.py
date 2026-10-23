"""The bundled sample has known attackers; loghunt must find each of them and nobody else."""

from __future__ import annotations

ATTACKERS = {
    "203.0.113.66": "scanner-agent",  # sqlmap
    "203.0.113.23": "probe-paths",  # secret and admin-panel prober
    "198.51.100.200": "flood",
    "192.0.2.77": "brute-force",  # wp-login.php
    "203.0.113.140": "attack-payload",  # Log4Shell, XSS, traversal
}


def test_finds_every_single_attacker(sample):
    found = {s.ip: {f.rule for f in s.findings} for s in sample.suspects}
    for ip, rule in ATTACKERS.items():
        assert rule in found.get(ip, set()), ip


def test_finds_the_botnet(sample):
    assert len(sample.campaigns) == 1
    campaign = sample.campaigns[0]
    assert len(campaign.ips) == 19
    assert campaign.total_requests == 152
    assert campaign.requests == ("POST /xmlrpc.php",)


def test_no_false_positives(sample):
    flagged = {s.ip for s in sample.suspects}
    expected = set(ATTACKERS) | set(sample.campaigns[0].ips)
    assert flagged == expected
    assert "198.51.100.10" not in flagged  # Googlebot crawl
    assert "192.0.2.10" not in flagged  # curl health check every minute
    assert not any(ip.startswith("100.") for ip in flagged)  # ordinary visitors


def test_every_line_parses(sample):
    assert sample.skipped == 0
    assert sample.lines == 17911
