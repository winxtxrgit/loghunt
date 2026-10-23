from __future__ import annotations

from conftest import entry

from loghunt.hunt import hunt


def rules_for(lines, ip):
    result = hunt(lines)
    for suspect in result.suspects:
        if suspect.ip == ip:
            return {f.rule for f in suspect.findings}
    return set()


def test_scanner_agent():
    lines = [entry("203.0.113.1", "/", agent="sqlmap/1.8.4#stable (https://sqlmap.org)")]
    assert "scanner-agent" in rules_for(lines, "203.0.113.1")


def test_attack_payload_is_decoded_before_matching():
    lines = [entry("203.0.113.2", "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users")]
    assert rules_for(lines, "203.0.113.2") == {"attack-payload"}


def test_probe_paths_need_three_distinct_paths():
    two = [entry("203.0.113.3", p, status=404) for p in ("/.env", "/.git/config")]
    assert rules_for(two, "203.0.113.3") == set()
    three = two + [entry("203.0.113.3", "/phpmyadmin/", status=404)]
    assert "probe-paths" in rules_for(three, "203.0.113.3")


def test_brute_force_counts_login_posts():
    lines = [entry("192.0.2.9", "/wp-login.php", method="POST", second=i * 3) for i in range(25)]
    assert "brute-force" in rules_for(lines, "192.0.2.9")


def test_get_on_login_page_is_not_brute_force():
    lines = [entry("192.0.2.9", "/login", second=i * 3) for i in range(25)]
    assert "brute-force" not in rules_for(lines, "192.0.2.9")


def test_flood_beats_burst():
    lines = [entry("198.51.100.4", "/", second=i // 20) for i in range(700)]
    rules = rules_for(lines, "198.51.100.4")
    assert "flood" in rules
    assert "burst" not in rules


def test_error_ratio_and_burst_together_cross_the_line():
    lines = [entry("198.51.100.5", f"/item/{i}", second=i // 3, status=404) for i in range(150)]
    assert rules_for(lines, "198.51.100.5") == {"burst", "error-ratio"}


def test_script_agent_alone_is_not_reported():
    lines = [entry("192.0.2.10", "/health", second=i * 60, agent="curl/8.5.0") for i in range(60)]
    assert rules_for(lines, "192.0.2.10") == set()


def test_busy_normal_visitor_is_not_reported():
    lines = [entry("100.64.1.1", f"/blog/post-{i}", second=i * 4) for i in range(200)]
    assert hunt(lines).suspects == []


def test_min_score_filters_suspects():
    from loghunt.rules import Thresholds

    lines = [entry("192.0.2.10", "/", agent="curl/8.5.0")]
    assert hunt(lines).suspects == []
    assert [s.ip for s in hunt(lines, Thresholds(min_score=10)).suspects] == ["192.0.2.10"]


def test_double_encoded_traversal_is_a_payload():
    target = "/static/%252e%252e%252f%252e%252e%252fetc%252fpasswd"
    assert rules_for([entry("203.0.113.8", target)], "203.0.113.8") == {"attack-payload"}


def test_ordinary_query_strings_are_not_payloads():
    from loghunt.signatures import has_payload

    for target in ("/search?q=rock+and+roll", "/p?id=10&sort=asc", "/docs/a%20b", "/?q=1%2B1"):
        assert not has_payload(target), target
