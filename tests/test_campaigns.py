from __future__ import annotations

from conftest import entry

from loghunt.hunt import hunt

BOT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0"


def botnet(size: int, posts_each: int) -> list[str]:
    lines = []
    for n in range(size):
        ip = f"198.18.{n}.{n + 1}"
        for k in range(posts_each):
            second = n * 97 + k * 600
            lines.append(entry(ip, "/xmlrpc.php", method="POST", second=second, agent=BOT))
    return lines


def test_low_and_slow_botnet_is_one_campaign():
    result = hunt(botnet(size=10, posts_each=5))
    assert len(result.campaigns) == 1
    campaign = result.campaigns[0]
    assert len(campaign.ips) == 10
    assert campaign.requests == ("POST /xmlrpc.php",)
    assert campaign.total_requests == 50
    assert "50 login attempts together, no more than 5 from any one IP" in campaign.reason
    assert {s.ip for s in result.suspects} == set(campaign.ips)


def test_each_member_alone_is_not_flagged():
    result = hunt(botnet(size=1, posts_each=5))
    assert result.suspects == []
    assert result.campaigns == []


def test_two_ips_are_not_a_campaign():
    assert hunt(botnet(size=2, posts_each=15)).campaigns == []


def test_same_browser_same_pages_is_not_a_campaign():
    lines = []
    for n in range(30):
        ip = f"100.64.0.{n + 1}"
        lines += [entry(ip, "/", second=n), entry(ip, "/static/app.css", second=n)]
    result = hunt(lines)
    assert result.campaigns == []
    assert result.suspects == []


def test_different_agents_split_campaigns():
    lines = botnet(size=4, posts_each=6)
    lines += [line.replace(BOT, "OtherBot/1.0") for line in botnet(size=4, posts_each=6)]
    # Same IPs with a second agent would merge per IP, so give the copies new addresses.
    lines = lines[:24] + [line.replace("198.18.", "198.19.") for line in lines[24:]]
    result = hunt(lines)
    assert sorted(len(c.ips) for c in result.campaigns) == [4, 4]


def test_hotlinked_missing_image_is_not_a_campaign():
    # Another site embeds an image that was deleted here: many real browsers, one 404 each.
    lines = [entry(f"100.64.9.{n}", "/img/old.png", second=n, status=404) for n in range(40)]
    result = hunt(lines)
    assert result.campaigns == []
    assert result.suspects == []


def test_probers_running_one_script_are_grouped():
    def probes(paths):
        return [
            entry(f"198.18.7.{n}", path, second=n * 60, status=404, agent=BOT)
            for n in range(1, 6)
            for path in paths
        ]

    # Two probe paths each: below the threshold for one IP, and for the group too.
    assert hunt(probes(("/.env", "/.git/config"))).campaigns == []

    # Three each: every IP is flagged, and the five are reported as one campaign.
    result = hunt(probes(("/.env", "/.git/config", "/backup.zip")))
    assert [len(c.ips) for c in result.campaigns] == [5]
    assert all("campaign" in {f.rule for f in s.findings} for s in result.suspects)
