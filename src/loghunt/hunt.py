"""Run the whole analysis: parse, count, apply rules, group campaigns, rank."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .campaigns import Campaign, campaign_finding, find_campaigns
from .parser import parse_line
from .rules import Finding, Thresholds, evaluate
from .stats import IPStats

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class Suspect:
    stats: IPStats
    findings: list[Finding]

    @property
    def ip(self) -> str:
        return self.stats.ip

    @property
    def score(self) -> int:
        return min(100, sum(f.score for f in self.findings))

    @property
    def severity(self) -> str:
        if self.score >= 70:
            return "high"
        return "medium" if self.score >= 40 else "low"


@dataclass
class Result:
    lines: int
    skipped: int
    stats: dict[str, IPStats]
    suspects: list[Suspect]
    campaigns: list[Campaign]
    limits: Thresholds = field(default_factory=Thresholds)
    allowed: int = 0  # IPs on the allowlist, never checked
    since: int | None = None  # the --since / --until window, Unix seconds
    until: int | None = None
    outside: int = 0  # requests left out because they fall outside the window

    @property
    def parsed(self) -> int:
        """Requests analysed: access log entries inside the window."""
        return self.lines - self.skipped - self.outside

    @property
    def start(self) -> int | None:
        return min((s.first for s in self.stats.values()), default=None)

    @property
    def end(self) -> int | None:
        return max((s.last for s in self.stats.values()), default=None)

    @property
    def flagged_requests(self) -> int:
        return sum(s.stats.requests for s in self.suspects)

    def timeline(self, buckets: int = 120) -> list[tuple[int, int, int]]:
        """``(bucket start, all requests, flagged requests)``, at most *buckets* rows."""
        if self.start is None or self.end is None:
            return []
        first, last = self.start // 60, self.end // 60
        width = max(1, -(-(last - first + 1) // buckets))  # minutes per bucket, rounded up
        size = (last - first) // width + 1
        total, flagged = [0] * size, [0] * size
        flagged_ips = {s.ip for s in self.suspects}
        for entry in self.stats.values():
            is_flagged = entry.ip in flagged_ips
            for minute, count in entry.per_minute.items():
                index = (minute - first) // width
                total[index] += count
                if is_flagged:
                    flagged[index] += count
        return [((first + i * width) * 60, total[i], flagged[i]) for i in range(size)]


def is_allowed(ip: str, allow: Sequence[Network]) -> bool:
    """Whether *ip* falls in one of the *allow* networks. A value that is not an IP never does."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # nginx on a dual-stack socket can log an IPv4 client as ::ffff:203.0.113.9.
    mapped = getattr(address, "ipv4_mapped", None)
    return any(address in network or (mapped and mapped in network) for network in allow)


def hunt(
    lines: Iterable[str],
    limits: Thresholds | None = None,
    allow: Sequence[Network] = (),
    since: int | None = None,
    until: int | None = None,
) -> Result:
    """Analyse *lines*.

    IPs in *allow* still count toward traffic but are never flagged. Only requests at or
    after *since* and before *until* (Unix seconds) are analysed.
    """
    limits = limits or Thresholds()
    stats: dict[str, IPStats] = {}
    count = skipped = outside = 0
    for line in lines:
        request = parse_line(line)
        if request is None:
            if line.strip():
                count += 1
                skipped += 1
            continue
        count += 1
        if (since is not None and request.time < since) or (
            until is not None and request.time >= until
        ):
            outside += 1
            continue
        entry = stats.get(request.ip)
        if entry is None:
            entry = stats[request.ip] = IPStats(request.ip)
        entry.add(request)

    # Allowed IPs stay out of campaigns too, so a group of your own monitors is never one.
    checked = {ip: e for ip, e in stats.items() if not allow or not is_allowed(ip, allow)}
    findings = {ip: evaluate(entry, limits) for ip, entry in checked.items()}
    campaigns = find_campaigns(checked, findings, limits)
    for campaign in campaigns:
        for ip in campaign.ips:
            findings[ip].append(campaign_finding(campaign))

    suspects = [Suspect(stats[ip], found) for ip, found in findings.items() if found]
    suspects = [s for s in suspects if s.score >= limits.min_score]
    suspects.sort(key=lambda s: (-s.score, -s.stats.requests, s.ip))
    allowed = len(stats) - len(checked)
    return Result(
        count, skipped, stats, suspects, campaigns, limits, allowed, since, until, outside
    )
