"""Run the whole analysis: parse, count, apply rules, group campaigns, rank."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .campaigns import Campaign, campaign_finding, find_campaigns
from .parser import parse_line
from .rules import Finding, Thresholds, evaluate
from .stats import IPStats


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

    @property
    def parsed(self) -> int:
        return self.lines - self.skipped

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


def hunt(lines: Iterable[str], limits: Thresholds | None = None) -> Result:
    limits = limits or Thresholds()
    stats: dict[str, IPStats] = {}
    count = skipped = 0
    for line in lines:
        request = parse_line(line)
        if request is None:
            if line.strip():
                count += 1
                skipped += 1
            continue
        count += 1
        entry = stats.get(request.ip)
        if entry is None:
            entry = stats[request.ip] = IPStats(request.ip)
        entry.add(request)

    findings = {ip: evaluate(entry, limits) for ip, entry in stats.items()}
    campaigns = find_campaigns(stats, findings, limits)
    for campaign in campaigns:
        for ip in campaign.ips:
            findings[ip].append(campaign_finding(campaign))

    suspects = [Suspect(stats[ip], found) for ip, found in findings.items() if found]
    suspects = [s for s in suspects if s.score >= limits.min_score]
    suspects.sort(key=lambda s: (-s.score, -s.stats.requests, s.ip))
    return Result(count, skipped, stats, suspects, campaigns, limits)
