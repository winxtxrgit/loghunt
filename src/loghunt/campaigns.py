"""Find botnets: many IPs running the same script, each one quiet enough to pass alone.

IPs that send exactly the same set of requests with the same User-Agent are one
fingerprint. A fingerprint shared by several IPs becomes a campaign when the
group, added up, does what a single attacker would be flagged for.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .rules import Finding, Thresholds
from .stats import IPStats


@dataclass(frozen=True)
class Campaign:
    id: str
    agent: str
    requests: tuple[str, ...]  # the shared fingerprint, "METHOD /path"
    ips: tuple[str, ...]
    total_requests: int
    networks: int  # distinct /16 (IPv4) or /32 (IPv6) networks
    reason: str


def _network(ip: str) -> str:
    if ":" in ip:
        return ":".join(ip.split(":")[:2])
    return ".".join(ip.split(".")[:2])


def _group_reason(
    members: list[IPStats], findings: dict[str, list[Finding]], limits: Thresholds
) -> str | None:
    logins = sum(sum(m.login_posts.values()) for m in members)
    if logins >= limits.login_posts:
        busiest = max(sum(m.login_posts.values()) for m in members)
        return f"{logins} login attempts together, no more than {busiest} from any one IP"
    probes = set().union(*(m.probes for m in members))
    if len(probes) >= limits.probes:
        return f"Asked for {len(probes)} attacker-only paths together"
    payloads = sum(m.payload_hits for m in members)
    if payloads:
        return f"{payloads} requests with attack payloads together"
    requests = sum(m.requests for m in members)
    errors = sum(m.client_errors for m in members)
    if requests >= limits.error_min_requests and errors / requests >= limits.error_ratio:
        return f"{errors / requests:.0%} of {requests:,} requests failed with 4xx"
    flagged = [
        m for m in members if sum(f.score for f in findings.get(m.ip, ())) >= limits.min_score
    ]
    if flagged:
        return f"{len(flagged)} of these IPs were already flagged on their own"
    return None


def find_campaigns(
    stats: dict[str, IPStats], findings: dict[str, list[Finding]], limits: Thresholds
) -> list[Campaign]:
    groups: dict[tuple[str, frozenset[str]], list[IPStats]] = defaultdict(list)
    for entry in stats.values():
        agent = entry.main_agent
        if agent is None or entry.paths_overflow or not entry.paths:
            continue
        if len(entry.paths) > limits.campaign_max_paths:
            continue
        groups[(agent, frozenset(entry.paths))].append(entry)

    campaigns = []
    for (agent, paths), members in groups.items():
        if len(members) < limits.campaign_min_ips:
            continue
        reason = _group_reason(members, findings, limits)
        if reason is None:
            continue
        campaigns.append((agent, paths, members, reason))

    campaigns.sort(key=lambda c: (-len(c[2]), -sum(m.requests for m in c[2])))
    return [
        Campaign(
            id=f"C{index}",
            agent=agent,
            requests=tuple(sorted(paths)),
            ips=tuple(sorted(m.ip for m in members)),
            total_requests=sum(m.requests for m in members),
            networks=len({_network(m.ip) for m in members}),
            reason=reason,
        )
        for index, (agent, paths, members, reason) in enumerate(campaigns, start=1)
    ]


def campaign_finding(campaign: Campaign) -> Finding:
    count = len(campaign.requests)
    what = "request" if count == 1 else f"{count} requests"
    reason = (
        f"Part of campaign {campaign.id}: {len(campaign.ips)} IPs sent the same "
        f"{what} with the same User-Agent. {campaign.reason}"
    )
    return Finding("campaign", 40, reason)
