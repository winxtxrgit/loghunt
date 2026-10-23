"""Per-IP counters built in one pass over the log."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import unquote_plus

from .parser import Request
from .signatures import has_payload, is_login, is_probe

# Distinct requests remembered per IP. Scripted bots repeat a short list; an IP
# past the cap is a crawler or a busy proxy and is not fingerprinted.
PATH_CAP = 500
PROBE_CAP = 200
SAMPLE_CAP = 3


@dataclass(slots=True)
class IPStats:
    ip: str
    requests: int = 0
    first: int = 0
    last: int = 0
    per_minute: Counter[int] = field(default_factory=Counter)
    status_classes: Counter[int] = field(default_factory=Counter)
    agents: Counter[str] = field(default_factory=Counter)
    paths: set[str] = field(default_factory=set)  # "METHOD /path"
    paths_overflow: bool = False
    probes: set[str] = field(default_factory=set)
    login_posts: Counter[str] = field(default_factory=Counter)
    payload_hits: int = 0
    payload_samples: list[str] = field(default_factory=list)
    malformed: int = 0

    def add(self, request: Request) -> None:
        if self.requests == 0:
            self.first = self.last = request.time
        else:
            # Merged or rotated logs are not always in order.
            self.first = min(self.first, request.time)
            self.last = max(self.last, request.time)
        self.requests += 1
        self.per_minute[request.time // 60] += 1
        self.status_classes[request.status // 100] += 1
        if request.agent is not None:
            self.agents[request.agent] += 1

        if request.method == "-":
            self.malformed += 1
        elif not self.paths_overflow:
            self.paths.add(f"{request.method} {request.path}")
            if len(self.paths) > PATH_CAP:
                self.paths_overflow = True
                self.paths.clear()

        if request.path and len(self.probes) < PROBE_CAP and is_probe(request.path):
            self.probes.add(request.path)
        if request.method == "POST" and is_login(request.path):
            self.login_posts[request.path] += 1
        if has_payload(request.target):
            self.payload_hits += 1
            if len(self.payload_samples) < SAMPLE_CAP:
                # Decoded, so the report shows `' AND SLEEP(5)` rather than `%27%20AND...`.
                sample = f"{request.method} {unquote_plus(request.target)}"
                self.payload_samples.append(sample[:200])

    @property
    def peak_per_minute(self) -> int:
        return max(self.per_minute.values(), default=0)

    @property
    def client_errors(self) -> int:
        return self.status_classes[4]

    @property
    def main_agent(self) -> str | None:
        """The most used User-Agent, or ``None`` if the log format has none."""
        common = self.agents.most_common(1)
        return common[0][0] if common else None
