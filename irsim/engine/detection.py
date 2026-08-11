"""Detection engine.

A small set of stateful, sliding-window rules. Each rule sees the telemetry
stream one event at a time (exactly as a streaming SIEM correlation engine
would) and raises an Alert when a pattern crosses its threshold. Rules never
see an event's ground-truth label; that is only attached afterwards, from the
contributing events, so the scorecard can separate true and false positives.
"""
from __future__ import annotations

from collections import defaultdict, deque
from statistics import mean, pstdev

from .models import Alert, Event


def _is_internal(ip: str) -> bool:
    return ip.startswith("10.20.0.")


class Rule:
    id = "base"
    category = "base"
    severity = "low"
    cooldown = 15.0

    def __init__(self):
        self._last_fired: dict = defaultdict(lambda: -1e9)

    def _cooled(self, key, t) -> bool:
        return (t - self._last_fired[key]) >= self.cooldown

    def _fire(self, key, t):
        self._last_fired[key] = t

    def feed(self, e: Event) -> Alert | None:      # pragma: no cover - override
        raise NotImplementedError


class PortScanRule(Rule):
    id, category, severity, cooldown = "port_scan", "port_scan", "medium", 20.0
    WINDOW, THRESHOLD = 12.0, 15

    def __init__(self):
        super().__init__()
        self._w: dict[str, deque] = defaultdict(deque)

    def feed(self, e):
        if e.action != "syn" or e.dst_port is None:
            return None
        w = self._w[e.src_ip]
        w.append((e.t, e.dst_port, e.label, e.id))
        while w and e.t - w[0][0] > self.WINDOW:
            w.popleft()
        ports = {p for _, p, _, _ in w}
        if len(ports) >= self.THRESHOLD and self._cooled(e.src_ip, e.t):
            self._fire(e.src_ip, e.t)
            return _mk(self, e, sorted(w, key=lambda x: x[0]),
                       f"{len(ports)} distinct ports probed on {e.dst_ip} "
                       f"from {e.src_ip} within {self.WINDOW:.0f}s",
                       confidence=min(0.99, 0.5 + len(ports) / 60))
        return None


class DosRule(Rule):
    id, category, severity, cooldown = "dos", "dos", "high", 15.0
    WINDOW, THRESHOLD = 5.0, 50

    def __init__(self):
        super().__init__()
        self._w: dict[tuple, deque] = defaultdict(deque)

    def feed(self, e):
        if e.action != "syn" or e.dst_port is None:
            return None
        key = (e.dst_ip, e.dst_port)
        w = self._w[key]
        w.append((e.t, e.src_ip, e.label, e.id))
        while w and e.t - w[0][0] > self.WINDOW:
            w.popleft()
        if len(w) >= self.THRESHOLD and self._cooled(key, e.t):
            self._fire(key, e.t)
            rate = len(w) / self.WINDOW
            return _mk(self, e, list(w),
                       f"{rate:.0f} SYN/s to {e.dst_ip}:{e.dst_port} — "
                       f"possible TCP SYN flood",
                       confidence=min(0.99, 0.6 + rate / 200), dst=e.dst_ip)
        return None


class BruteForceRule(Rule):
    id, category, severity, cooldown = "brute_force", "brute_force", "high", 25.0
    WINDOW, THRESHOLD = 20.0, 12

    def __init__(self):
        super().__init__()
        self._w: dict[tuple, deque] = defaultdict(deque)

    def feed(self, e):
        if e.kind != "auth" or e.action != "login_fail":
            return None
        acct = e.meta.get("account", "?")
        key = (e.dst_ip, acct)
        w = self._w[key]
        w.append((e.t, e.src_ip, e.label, e.id))
        while w and e.t - w[0][0] > self.WINDOW:
            w.popleft()
        if len(w) >= self.THRESHOLD and self._cooled(key, e.t):
            self._fire(key, e.t)
            return _mk(self, e, list(w),
                       f"{len(w)} failed logins for '{acct}' on {e.dst_ip} "
                       f"in {self.WINDOW:.0f}s",
                       confidence=min(0.99, 0.55 + len(w) / 40), dst=e.dst_ip)
        return None


class BeaconRule(Rule):
    id, category, severity, cooldown = "c2_beacon", "c2_beacon", "high", 60.0
    WINDOW, MIN_HITS, MAX_CV = 30.0, 6, 0.28

    def __init__(self):
        super().__init__()
        self._w: dict[tuple, deque] = defaultdict(deque)

    def feed(self, e):
        if e.action != "connect":
            return None
        key = (e.src_ip, e.dst_ip)
        w = self._w[key]
        w.append((e.t, e.src_ip, e.label, e.id))
        while w and e.t - w[0][0] > self.WINDOW:
            w.popleft()
        times = [x[0] for x in w]
        if len(times) >= self.MIN_HITS:
            gaps = [b - a for a, b in zip(times, times[1:])]
            m = mean(gaps)
            cv = (pstdev(gaps) / m) if m else 1.0
            if cv <= self.MAX_CV and self._cooled(key, e.t):
                self._fire(key, e.t)
                return _mk(self, e, list(w),
                           f"Regular {m:.1f}s beacon from {e.src_ip} to "
                           f"{e.dst_ip} (low jitter) — likely C2",
                           confidence=min(0.98, 0.6 + (self.MAX_CV - cv)),
                           src=e.src_ip, dst=e.dst_ip)
        return None


class ExfilRule(Rule):
    id, category, severity, cooldown = "data_exfil", "data_exfil", "critical", 20.0
    WINDOW, THRESHOLD = 15.0, 20_000_000    # 20 MB outbound

    def __init__(self):
        super().__init__()
        self._w: dict[str, deque] = defaultdict(deque)

    def feed(self, e):
        if e.action != "transfer" or _is_internal(e.dst_ip):
            return None
        w = self._w[e.src_ip]
        w.append((e.t, e.bytes, e.label, e.id))
        while w and e.t - w[0][0] > self.WINDOW:
            w.popleft()
        total = sum(b for _, b, _, _ in w)
        if total >= self.THRESHOLD and self._cooled(e.src_ip, e.t):
            self._fire(e.src_ip, e.t)
            return _mk(self, e, [(t, s, lb, i) for t, s, lb, i in w],
                       f"{total/1e6:.0f} MB pushed from {e.src_ip} to external "
                       f"{e.dst_ip} in {self.WINDOW:.0f}s",
                       confidence=min(0.99, 0.6 + total / 1e8),
                       src=e.src_ip, dst=e.dst_ip)
        return None


def _mk(rule: Rule, e: Event, window_rows, summary, confidence,
        src=None, dst=None) -> Alert:
    labels = [row[2] for row in window_rows]
    ids = [row[-1] for row in window_rows]
    truth = "malicious" if "malicious" in labels else "benign"
    return Alert(
        t=e.t, rule=rule.id, category=rule.category, severity=rule.severity,
        src_ip=src or e.src_ip, dst_ip=dst or e.dst_ip,
        confidence=confidence, summary=summary,
        evidence=ids[-12:], truth=truth,
    )


class DetectionEngine:
    """Runs every event through every rule and collects the alerts raised."""

    def __init__(self):
        self.rules: list[Rule] = [
            PortScanRule(), DosRule(), BruteForceRule(),
            BeaconRule(), ExfilRule(),
        ]

    def process(self, e: Event) -> list[Alert]:
        out = []
        for r in self.rules:
            a = r.feed(e)
            if a:
                out.append(a)
        return out
