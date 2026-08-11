"""Core data models for the incident-response simulation engine.

Everything the tool works with is a synthetic telemetry Event. Nothing here
touches a real network — events are generated in memory so the simulation is
safe to run anywhere and the exercise stays focused on *response*, not attack.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Severity + phase vocabularies (kept as plain strings so they serialise
# cleanly to JSON for the dashboard).
# ---------------------------------------------------------------------------
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# NIST SP 800-61 incident-handling lifecycle, slightly compressed.
PHASES = ["detection", "analysis", "containment", "eradication", "recovery", "closed"]

_event_counter = itertools.count(1)
_alert_counter = itertools.count(1)


@dataclass
class Event:
    """A single unit of synthetic security telemetry.

    `label` is ground truth ("malicious" / "benign"). The detection engine
    never sees it — it is used only afterwards to score how well detection did.
    """
    t: float                       # simulation time (seconds since run start)
    kind: str                      # net | auth | flow | proc
    action: str                    # syn | login_fail | login_ok | connect | transfer
    src_ip: str
    dst_ip: str
    dst_port: Optional[int] = None
    protocol: str = "tcp"
    bytes: int = 0
    label: str = "benign"          # ground truth, hidden from detection
    scenario_id: Optional[str] = None
    meta: dict = field(default_factory=dict)
    id: int = field(default_factory=lambda: next(_event_counter))

    def as_row(self) -> dict[str, Any]:
        """Compact dict for the live event feed in the UI."""
        return {
            "id": self.id,
            "t": round(self.t, 2),
            "kind": self.kind,
            "action": self.action,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "bytes": self.bytes,
        }


@dataclass
class Alert:
    """Raised by a detection rule when a pattern crosses a threshold."""
    t: float
    rule: str                      # rule id, e.g. "port_scan"
    category: str                  # incident category this maps to
    severity: str
    src_ip: str
    dst_ip: str
    confidence: float              # 0..1
    summary: str
    evidence: list[int] = field(default_factory=list)   # contributing event ids
    truth: str = "unknown"         # filled from contributing events for scoring
    id: int = field(default_factory=lambda: next(_alert_counter))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["t"] = round(self.t, 2)
        d["confidence"] = round(self.confidence, 2)
        return d
