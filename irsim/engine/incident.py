"""Incident lifecycle management.

Alerts are noisy and low-level; incidents are the unit an analyst actually
works. This module correlates related alerts into a single incident, tracks it
through the NIST phases, and records every response action (whether taken
automatically or by a human analyst) with a timestamp so the scorecard can
measure how the response went.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Alert
from .playbooks import Step, steps_for

# Containment SLA per severity, in simulation-seconds. Missing it is a gap.
CONTAINMENT_SLA = {"critical": 20, "high": 30, "medium": 60, "low": 120, "info": 240}

_PHASE_STATUS = {
    "containment": "contained",
    "eradication": "eradicated",
    "recovery": "recovered",
}


@dataclass
class Incident:
    id: str
    category: str
    severity: str
    title: str
    attacker_ip: str
    target_ip: str
    detected_t: float
    recommended_steps: list[Step]
    alerts: list[dict] = field(default_factory=list)
    executed: list[dict] = field(default_factory=list)   # response actions taken
    contained_t: float | None = None
    eradicated_t: float | None = None
    recovered_t: float | None = None
    closed_t: float | None = None
    # ground truth, filled by the simulator for scoring (analyst never sees it)
    first_event_t: float | None = None
    # internal auto-mode execution schedule: list of (exec_t, Step)
    _schedule: list = field(default_factory=list)

    # ------------------------------------------------------------------ state
    @property
    def status(self) -> str:
        if self.closed_t is not None:
            return "closed"
        if self.recovered_t is not None:
            return "recovered"
        if self.eradicated_t is not None:
            return "eradicated"
        if self.contained_t is not None:
            return "contained"
        return "investigating"

    @property
    def executed_ids(self) -> set[str]:
        return {a["step_id"] for a in self.executed}

    @property
    def sla_seconds(self) -> float:
        return CONTAINMENT_SLA.get(self.severity, 120)

    def pending_steps(self) -> list[Step]:
        done = self.executed_ids
        return [s for s in self.recommended_steps if s.id not in done]

    # ------------------------------------------------------------- transitions
    def execute_step(self, step_id: str, t: float, mode: str) -> dict | None:
        if step_id in self.executed_ids:
            return None
        step = next((s for s in self.recommended_steps if s.id == step_id), None)
        if step is None:
            return None
        record = {"step_id": step.id, "phase": step.phase, "action": step.action,
                  "description": step.description, "t": round(t, 2), "mode": mode}
        self.executed.append(record)

        if step.phase == "containment" and self.contained_t is None:
            self.contained_t = t
        elif step.phase == "eradication" and self.eradicated_t is None:
            self.eradicated_t = t
        elif step.phase == "recovery" and self.recovered_t is None:
            self.recovered_t = t

        if not self.pending_steps():
            self.closed_t = t
        return record

    def to_dict(self) -> dict:
        return {
            "id": self.id, "category": self.category, "severity": self.severity,
            "title": self.title, "attacker_ip": self.attacker_ip,
            "target_ip": self.target_ip, "status": self.status,
            "detected_t": round(self.detected_t, 2),
            "contained_t": _r(self.contained_t),
            "eradicated_t": _r(self.eradicated_t),
            "recovered_t": _r(self.recovered_t),
            "closed_t": _r(self.closed_t),
            "sla_seconds": self.sla_seconds,
            "alerts": self.alerts,
            "executed": self.executed,
            "recommended": [
                {"id": s.id, "phase": s.phase, "action": s.action,
                 "description": s.description, "done": s.id in self.executed_ids}
                for s in self.recommended_steps
            ],
        }


def _r(v):
    return round(v, 2) if v is not None else None


_TITLES = {
    "port_scan": "Port scan against {t}",
    "dos": "Denial-of-service against {t}",
    "brute_force": "SSH brute force on {t}",
    "c2_beacon": "C2 beacon from {t}",
    "data_exfil": "Data exfiltration from {t}",
}


class IncidentManager:
    def __init__(self, correlation_window: float = 90.0):
        self.incidents: dict[str, Incident] = {}
        self._open_index: dict[tuple, str] = {}
        self._window = correlation_window
        self._seq = 0

    @staticmethod
    def _split(a: str, b: str) -> tuple[str, str]:
        """Return (adversary_ip, internal_asset_ip).

        Inbound attacks have the external host as source; egress activity
        (beacons, exfil) has the internal host as source. Either way we want the
        internal 10.20.0.x host to be the incident's asset.
        """
        a_int, b_int = a.startswith("10.20.0."), b.startswith("10.20.0.")
        if b_int and not a_int:
            return a, b
        if a_int and not b_int:
            return b, a
        return a, b

    def _key(self, adversary: str, asset: str, category: str) -> tuple:
        # DoS sources are often spoofed, so correlate those by asset only.
        if category == "dos":
            return (category, asset)
        return (category, adversary, asset)

    def ingest(self, alert: Alert) -> Incident:
        adversary, asset = self._split(alert.src_ip, alert.dst_ip)
        key = self._key(adversary, asset, alert.category)
        inc_id = self._open_index.get(key)
        inc = self.incidents.get(inc_id) if inc_id else None
        # correlate only into a still-open, recent incident
        if inc and inc.status != "closed" and alert.t - inc.detected_t <= self._window:
            inc.alerts.append(alert.to_dict())
            return inc

        self._seq += 1
        new_id = f"INC-{self._seq:03d}"
        inc = Incident(
            id=new_id, category=alert.category, severity=alert.severity,
            title=_TITLES.get(alert.category, "Security incident on {t}").format(
                t=asset),
            attacker_ip=adversary, target_ip=asset,
            detected_t=alert.t, recommended_steps=steps_for(alert.category),
            alerts=[alert.to_dict()],
        )
        self.incidents[new_id] = inc
        self._open_index[key] = new_id
        return inc

    def all(self) -> list[Incident]:
        return list(self.incidents.values())
