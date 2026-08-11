"""Attack scenarios.

Each scenario is a *campaign* that unfolds over simulated time and emits a
sequence of synthetic Events. Scenarios also declare the response playbook a
well-run SOC should execute, which is what the gap analysis grades against.

All traffic is fictional and generated in memory. IP addresses use
documentation ranges (RFC 5737 / RFC 3849-style private space) so nothing here
points at a real host.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable

from .models import Event

# Documentation / private ranges only — never real targets.
INTERNAL_NET = "10.20.0."
ATTACKER_POOL = ["203.0.113.7", "203.0.113.66", "198.51.100.23", "192.0.2.150"]


@dataclass
class Scenario:
    id: str
    name: str
    tactic: str                    # MITRE ATT&CK-style tactic label
    category: str                  # maps to a detection rule + playbook
    severity: str
    description: str
    attacker_ip: str
    target_ip: str
    build: Callable[["Scenario", float, random.Random], list[Event]]
    duration: float = 60.0         # sim-seconds the campaign spans

    def generate(self, start_t: float, rng: random.Random) -> list[Event]:
        events = self.build(self, start_t, rng)
        for e in events:
            e.scenario_id = self.id
        return events


def _mal(scn: Scenario, **kw) -> Event:
    kw.setdefault("label", "malicious")
    kw.setdefault("src_ip", scn.attacker_ip)
    kw.setdefault("dst_ip", scn.target_ip)
    return Event(**kw)


# ---------------------------------------------------------------------------
# Individual campaign builders
# ---------------------------------------------------------------------------
def _port_scan(scn, start_t, rng):
    """Reconnaissance: SYN sweep across many ports on one host."""
    ports = rng.sample(range(20, 1024), 40)
    out = []
    for i, p in enumerate(ports):
        out.append(_mal(scn, t=start_t + i * 0.4 + rng.uniform(0, 0.1),
                        kind="net", action="syn", dst_port=p,
                        meta={"flags": "S"}))
    return out


def _syn_flood(scn, start_t, rng):
    """Impact / DoS: a burst of SYNs to one service, some spoofed sources."""
    out = []
    n = 280
    spoofed = [f"203.0.113.{rng.randint(1, 254)}" for _ in range(6)]
    for i in range(n):
        src = rng.choice([scn.attacker_ip] + spoofed)
        out.append(_mal(scn, t=start_t + i * 0.05 + rng.uniform(0, 0.02),
                        kind="net", action="syn", src_ip=src,
                        dst_port=443, meta={"flags": "S"}))
    return out


def _brute_force(scn, start_t, rng):
    """Credential access: repeated SSH login failures, then one success."""
    out = []
    n = 50
    for i in range(n):
        out.append(_mal(scn, t=start_t + i * 0.6 + rng.uniform(0, 0.2),
                        kind="auth", action="login_fail", dst_port=22,
                        meta={"account": "root", "service": "ssh"}))
    # the campaign succeeds at the end — this is why fast containment matters
    out.append(_mal(scn, t=start_t + n * 0.6 + 1.0, kind="auth",
                    action="login_ok", dst_port=22,
                    meta={"account": "root", "service": "ssh"}))
    return out


def _c2_beacon(scn, start_t, rng):
    """Command & control: small, regular check-ins to an external host."""
    out = []
    interval = 4.0
    for i in range(14):
        jitter = rng.uniform(-0.15, 0.15)
        out.append(_mal(scn, t=start_t + i * interval + jitter,
                        src_ip=scn.target_ip, dst_ip=scn.attacker_ip,
                        kind="flow", action="connect", dst_port=8443,
                        bytes=rng.randint(180, 420),
                        meta={"note": "periodic beacon"}))
    return out


def _data_exfil(scn, start_t, rng):
    """Exfiltration: a large outbound transfer to an external host."""
    out = []
    # a short beacon precursor, then the bulk transfer
    for i in range(3):
        out.append(_mal(scn, t=start_t + i * 3.0, src_ip=scn.target_ip,
                        dst_ip=scn.attacker_ip, kind="flow", action="connect",
                        dst_port=8443, bytes=rng.randint(200, 400)))
    chunks = 8
    for i in range(chunks):
        out.append(_mal(scn, t=start_t + 10 + i * 1.5, src_ip=scn.target_ip,
                        dst_ip=scn.attacker_ip, kind="flow", action="transfer",
                        dst_port=8443, bytes=rng.randint(4_000_000, 9_000_000),
                        meta={"note": "bulk outbound"}))
    return out


# ---------------------------------------------------------------------------
# Scenario catalogue
# ---------------------------------------------------------------------------
def build_catalogue() -> dict[str, Scenario]:
    scns = [
        Scenario("port_scan", "Port Scan Sweep", "Reconnaissance", "port_scan",
                 "medium",
                 "External host probes 40+ ports on a web server to map exposed services.",
                 ATTACKER_POOL[0], INTERNAL_NET + "15", _port_scan, duration=18),
        Scenario("syn_flood", "SYN Flood (DoS)", "Impact", "dos", "high",
                 "A flood of half-open TCP connections targets the HTTPS service, "
                 "degrading availability.",
                 ATTACKER_POOL[1], INTERNAL_NET + "15", _syn_flood, duration=28),
        Scenario("ssh_brute", "SSH Brute Force", "Credential Access", "brute_force",
                 "high",
                 "Password guessing against SSH, culminating in a successful root login.",
                 ATTACKER_POOL[2], INTERNAL_NET + "22", _brute_force, duration=33),
        Scenario("c2_beacon", "Malware C2 Beacon", "Command & Control", "c2_beacon",
                 "high",
                 "A compromised host checks in to an external controller at a regular interval.",
                 ATTACKER_POOL[3], INTERNAL_NET + "40", _c2_beacon, duration=56),
        Scenario("data_exfil", "Data Exfiltration", "Exfiltration", "data_exfil",
                 "critical",
                 "Large volumes of data are pushed to an external endpoint over HTTPS.",
                 ATTACKER_POOL[3], INTERNAL_NET + "40", _data_exfil, duration=24),
    ]
    return {s.id: s for s in scns}
