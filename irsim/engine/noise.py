"""Benign background traffic.

Real SOCs don't operate in a vacuum — normal user and server traffic runs
alongside any attack. Injecting benign noise means detection rules have a
chance to raise *false positives*, which the scorecard tracks. It keeps the
exercise honest.
"""
from __future__ import annotations

import random

from .models import Event

INTERNAL = "10.20.0."
COMMON_DST = ["93.184.216.34", "140.82.112.3", "151.101.1.140", "8.8.8.8"]


def generate_noise(start_t: float, span: float, rng: random.Random,
                   rate: float = 0.8) -> list[Event]:
    """Produce roughly `rate` benign events per sim-second across the window."""
    out: list[Event] = []
    n = int(span * rate)
    for _ in range(n):
        t = start_t + rng.uniform(0, span)
        host = f"{INTERNAL}{rng.randint(10, 60)}"
        roll = rng.random()
        if roll < 0.55:                      # ordinary outbound web/flow
            out.append(Event(t=t, kind="flow", action="connect", src_ip=host,
                             dst_ip=rng.choice(COMMON_DST), dst_port=443,
                             bytes=rng.randint(500, 60_000), label="benign"))
        elif roll < 0.8:                     # a couple of connections to a few ports
            for p in rng.sample([80, 443, 53, 123], rng.randint(1, 2)):
                out.append(Event(t=t, kind="net", action="syn", src_ip=host,
                                 dst_ip=rng.choice(COMMON_DST), dst_port=p,
                                 label="benign"))
        elif roll < 0.93:                    # an occasional mistyped-password login
            out.append(Event(t=t, kind="auth", action="login_fail", src_ip=host,
                             dst_ip=f"{INTERNAL}22", dst_port=22,
                             meta={"account": rng.choice(["alice", "bob"])},
                             label="benign"))
        else:                                # a normal-sized backup transfer
            out.append(Event(t=t, kind="flow", action="transfer", src_ip=host,
                             dst_ip=rng.choice(COMMON_DST), dst_port=443,
                             bytes=rng.randint(200_000, 900_000), label="benign"))
    return out
