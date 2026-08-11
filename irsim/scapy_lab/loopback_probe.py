"""OPTIONAL lab add-on — loopback-only packet generation with Scapy.

The main simulator is fully synthetic and needs none of this. This script is a
teaching aid for the *packet-crafting* side of the brief: it uses Scapy to emit
real TCP SYN packets and sniff them back, so you can watch genuine traffic and
adapt the detection logic to live packets in a lab.

SAFETY / SCOPE — read before running:
  * It only ever targets 127.0.0.1 (your own loopback). The target is hard-coded
    and the script refuses to run against anything else.
  * It sends a small, fixed number of packets to a port you control.
  * Raw sockets need root (sudo) and Scapy installed: pip install scapy.
  * Do not repurpose this to send traffic to hosts you do not own. Sending scan
    or flood traffic to systems without explicit authorisation is illegal in
    most jurisdictions and is not what this project is for.

Usage:
  # terminal 1 — a throwaway listener so the SYNs have somewhere to land:
  #   python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',9999));s.listen();\
  #               [s.accept() for _ in range(1)]"
  # terminal 2:
  sudo python3 loopback_probe.py --ports 20 --confirm
"""
from __future__ import annotations

import argparse
import sys

LOOPBACK = "127.0.0.1"


def main() -> int:
    ap = argparse.ArgumentParser(description="Loopback-only Scapy SYN demo.")
    ap.add_argument("--ports", type=int, default=15,
                    help="How many distinct loopback ports to touch (max 50).")
    ap.add_argument("--base-port", type=int, default=9000)
    ap.add_argument("--confirm", action="store_true",
                    help="Required. Acknowledges this only touches 127.0.0.1.")
    args = ap.parse_args()

    if not args.confirm:
        print("Refusing to run without --confirm. This tool only targets "
              "127.0.0.1 (your own loopback).")
        return 2

    try:
        from scapy.all import IP, TCP, sr1, sniff  # noqa: F401
    except ImportError:
        print("Scapy is not installed. Install it with: pip install scapy")
        return 1

    count = max(1, min(50, args.ports))
    print(f"[lab] Emitting {count} SYN packets to {LOOPBACK}:"
          f"{args.base_port}..{args.base_port + count - 1}")
    print("[lab] This mimics a port sweep so you can feed real packets into a "
          "Scapy-based detector — on loopback only.")

    for i in range(count):
        dport = args.base_port + i
        pkt = IP(dst=LOOPBACK) / TCP(dport=dport, flags="S")
        # timeout kept short; we don't care about the reply, only that a real
        # packet was crafted and put on the loopback interface.
        sr1(pkt, timeout=0.2, verbose=0)

    print("[lab] Done. Sniff the loopback interface (e.g. tcpdump -i lo) or wire "
          "a Scapy sniff() callback into engine/detection.py to score live "
          "traffic instead of synthetic events.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
