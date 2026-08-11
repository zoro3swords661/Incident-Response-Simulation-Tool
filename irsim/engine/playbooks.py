"""Automated response playbooks.

Each incident category has an ordered playbook of steps, tagged with the NIST
lifecycle phase they belong to. In AUTO mode the simulator executes these with
realistic delays and measures how fast containment happened. In MANUAL mode the
analyst triggers steps from the UI, and any recommended step left un-executed
becomes a documented gap.

Every "action" here is *simulated* — it records that a containment decision was
made and updates incident state. The tool never reaches out to a real firewall,
host, or account.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Step:
    id: str
    phase: str              # analysis | containment | eradication | recovery
    action: str             # short imperative label
    description: str
    auto_seconds: float     # how long it takes when run automatically
    primary: bool = False   # the step that marks the phase "achieved"


PLAYBOOKS: dict[str, list[Step]] = {
    "port_scan": [
        Step("enrich", "analysis", "Enrich source",
             "Look up reputation and geolocation for the scanning host.", 2),
        Step("block_ip", "containment", "Block source IP",
             "Add the source to the perimeter firewall deny list.", 3, primary=True),
        Step("harden", "eradication", "Reduce attack surface",
             "Close or restrict exposed non-essential ports.", 5, primary=True),
        Step("verify", "recovery", "Verify & monitor",
             "Confirm services are healthy and watch for a repeat scan.", 4, primary=True),
    ],
    "dos": [
        Step("scope", "analysis", "Identify target",
             "Pin down the targeted service and contributing source IPs.", 2),
        Step("rate_limit", "containment", "Enable rate limiting",
             "Turn on SYN cookies / rate limiting at the edge.", 3, primary=True),
        Step("block_src", "containment", "Block sources",
             "Blackhole or block the offending source addresses.", 3),
        Step("scrub", "eradication", "Engage scrubbing",
             "Route traffic through upstream / CDN scrubbing.", 5, primary=True),
        Step("restore", "recovery", "Restore capacity",
             "Confirm latency and availability are back to baseline.", 4, primary=True),
    ],
    "brute_force": [
        Step("scope", "analysis", "Scope the account",
             "Identify the targeted account(s) and source of the attempts.", 2),
        Step("lock", "containment", "Lock account",
             "Disable the targeted account to stop further guessing.", 2, primary=True),
        Step("block_ip", "containment", "Block source IP",
             "Block the source address at the firewall.", 2),
        Step("rotate", "eradication", "Rotate credentials",
             "Force a password reset and revoke active sessions.", 4, primary=True),
        Step("persist", "eradication", "Check for persistence",
             "Inspect for new SSH keys or backdoors from the successful login.", 5),
        Step("reenable", "recovery", "Re-enable with MFA",
             "Restore the account behind MFA and monitor.", 4, primary=True),
    ],
    "c2_beacon": [
        Step("scope", "analysis", "Identify host & C2",
             "Identify the beaconing host and the external controller.", 2),
        Step("isolate", "containment", "Isolate host",
             "Network-isolate the compromised host.", 3, primary=True),
        Step("block_c2", "containment", "Block C2",
             "Block the controller domain/IP at DNS and firewall.", 2),
        Step("remove", "eradication", "Remove implant",
             "Terminate the malicious process and remove the implant.", 6, primary=True),
        Step("reimage", "recovery", "Reimage host",
             "Rebuild or restore the host from a known-good image.", 6, primary=True),
    ],
    "data_exfil": [
        Step("assess", "analysis", "Assess exposure",
             "Determine what data and how much volume left the environment.", 3),
        Step("block_egress", "containment", "Block egress",
             "Block outbound traffic to the external endpoint.", 3, primary=True),
        Step("isolate", "containment", "Isolate source",
             "Isolate the host that is exfiltrating data.", 2),
        Step("revoke", "eradication", "Revoke access",
             "Revoke the credentials and tokens used in the transfer.", 4, primary=True),
        Step("breach", "recovery", "Start breach process",
             "Trigger the breach-response process and restore monitoring.", 5, primary=True),
    ],
}


def steps_for(category: str) -> list[Step]:
    return PLAYBOOKS.get(category, [])
