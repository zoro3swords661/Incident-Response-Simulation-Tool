# IR-SIM — Cybersecurity Incident Response Simulation Tool

A self-contained tool for **running incident-response drills**. It generates
synthetic security telemetry, detects attacks as they unfold, and then either
runs the response playbooks automatically or hands the console to a human
analyst — finishing with an after-action scorecard that quantifies detection
speed, containment speed, response completeness, and the specific gaps to fix.

The point of the exercise is *response*, not attack. Every event is generated in
memory — the tool never touches a real network, host, or account — so it is safe
to run anywhere and legal to run without any authorisation paperwork.

---

## Why this design

Most "incident simulators" are really attack scripts. A real IR exercise cares
about a different question: **when something bad happens, how well and how fast
does the SOC respond?** IR-SIM models the whole loop —

```
scenario → telemetry → detection → incident → response (auto/manual) → score
```

— which lets it surface the things that actually matter in a drill: missed
detections, SLA breaches, half-finished remediations, and alert fatigue.

---

## Quick start

```bash
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000
```

1. Pick which attack scenarios to inject.
2. Choose **Automated** (the tool responds and you watch) or
   **Manual (analyst)** (you triage and click the response steps live).
3. Set a speed multiplier and an optional seed for reproducible runs.
4. Launch. Watch the telemetry stream, alerts, and incidents in real time.
5. In manual mode, click **End & score** when you're done. The after-action
   report appears with your resilience score and a prioritised list of gaps.

---

## What's in the box

Five attack scenarios, each mapped to a detection rule and a NIST-aligned
response playbook:

| Scenario | Tactic | Detection signal | Severity |
|---|---|---|---|
| Port Scan Sweep | Reconnaissance | many distinct ports from one source in a window | medium |
| SYN Flood (DoS) | Impact | SYN rate to one service crosses threshold | high |
| SSH Brute Force | Credential Access | failed-login count per account/host | high |
| Malware C2 Beacon | Command & Control | regular, low-jitter check-ins to an external host | high |
| Data Exfiltration | Exfiltration | large outbound volume to an external endpoint | critical |

Benign background traffic runs alongside the attacks, so detection rules can
raise false positives — which the scorecard tracks.

---

## Architecture

```
app.py                     Flask routes + JSON API
engine/
  models.py                Event and Alert data models
  scenarios.py             Attack campaigns (emit timed synthetic events)
  noise.py                 Benign background traffic
  detection.py             Sliding-window detection rules → alerts
  incident.py              Correlate alerts → incidents; track NIST lifecycle
  playbooks.py             Response steps per category (analysis→recovery)
  metrics.py               Scoring + gap analysis (the after-action report)
  simulator.py             Background-thread orchestrator + thread-safe state
templates/index.html       Situation-room dashboard
static/style.css, app.js   UI styling + live polling client
scapy_lab/loopback_probe.py  OPTIONAL real-packet demo (loopback only)
```

The Flask request threads never touch engine state directly — they read a
consistent snapshot behind a lock while the simulation advances on its own
thread.

### Incident lifecycle (NIST SP 800-61)

```
detection → analysis → containment → eradication → recovery → closed
```

Each playbook step is tagged with the phase it belongs to. The first containment
action stamps the containment time (used for the SLA); recovery closes the loop.

### Scoring model

The **resilience score** (0–100) blends four components:

| Component | Weight | Measures |
|---|---|---|
| Detection | 35 | share of injected attacks detected, minus a false-positive penalty |
| Speed / SLA | 30 | share of incidents contained within their severity SLA |
| Completeness | 25 | fraction of recommended playbook steps actually executed |
| Recovery | 10 | fraction of incidents driven all the way to recovery |

Containment SLAs (in simulation-seconds): critical 20 · high 30 · medium 60 ·
low 120. The **gap analysis** lists undetected attacks, missed SLAs, incomplete
responses, and false-positive noise, each with a concrete recommendation.

---

## Extending it

- **Add a scenario:** write a campaign builder in `engine/scenarios.py`, add it
  to the catalogue, and (if it's a new attack type) add a matching rule in
  `engine/detection.py` and a playbook in `engine/playbooks.py`.
- **Tune detection:** every rule exposes `WINDOW` / `THRESHOLD` constants — the
  scorecard's MTTD and false-positive count show the effect of changes.
- **Feed real packets:** `scapy_lab/loopback_probe.py` crafts genuine TCP SYNs
  on `127.0.0.1` so you can wire a Scapy `sniff()` callback into the detection
  engine and score live loopback traffic instead of synthetic events.

---

## Scope & safety

- The simulator is **100% synthetic** and offline. IP addresses use documentation
  and private ranges only.
- The optional Scapy module is **hard-coded to loopback (127.0.0.1)** and refuses
  other targets. Do not adapt it to send scan or flood traffic to hosts you don't
  own — that's illegal without explicit authorisation and outside this project's
  purpose.
- The bundled Flask server is the development server; put it behind a real WSGI
  server (gunicorn/uWSGI) if you ever expose it beyond localhost.
