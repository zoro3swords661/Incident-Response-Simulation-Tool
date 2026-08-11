"""Simulation orchestrator.

Ties the pieces together and runs a simulation on a background thread:
generate telemetry -> stream it through detection -> correlate into incidents
-> (auto mode) run playbooks on a timer, or (manual mode) wait for the analyst
-> score the exercise. A lock guards all shared state so the Flask request
threads can read a consistent snapshot at any time.
"""
from __future__ import annotations

import random
import threading
import time

from . import metrics
from .detection import DetectionEngine
from .incident import IncidentManager
from .noise import generate_noise
from .scenarios import build_catalogue

TICK_REAL = 0.1          # seconds of real time per loop
TRIAGE_DELAY = 2.5       # sim-seconds before automated response begins
FEED_CAP = 60            # rows kept for the live UI feeds


class SimulationManager:
    def __init__(self):
        self.catalogue = build_catalogue()
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._reset_state()

    # ------------------------------------------------------------------ setup
    def _reset_state(self):
        self.mode = "auto"
        self.speed = 8.0
        self.running = False
        self.finished = False
        self.sim_time = 0.0
        self.end_time = 0.0
        self.events = []           # full timeline (sorted)
        self._idx = 0
        self.injected = []         # ground truth for scoring
        self.recent_events = []
        self.alerts = []
        self.detector = DetectionEngine()
        self.incidents = IncidentManager()
        self.log = []
        self.metrics = None
        self._scheduled_ids = set()
        self.events_seen = 0

    def catalogue_list(self) -> list[dict]:
        return [{"id": s.id, "name": s.name, "tactic": s.tactic,
                 "category": s.category, "severity": s.severity,
                 "description": s.description} for s in self.catalogue.values()]

    # ---------------------------------------------------------------- control
    def start(self, scenario_ids, mode="auto", speed=8.0, seed=None):
        with self._lock:
            if self.running:
                return False, "A simulation is already running."
            ids = [s for s in scenario_ids if s in self.catalogue] or \
                list(self.catalogue.keys())
            self._reset_state()
            self.mode = "manual" if mode == "manual" else "auto"
            self.speed = max(1.0, min(40.0, float(speed)))
            rng = random.Random(seed)
            self._build_timeline(ids, rng)
            self.running = True
            self._log(f"Exercise started — {len(ids)} scenario(s), "
                      f"{self.mode} mode, {self.speed:.0f}x speed.")
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return True, "started"

    def _build_timeline(self, ids, rng):
        all_events = []
        cursor = 3.0
        for sid in ids:
            scn = self.catalogue[sid]
            evs = scn.generate(cursor, rng)
            first_mal = min(e.t for e in evs if e.label == "malicious")
            self.injected.append({
                "scenario_id": scn.id, "name": scn.name,
                "category": scn.category, "severity": scn.severity,
                "attacker_ip": scn.attacker_ip, "target_ip": scn.target_ip,
                "first_event_t": first_mal,
            })
            all_events.extend(evs)
            cursor += 6.0          # stagger campaign starts
        span = max((e.t for e in all_events), default=10.0) + 5.0
        all_events.extend(generate_noise(0.0, span, rng, rate=0.7))
        all_events.sort(key=lambda e: e.t)
        self.events = all_events
        self.end_time = span + 25.0    # tail for automated responses to finish

    def stop(self):
        with self._lock:
            if self.running:
                self._finish("stopped by operator")

    # -------------------------------------------------------------- main loop
    def _run(self):
        while True:
            time.sleep(TICK_REAL)
            with self._lock:
                if not self.running:
                    break
                self.sim_time += self.speed * TICK_REAL
                self._drain_events()
                if self.mode == "auto":
                    self._run_auto_responses()
                if self._should_finish():
                    self._finish("all events processed")
                    break

    def _drain_events(self):
        while self._idx < len(self.events) and \
                self.events[self._idx].t <= self.sim_time:
            e = self.events[self._idx]
            self._idx += 1
            self.events_seen += 1
            self.recent_events.append(e.as_row())
            self.recent_events = self.recent_events[-FEED_CAP:]
            for alert in self.detector.process(e):
                self.alerts.append(alert.to_dict())
                inc = self.incidents.ingest(alert)
                self._log(f"ALERT [{alert.severity}] {alert.summary} "
                          f"→ {inc.id}", t=alert.t)
                if self.mode == "auto" and inc.id not in self._scheduled_ids:
                    self._schedule_auto(inc)

    def _schedule_auto(self, inc):
        self._scheduled_ids.add(inc.id)
        t = inc.detected_t + TRIAGE_DELAY
        sched = []
        for step in inc.recommended_steps:
            t += step.auto_seconds
            sched.append([t, step])
        inc._schedule = sched

    def _run_auto_responses(self):
        for inc in self.incidents.all():
            if not inc._schedule:
                continue
            remaining = []
            for exec_t, step in inc._schedule:
                if exec_t <= self.sim_time:
                    rec = inc.execute_step(step.id, exec_t, "auto")
                    if rec:
                        self._log(f"RESPONSE {inc.id} [{step.phase}] "
                                  f"{step.action}", t=exec_t)
                else:
                    remaining.append([exec_t, step])
            inc._schedule = remaining

    def _should_finish(self) -> bool:
        events_done = self._idx >= len(self.events)
        if self.mode == "auto":
            pending = any(i._schedule for i in self.incidents.all())
            return events_done and not pending and self.sim_time >= self.end_time - 20
        # manual: keep clock running for the analyst, but cap runaway time
        return events_done and self.sim_time >= self.end_time + 90

    def _finish(self, reason):
        self.running = False
        self.finished = True
        self.metrics = metrics.compute(self.injected, self.incidents.all(),
                                       self.alerts)
        self._log(f"Exercise complete ({reason}). "
                  f"Resilience score {self.metrics['resilience_score']} "
                  f"(grade {self.metrics['grade']}).")

    # --------------------------------------------------- analyst (manual mode)
    def respond(self, incident_id, step_id):
        with self._lock:
            inc = self.incidents.incidents.get(incident_id)
            if not inc:
                return False, "Unknown incident."
            rec = inc.execute_step(step_id, self.sim_time, "manual")
            if not rec:
                return False, "Step already done or invalid."
            self._log(f"RESPONSE {inc.id} [{rec['phase']}] {rec['action']} "
                      f"(analyst)", t=self.sim_time)
            return True, rec

    def finish_now(self):
        with self._lock:
            if self.running or not self.finished:
                self._finish("ended by analyst")
            return self.metrics

    def _log(self, msg, t=None):
        stamp = t if t is not None else self.sim_time
        self.log.append({"t": round(stamp, 2), "msg": msg})
        self.log = self.log[-200:]

    # ------------------------------------------------------------- snapshot
    def snapshot(self) -> dict:
        with self._lock:
            by_status = {}
            for inc in self.incidents.all():
                by_status[inc.status] = by_status.get(inc.status, 0) + 1
            progress = 0.0
            if self.end_time:
                progress = min(100.0, 100.0 * self.sim_time / self.end_time)
            return {
                "running": self.running, "finished": self.finished,
                "mode": self.mode, "speed": self.speed,
                "sim_time": round(self.sim_time, 1),
                "end_time": round(self.end_time, 1),
                "progress": round(progress, 1),
                "counts": {
                    "events": self.events_seen,
                    "alerts": len(self.alerts),
                    "incidents": len(self.incidents.incidents),
                    "by_status": by_status,
                },
                "recent_events": list(reversed(self.recent_events[-25:])),
                "recent_alerts": list(reversed(self.alerts[-15:])),
                "incidents": [i.to_dict() for i in self.incidents.all()],
                "log": list(reversed(self.log[-40:])),
                "metrics": self.metrics,
            }
