"""IR-SIM — Cybersecurity Incident Response Simulation Tool.

Flask front end over the self-contained simulation engine. The engine generates
synthetic security telemetry, detects incidents, and either auto-runs response
playbooks or lets a human analyst respond live — then scores the exercise.

Run:  python app.py   ->  http://127.0.0.1:5000
"""
from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from engine import SimulationManager

app = Flask(__name__)
sim = SimulationManager()          # single shared simulation instance


@app.route("/")
def index():
    return render_template("index.html")


@app.get("/api/catalogue")
def catalogue():
    return jsonify(sim.catalogue_list())


@app.get("/api/state")
def state():
    return jsonify(sim.snapshot())


@app.post("/api/start")
def start():
    data = request.get_json(silent=True) or {}
    ok, msg = sim.start(
        scenario_ids=data.get("scenarios", []),
        mode=data.get("mode", "auto"),
        speed=data.get("speed", 8.0),
        seed=data.get("seed"),
    )
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 409)


@app.post("/api/respond")
def respond():
    data = request.get_json(silent=True) or {}
    ok, result = sim.respond(data.get("incident_id"), data.get("step_id"))
    return jsonify({"ok": ok, "result": result}), (200 if ok else 400)


@app.post("/api/stop")
def stop():
    sim.stop()
    return jsonify({"ok": True})


@app.post("/api/finish")
def finish():
    return jsonify({"ok": True, "metrics": sim.finish_now()})


if __name__ == "__main__":
    # threaded=True so the background simulation loop and API requests coexist.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
