"""Scoring and gap analysis.

Given the ground truth (which attacks were actually injected) and what the SOC
did (detections, incidents, response actions), this produces the exercise
scorecard: detection rate, mean-time-to-detect / -contain / -recover, response
completeness, an overall resilience score, and a prioritised list of gaps.
"""
from __future__ import annotations

from statistics import mean

from .incident import Incident


def _match(scn: dict, incidents: list[Incident]) -> Incident | None:
    """Find the incident that corresponds to an injected scenario."""
    scn_ips = {scn["target_ip"], scn["attacker_ip"]}
    cands = [i for i in incidents
             if i.category == scn["category"]
             and ({i.target_ip, i.attacker_ip} & scn_ips)]
    return min(cands, key=lambda i: i.detected_t) if cands else None


def compute(injected: list[dict], incidents: list[Incident],
            all_alerts: list[dict]) -> dict:
    per_scenario = []
    mttd_vals, mttc_vals, recover_vals, completeness_vals = [], [], [], []
    detected = 0

    for scn in injected:
        inc = _match(scn, incidents)
        row = {"scenario_id": scn["scenario_id"], "name": scn["name"],
               "category": scn["category"], "severity": scn["severity"],
               "target_ip": scn["target_ip"], "detected": inc is not None}
        if inc:
            detected += 1
            inc.first_event_t = scn["first_event_t"]
            mttd = inc.detected_t - scn["first_event_t"]
            mttd_vals.append(mttd)
            row["mttd"] = round(mttd, 2)
            row["incident_id"] = inc.id
            row["status"] = inc.status
            if inc.contained_t is not None:
                mttc = inc.contained_t - inc.detected_t
                mttc_vals.append(mttc)
                row["mttc"] = round(mttc, 2)
                row["sla_met"] = mttc <= inc.sla_seconds
            else:
                row["mttc"] = None
                row["sla_met"] = False
            if inc.recovered_t is not None:
                recover_vals.append(inc.recovered_t - inc.detected_t)
            total = len(inc.recommended_steps) or 1
            comp = len(inc.executed_ids & {s.id for s in inc.recommended_steps}) / total
            completeness_vals.append(comp)
            row["completeness"] = round(comp, 2)
        per_scenario.append(row)

    n_injected = len(injected) or 1
    detection_rate = detected / n_injected
    false_positives = [a for a in all_alerts if a.get("truth") == "benign"]
    fp_rate = len(false_positives) / (len(all_alerts) or 1)

    avg_mttd = mean(mttd_vals) if mttd_vals else None
    avg_mttc = mean(mttc_vals) if mttc_vals else None
    avg_recover = mean(recover_vals) if recover_vals else None
    avg_completeness = mean(completeness_vals) if completeness_vals else 0.0

    # --- resilience score (0..100) --------------------------------------
    det_component = detection_rate * 35 - min(10, fp_rate * 40)
    det_component = max(0.0, det_component)

    if mttc_vals:
        sla_hits = [1 for scn in per_scenario if scn.get("sla_met")]
        speed_component = (len(sla_hits) / n_injected) * 30
    else:
        speed_component = 0.0

    completeness_component = avg_completeness * 25
    recovered = sum(1 for i in incidents if i.recovered_t is not None)
    recovery_component = (recovered / n_injected) * 10

    score = round(det_component + speed_component +
                  completeness_component + recovery_component, 1)
    grade = ("A" if score >= 85 else "B" if score >= 70 else
             "C" if score >= 55 else "D" if score >= 40 else "F")

    return {
        "detection_rate": round(detection_rate, 3),
        "detected": detected, "injected": len(injected),
        "false_positives": len(false_positives),
        "false_positive_rate": round(fp_rate, 3),
        "avg_mttd": _r(avg_mttd), "avg_mttc": _r(avg_mttc),
        "avg_recover": _r(avg_recover),
        "avg_completeness": round(avg_completeness, 3),
        "resilience_score": score, "grade": grade,
        "components": {
            "detection": round(det_component, 1),
            "speed": round(speed_component, 1),
            "completeness": round(completeness_component, 1),
            "recovery": round(recovery_component, 1),
        },
        "per_scenario": per_scenario,
        "gaps": _gaps(per_scenario, incidents, false_positives),
    }


def _gaps(per_scenario, incidents, false_positives) -> list[dict]:
    gaps = []
    for scn in per_scenario:
        if not scn["detected"]:
            gaps.append({
                "severity": "critical", "type": "undetected",
                "title": f"Missed detection: {scn['name']}",
                "detail": f"The {scn['category']} campaign against "
                          f"{scn['target_ip']} was never detected.",
                "recommendation": "Add or tune a detection rule for this "
                                  "technique and lower its threshold/window.",
            })
    for inc in incidents:
        if inc.contained_t is None:
            gaps.append({
                "severity": "high", "type": "no_containment",
                "title": f"{inc.id} not contained",
                "detail": f"No containment action was taken for "
                          f"'{inc.title}'.",
                "recommendation": "Execute the containment step from the "
                                  "playbook (e.g. block/isolate).",
            })
        elif (inc.contained_t - inc.detected_t) > inc.sla_seconds:
            gaps.append({
                "severity": "high", "type": "sla_breach",
                "title": f"{inc.id} missed containment SLA",
                "detail": f"Contained in "
                          f"{inc.contained_t - inc.detected_t:.1f}s vs "
                          f"{inc.sla_seconds:.0f}s target.",
                "recommendation": "Automate the primary containment step or "
                                  "pre-approve it for this severity.",
            })
        pending = inc.pending_steps()
        if inc.contained_t is not None and pending:
            gaps.append({
                "severity": "medium", "type": "incomplete",
                "title": f"{inc.id} response incomplete",
                "detail": "Skipped steps: " +
                          ", ".join(s.action for s in pending) + ".",
                "recommendation": "Complete eradication and recovery so the "
                                  "incident can be closed out.",
            })
    if len(false_positives) >= 3:
        gaps.append({
            "severity": "low", "type": "false_positive",
            "title": f"{len(false_positives)} false-positive alerts",
            "detail": "Benign traffic triggered alerts, adding analyst noise.",
            "recommendation": "Raise thresholds or add allow-lists to reduce "
                              "alert fatigue.",
        })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    gaps.sort(key=lambda g: order.get(g["severity"], 9))
    return gaps


def _r(v):
    return round(v, 2) if v is not None else None
