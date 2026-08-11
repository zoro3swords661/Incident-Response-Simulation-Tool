"use strict";

const $ = (id) => document.getElementById(id);
const PHASES = ["analysis", "containment", "eradication", "recovery"];
let selectedMode = "auto";
let pollTimer = null;

// ---------------------------------------------------------------- setup
async function loadCatalogue() {
  const scns = await (await fetch("/api/catalogue")).json();
  const list = $("scnList");
  list.innerHTML = "";
  for (const s of scns) {
    const el = document.createElement("label");
    el.className = "scn";
    el.innerHTML = `
      <input type="checkbox" value="${s.id}" checked>
      <div>
        <div class="name">${s.name} <span class="pill sev-${s.severity}">${s.severity}</span></div>
        <div class="desc">${s.description}</div>
      </div>
      <div class="tactic">${s.tactic}</div>`;
    list.appendChild(el);
  }
}

$("modeSeg").addEventListener("click", (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  selectedMode = b.dataset.mode;
  [...$("modeSeg").children].forEach((c) => c.classList.toggle("on", c === b));
});

$("speed").addEventListener("input", (e) => { $("speedVal").textContent = e.target.value; });

$("btnStart").addEventListener("click", async () => {
  const scenarios = [...document.querySelectorAll("#scnList input:checked")].map((c) => c.value);
  if (!scenarios.length) { alert("Select at least one scenario to inject."); return; }
  const seedRaw = $("seed").value.trim();
  const body = {
    scenarios, mode: selectedMode,
    speed: parseFloat($("speed").value),
    seed: seedRaw === "" ? null : (isNaN(+seedRaw) ? seedRaw : +seedRaw),
  };
  const r = await (await fetch("/api/start", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  })).json();
  if (!r.ok) { alert(r.message); return; }
  $("scorecard").classList.remove("show");
  startPolling();
});

$("btnStop").addEventListener("click", () => fetch("/api/stop", { method: "POST" }));
$("btnEnd").addEventListener("click", () => fetch("/api/finish", { method: "POST" }));

async function respond(incidentId, stepId) {
  await fetch("/api/respond", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ incident_id: incidentId, step_id: stepId }),
  });
  refresh();
}

// ---------------------------------------------------------------- polling
function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  refresh();
  pollTimer = setInterval(refresh, 700);
}

async function refresh() {
  let s;
  try { s = await (await fetch("/api/state")).json(); } catch { return; }
  render(s);
  if (s.finished && pollTimer) { clearInterval(pollTimer); pollTimer = null; refresh2(s); }
}
function refresh2(s) { render(s); }   // final paint

// ---------------------------------------------------------------- render
function render(s) {
  $("clock").textContent = s.sim_time.toFixed(1) + "s";
  $("clockEnd").textContent = "/ " + s.end_time.toFixed(1) + "s";
  $("progress").style.width = (s.finished ? 100 : s.progress) + "%";

  $("modeBadge").textContent = s.mode;
  $("speedBadge").textContent = s.speed.toFixed(0) + "×";
  const live = $("liveBadge");
  live.textContent = s.running ? "live" : (s.finished ? "complete" : "standby");
  live.className = "badge" + (s.running ? " live" : "");

  $("cEvents").textContent = s.counts.events;
  $("cAlerts").textContent = s.counts.alerts;
  const open = s.counts.incidents - (s.counts.by_status.closed || 0);
  $("cIncidents").textContent = open + " / " + s.counts.incidents;
  $("cScore").textContent = s.metrics ? s.metrics.resilience_score : "—";

  $("btnStart").disabled = s.running;
  $("btnStop").disabled = !s.running;
  $("btnEnd").disabled = !s.running;
  $("setup").style.display = s.running ? "none" : "block";

  renderIncidents(s);
  renderFeed(s);
  renderAlerts(s);
  renderConsole(s);
  if (s.finished && s.metrics) renderScorecard(s.metrics);
}

function renderIncidents(s) {
  const body = $("incBody");
  if (!s.incidents.length) {
    body.innerHTML = `<div class="empty">${s.running ? "Monitoring… no incidents detected yet." : "No incidents yet. Launch an exercise to begin."}</div>`;
    return;
  }
  const manual = s.mode === "manual" && s.running;
  body.innerHTML = s.incidents.map((i) => {
    const donePhases = new Set(i.executed.map((e) => e.phase));
    const pips = ["detection", ...PHASES].map((p) => {
      const done = p === "detection" ? true : donePhases.has(p);
      return `<div class="pip ${done ? "done" : ""}" title="${p}"></div>`;
    }).join("");
    const steps = i.recommended.map((st) => {
      const interactive = manual && !st.done;
      const cls = (st.done ? "done " : "") + (interactive ? "" : "ro");
      const click = interactive ? `onclick="respond('${i.id}','${st.id}')"` : "";
      return `<button class="step-btn ${cls}" ${click} title="${st.description}">
        <span class="ph">${st.phase}</span>${st.action}</button>`;
    }).join("");
    const mttc = i.contained_t !== null ? (i.contained_t - i.detected_t).toFixed(1) + "s" : "—";
    return `<div class="inc sev-${i.severity}">
      <div class="top">
        <div>
          <div class="id">${i.id} · detected T+${i.detected_t.toFixed(1)}s</div>
          <div class="title">${i.title}</div>
        </div>
        <div style="display:flex;gap:6px;align-items:center">
          <span class="pill sev-${i.severity}">${i.severity}</span>
          <span class="status ${i.status}">${i.status}</span>
        </div>
      </div>
      <div class="meta">adversary ${i.attacker_ip} → asset ${i.target_ip} · alerts ${i.alerts.length} · time-to-contain ${mttc} (SLA ${i.sla_seconds}s)</div>
      <div class="chain">${pips}</div>
      <div class="steps">${steps}</div>
      ${(!manual && s.running) ? `<div class="auto-note">Automated playbook executing…</div>` : ""}
    </div>`;
  }).join("");
}

function renderFeed(s) {
  const f = $("feed");
  if (!s.recent_events.length) { f.innerHTML = `<div class="empty">idle</div>`; return; }
  f.innerHTML = s.recent_events.map((e) => `
    <div class="row">
      <span class="t">${e.t.toFixed(1)}</span>
      <span class="k">${e.kind}</span>
      <span>${e.src_ip} → ${e.dst_ip}${e.dst_port ? ":" + e.dst_port : ""} · ${e.action}${e.bytes ? " · " + fmtBytes(e.bytes) : ""}</span>
    </div>`).join("");
}

function renderAlerts(s) {
  const f = $("alertFeed");
  if (!s.recent_alerts.length) { f.innerHTML = `<div class="empty">idle</div>`; return; }
  f.innerHTML = s.recent_alerts.map((a) => `
    <div class="row sev-${a.severity}">
      <span class="t">${a.t.toFixed(1)}</span>
      <span class="msg">${a.summary}</span>
    </div>`).join("");
}

function renderConsole(s) {
  const c = $("console");
  if (!s.log.length) { c.innerHTML = `<div class="empty">idle</div>`; return; }
  c.innerHTML = s.log.map((l) => `<div class="line"><span class="t">T+${l.t.toFixed(1)}</span>${escapeHtml(l.msg)}</div>`).join("");
}

// ---------------------------------------------------------------- scorecard
function renderScorecard(m) {
  const card = $("scorecard");
  card.classList.add("show");

  const R = 70, C = 2 * Math.PI * R;
  const frac = Math.max(0, Math.min(1, m.resilience_score / 100));
  const color = m.resilience_score >= 70 ? "var(--ok)" : m.resilience_score >= 40 ? "var(--med)" : "var(--crit)";
  $("dial").innerHTML = `
    <svg width="170" height="170" viewBox="0 0 170 170">
      <circle cx="85" cy="85" r="${R}" fill="none" stroke="var(--line-soft)" stroke-width="12"/>
      <circle cx="85" cy="85" r="${R}" fill="none" stroke="${color}" stroke-width="12"
        stroke-linecap="round" stroke-dasharray="${C}" stroke-dashoffset="${C * (1 - frac)}"/>
    </svg>
    <div style="margin-top:-115px">
      <div class="val">${m.resilience_score}</div>
      <div class="grade">GRADE ${m.grade}</div>
    </div>
    <div style="height:70px"></div>`;

  const fmt = (v, suf = "") => v === null || v === undefined ? "—" : v + suf;
  $("metricline").innerHTML = `
    ${metric("Detection rate", Math.round(m.detection_rate * 100) + "%")}
    ${metric("Mean time to detect", fmt(m.avg_mttd, "s"))}
    ${metric("Mean time to contain", fmt(m.avg_mttc, "s"))}
    ${metric("Response completeness", Math.round(m.avg_completeness * 100) + "%")}`;

  const comps = [
    ["Detection", m.components.detection, 35],
    ["Speed / SLA", m.components.speed, 30],
    ["Completeness", m.components.completeness, 25],
    ["Recovery", m.components.recovery, 10],
  ];
  $("components").innerHTML = comps.map(([lab, val, max]) => `
    <div class="comp">
      <span class="lab">${lab}</span>
      <span class="bar"><i style="width:${(val / max) * 100}%"></i></span>
      <span class="num">${val}/${max}</span>
    </div>`).join("");

  const gaps = $("gaps");
  if (!m.gaps.length) {
    gaps.innerHTML = `<div class="clean">✓ No gaps identified — every incident was detected, contained within SLA, and fully remediated.</div>`;
  } else {
    gaps.innerHTML = m.gaps.map((g) => `
      <div class="gap sev-${g.severity}">
        <div class="gt">${g.title} <span class="pill sev-${g.severity}">${g.severity}</span></div>
        <div class="gd">${g.detail}</div>
        <div class="gr">${g.recommendation}</div>
      </div>`).join("");
  }
}

function metric(k, v) {
  return `<div class="m"><div class="k">${k}</div><div class="v">${v}</div></div>`;
}

// ---------------------------------------------------------------- utils
function fmtBytes(b) {
  if (b >= 1e6) return (b / 1e6).toFixed(1) + "MB";
  if (b >= 1e3) return (b / 1e3).toFixed(0) + "KB";
  return b + "B";
}
function escapeHtml(x) {
  return x.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

// boot
loadCatalogue();
refresh();
