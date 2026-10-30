// UI. Never put uploaded text into the page as HTML (CI checks for this).
import { triage, summarise, caseKey, LABEL, VERDICTS, THRESHOLDS, SIGNAL_CATALOG } from "./engine.js";
import { parseAlerts, normalize, toCSV, TEMPLATE_HEADERS, LIMITS, InputError } from "./parse.js";
import { defaultContext } from "./context.js";
import { SAMPLE_ALERTS } from "./sample.js";

const SVGNS = "http://www.w3.org/2000/svg";
const $ = id => document.getElementById(id);

/** Build an element. Children that are strings become text nodes, never HTML. */
function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (/^on|^style$|^srcdoc$/i.test(k)) throw new Error(`Refusing unsafe attribute "${k}"`);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
function svg(tag, attrs = {}, text) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  if (text != null) el.textContent = String(text);
  return el;
}

const state = {
  ctx: defaultContext(),
  alerts: [],
  items: [],
  datasetName: "",
  sel: null,
  filter: "all",
  dec: Object.create(null),
  ovOpen: false,
};

const byId = id => state.items.find(it => it.alert.id === id);

function rescore() {
  state.items = triage(state.alerts, state.ctx);
  const order = { mal: 0, rev: 1, ben: 2 };
  state.items.sort((x, y) => order[x.result.verdict] - order[y.result.verdict] || (y.alert.ts ?? 0) - (x.alert.ts ?? 0));
}

function load(alerts, name) {
  state.ctx = defaultContext();
  state.alerts = alerts;
  state.datasetName = name;
  state.dec = Object.create(null);
  state.filter = "all";
  state.ovOpen = false;
  rescore();
  state.sel = state.items[0]?.alert.id ?? null;
  hideError();
  renderAll();
}

function showError(msg) { const e = $("error"); e.textContent = msg; e.hidden = false; }
function hideError() { $("error").hidden = true; }

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("on");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("on"), 2600);
}

/* ---------- KPIs ---------- */
function kpi(label, value, note) {
  return h("div", { class: "kpi" }, h("span", { class: "label", text: label }), h("span", { class: "value", text: value }), h("span", { class: "note", text: note }));
}
function minutes() {
  const b = Number($("min-before").value), a = Number($("min-after").value);
  return { before: Number.isFinite(b) && b > 0 ? b : 17, after: Number.isFinite(a) && a >= 0 ? a : 4 };
}
function renderKpis() {
  const m = minutes();
  const s = summarise(state.items, state.dec, m.before, m.after);
  $("kpis").replaceChildren(
    kpi("In queue", String(s.total), `${s.rawTotal} raw alerts after merging repeats`),
    kpi("Likely malicious", String(s.byVerdict.mal), "work these first"),
    kpi("Needs review", String(s.byVerdict.rev), `includes anything under ${THRESHOLDS.minConfidence} confidence`),
    kpi("Likely benign", String(s.byVerdict.ben), "confirm in one click"),
  );
  $("rkpis").replaceChildren(
    kpi("Decided by analysts", `${s.decided} of ${s.total}`, s.decided ? "this session" : "agree or override alerts in the queue"),
    kpi("Agreement with engine", s.agreeRate == null ? "–" : `${s.agreeRate}%`, `${s.overrides} override${s.overrides === 1 ? "" : "s"} · target ≥ 85%`),
    kpi("Analyst hours saved", `${s.hoursSaved.toFixed(1)} h`, `${s.hoursProjected.toFixed(1)} h if the whole queue is decided`),
    kpi("AI-instruction attempts", String(s.injections), "flagged and ignored"),
  );
}

/* ---------- Queue ---------- */
function renderChips() {
  const counts = { all: state.items.length, mal: 0, rev: 0, ben: 0 };
  for (const it of state.items) counts[it.result.verdict]++;
  const opts = [["all", "All"], ["mal", "Malicious"], ["rev", "Review"], ["ben", "Benign"]];
  $("chips").replaceChildren(...opts.map(([k, l]) =>
    h("button", { class: "chip", type: "button", "aria-pressed": String(state.filter === k), onclick: () => { state.filter = k; renderChips(); renderList(); } }, `${l} ${counts[k]}`)));
}

function renderList() {
  const list = $("list");
  if (!state.items.length) {
    list.replaceChildren(h("div", { class: "empty" }, h("strong", { text: "No alerts loaded" }), "Load the sample data or upload a CSV or JSON export from your SIEM."));
    $("qcount").textContent = "";
    return;
  }
  const open = state.items.filter(it => !state.dec[it.alert.id]).length;
  $("qcount").textContent = `${open} open of ${state.items.length}`;
  const nodes = [];
  for (const v of VERDICTS) {
    if (state.filter !== "all" && state.filter !== v) continue;
    const group = state.items.filter(it => it.result.verdict === v);
    nodes.push(h("div", { class: "group-label" }, h("span", { text: LABEL[v] }), h("span", { text: String(group.length) })));
    for (const { alert: a, result: r } of group) {
      const d = state.dec[a.id];
      nodes.push(h("button", {
        class: `row${d ? " done" : ""}`, type: "button", "aria-current": String(state.sel === a.id),
        onclick: () => select(a.id, true),
      },
        h("span", { class: `stripe s-${r.verdict}`, "aria-hidden": "true" }),
        h("span", {}, h("span", { class: "t", text: a.title }), h("span", { class: "m", text: `${a.id} · ${a.host}${a.count > 1 ? ` · ×${a.count}` : ""}` })),
        h("span", { class: "c" }, h("span", { text: fmtTime(a.ts) }), h("span", { text: `risk ${r.risk}` }), d ? h("span", { class: "done-mark", text: d.action === "agree" ? "Agreed" : "Overridden" }) : null),
      ));
    }
  }
  list.replaceChildren(...nodes);
}

function fmtTime(ts) {
  if (ts == null) return "no time";
  const d = new Date(ts);
  return `${d.toISOString().slice(5, 10)} ${d.toISOString().slice(11, 16)}Z`;
}

function select(id, scroll) {
  state.sel = id;
  state.ovOpen = false;
  renderList();
  renderDetail();
  if (scroll && window.matchMedia("(max-width: 860px)").matches) $("detail").scrollIntoView({ block: "start" });
}

/* ---------- Detail ---------- */
function gauge(label, value, cls, tickAt) {
  const fill = h("span", { class: `fill ${cls}` });
  fill.style.width = `${value}%`;
  const bar = h("div", { class: "bar", "aria-hidden": "true" }, fill);
  if (tickAt != null) { const t = h("span", { class: "tick" }); t.style.left = `${tickAt}%`; bar.append(t); }
  return [h("span", { class: "v-label", text: label }), bar, h("span", { class: "num", text: String(value) })];
}

function guardNote(r) {
  const why = r.flags.forcedWhy;
  if (why === "low_confidence") return h("div", { class: "guard" }, h("b", { text: "Routed to review by rule. " }), `The engine leaned ${LABEL[r.flags.forcedFrom].toLowerCase()}, but confidence ${r.confidence} is under ${THRESHOLDS.minConfidence}.`);
  if (why === "critical_asset") return h("div", { class: "guard" }, h("b", { text: "Routed to review by rule. " }), "This asset is critical, so it is never auto-labelled benign.");
  if (why === "injection") return h("div", { class: "guard" }, h("b", { text: "Routed to review by rule. " }), "The log tried to instruct the AI, so it is never auto-labelled benign.");
  if (r.flags.injection) return h("div", { class: "guard" }, h("b", { text: "Instruction-like text found and ignored. " }), "Log content is treated as data only. The attempt itself raised the risk score.");
  return null;
}

function renderDetail() {
  const box = $("detail");
  const it = byId(state.sel);
  if (!it) {
    box.replaceChildren(h("div", { class: "empty" }, h("strong", { text: "Select an alert" }), "Its verdict, the evidence behind it and your decision buttons appear here."));
    return;
  }
  const { alert: a, result: r } = it;
  const raw = a.raw || [a.parent_process && `parent=${a.parent_process}`, a.process && `process=${a.process}`, a.command_line && `cmd=${a.command_line}`, a.src_ip && `src=${a.src_ip}`, a.dest_ip && `dst=${a.dest_ip}`, a.user_agent && `ua=${a.user_agent}`].filter(Boolean).join("\n") || "No raw text supplied.";
  const sorted = [...r.signals].sort((x, y) => Math.abs(y.weight) - Math.abs(x.weight));

  box.replaceChildren(
    h("div", { class: "d-head" },
      h("div", { class: "meta" }, h("span", { text: a.id }), a.source ? h("span", { text: a.source }) : null, a.severity ? h("span", {}, "Severity ", h("b", { text: a.severity })) : null, h("span", { text: fmtTime(a.ts) }), a.count > 1 ? h("span", {}, h("b", { text: String(a.count) }), " repeats merged") : null),
      h("h1", { text: a.title }),
      h("div", { class: "meta" }, h("span", {}, "Host ", h("b", { text: a.host })), h("span", {}, "User ", h("b", { text: a.user })), h("span", {}, "Asset ", h("b", { text: r.flags.criticality }))),
    ),
    h("div", { class: "d-body" },
      h("section", { class: "verdict", "aria-label": "Engine verdict" },
        h("div", { class: "v-top" }, h("span", { class: "v-label", text: "Verdict" }), h("span", { class: `pill p-${r.verdict}`, text: LABEL[r.verdict] })),
        h("div", { class: "gauges" }, gauge("Risk", r.risk, r.verdict, null), gauge("Confidence", r.confidence, "neutral", THRESHOLDS.minConfidence)),
        h("div", { class: "bar-note", text: `Mark on the confidence bar = ${THRESHOLDS.minConfidence}. Below it, the alert always goes to a person.` }),
        guardNote(r),
        h("p", { class: "reason", text: r.reason }),
      ),
      h("section", {},
        h("h3", { text: `Signals behind the verdict (${sorted.length})` }),
        sorted.length
          ? h("ul", { class: "signals" }, sorted.map(sg => h("li", {},
              h("span", { class: "tag", text: sg.type }),
              h("span", {}, h("span", { class: "lbl", text: sg.label }), h("span", { class: "det", text: sg.detail })),
              h("span", { class: `w ${sg.weight > 0 ? "up" : "down"}`, text: `${sg.weight > 0 ? "+" : "−"}${Math.abs(sg.weight)}` }))))
          : h("p", { class: "hint", text: "No rule matched. The engine has no evidence either way, so a person decides." }),
      ),
      h("details", {}, h("summary", { text: "Raw alert" }), h("pre", { text: raw })),
    ),
    h("div", { class: "decide", id: "decide" }, decisionNodes(it)),
  );
}

function decisionNodes(it) {
  const { alert: a, result: r } = it;
  const d = state.dec[a.id];
  if (d) {
    return [
      h("div", { class: "status" },
        d.action === "agree" ? h("span", { class: "ok", text: `✓ You agreed: ${LABEL[d.final]}` }) : h("span", { class: "ov", text: `You overrode to ${LABEL[d.final]}` }),
        h("button", { class: "linkbtn", type: "button", onclick: () => undo(a.id), text: "Undo" })),
      d.note ? h("div", { class: "hint", text: `Note: ${d.note}` }) : null,
      h("div", { class: "hint", text: "Saved as a past case. Similar alerts now use it as evidence." }),
    ];
  }
  const nodes = [h("div", { class: "btns" },
    h("button", { class: "btn primary", type: "button", onclick: () => decide(a.id, "agree", r.verdict, "") }, `Agree: ${LABEL[r.verdict]}`),
    h("button", { class: "btn", type: "button", "aria-expanded": String(state.ovOpen), onclick: () => { state.ovOpen = !state.ovOpen; $("decide").replaceChildren(...decisionNodes(it)); } }, "Override"),
    h("span", { class: "hint", text: "Nothing happens to the host or user. This only records your judgement." }),
  )];
  if (state.ovOpen) {
    const others = VERDICTS.filter(v => v !== r.verdict);
    const note = h("textarea", { id: "ov-note", maxlength: "500", placeholder: "Why is the engine wrong? Optional, kept with the case." });
    const form = h("form", { class: "override", onsubmit: e => {
      e.preventDefault();
      const pick = form.querySelector("input[name=final]:checked");
      decide(a.id, "override", pick ? pick.value : others[0], note.value.trim().slice(0, 500));
    } },
      h("fieldset", { class: "radios" }, h("legend", { text: "Correct verdict" }),
        others.map((v, i) => h("label", { for: `final-${v}` }, h("input", { type: "radio", name: "final", id: `final-${v}`, value: v, checked: i === 0 }), LABEL[v]))),
      note,
      h("div", { class: "btns" }, h("button", { class: "btn primary", type: "submit", text: "Save override" }), h("button", { class: "btn", type: "button", text: "Cancel", onclick: () => { state.ovOpen = false; $("decide").replaceChildren(...decisionNodes(it)); } })),
    );
    nodes.push(form);
  }
  return nodes;
}

function decide(id, action, final, note) {
  const it = byId(id);
  if (!it) return;
  const before = new Map(state.items.map(x => [x.alert.id, x.result.verdict]));
  state.dec[id] = { action, final, note, engineVerdict: it.result.verdict, risk: it.result.risk, confidence: it.result.confidence };
  state.ctx.cases.push({ key: caseKey(it.alert), verdict: final, alertId: id, note, by: "analyst" });
  state.ovOpen = false;
  rescore();
  const changed = state.items.filter(x => x.alert.id !== id && !state.dec[x.alert.id] && before.get(x.alert.id) !== x.result.verdict);
  const next = state.items.find(x => !state.dec[x.alert.id]);
  if (next) state.sel = next.alert.id;
  renderAll();
  toast(changed.length ? `Saved. ${changed.length} similar alert${changed.length > 1 ? "s" : ""} re-scored from your decision` : action === "agree" ? "Verdict confirmed" : "Override saved");
}

function undo(id) {
  delete state.dec[id];
  state.ctx.cases = state.ctx.cases.filter(c => c.alertId !== id);
  rescore();
  state.sel = id;
  renderAll();
  toast("Decision undone");
}

/* ---------- Report ---------- */
function renderReport() {
  const m = minutes();
  const s = summarise(state.items, state.dec, m.before, m.after);
  const rows = [["Likely malicious", s.byVerdict.mal, "mal"], ["Needs review", s.byVerdict.rev, "rev"], ["Likely benign", s.byVerdict.ben, "ben"]];
  const pct = n => (s.total ? `${Math.round((n / s.total) * 100)}%` : "–");
  $("rtable").replaceChildren(
    h("thead", {}, h("tr", {}, h("th", { text: "Engine verdict" }), h("th", { class: "n", text: "Items" }), h("th", { class: "n", text: "Share" }))),
    h("tbody", {},
      rows.map(([l, n, v]) => h("tr", {}, h("td", {}, h("span", { class: `pill p-${v}`, text: l })), h("td", { class: "n", text: String(n) }), h("td", { class: "n", text: pct(n) }))),
      h("tr", {}, h("td", { text: "Hours saved so far" }), h("td", { class: "n", text: s.hoursSaved.toFixed(1) }), h("td", { class: "n", text: "" })),
      h("tr", {}, h("td", { text: "Hours if whole queue decided" }), h("td", { class: "n", text: s.hoursProjected.toFixed(1) }), h("td", { class: "n", text: "" })),
    ),
  );
  drawChart();
}

function drawChart() {
  const chart = $("chart");
  const days = new Map();
  for (const { alert: a, result: r } of state.items) {
    if (a.ts == null) continue;
    const day = new Date(a.ts).toISOString().slice(0, 10);
    if (!days.has(day)) days.set(day, { mal: 0, rev: 0, ben: 0 });
    days.get(day)[r.verdict]++;
  }
  const keys = [...days.keys()].sort().slice(-14);
  const W = 560, H = 240, L = 36, R = 12, T = 18, B = 34;
  chart.setAttribute("viewBox", `0 0 ${W} ${H}`);
  chart.replaceChildren();
  if (!keys.length) {
    chart.append(svg("text", { x: W / 2, y: H / 2, "text-anchor": "middle", fill: "var(--muted)", "font-size": 13 }, "No dated alerts to chart"));
    $("legend").replaceChildren();
    return;
  }
  const totals = keys.map(k => { const d = days.get(k); return d.mal + d.rev + d.ben; });
  const maxRaw = Math.max(...totals);
  const step = maxRaw <= 5 ? 1 : maxRaw <= 10 ? 2 : maxRaw <= 25 ? 5 : Math.ceil(maxRaw / 5 / 10) * 10;
  const max = Math.ceil(maxRaw / step) * step;
  const y = v => T + (H - T - B) * (1 - v / max);
  for (let t = 0; t <= max; t += step) {
    chart.append(svg("line", { x1: L, x2: W - R, y1: y(t), y2: y(t), stroke: "var(--line)", "stroke-width": 1 }));
    chart.append(svg("text", { x: L - 8, y: y(t) + 4, "text-anchor": "end", "font-size": 11, fill: "var(--muted)" }, t));
  }
  const bw = (W - L - R) / keys.length;
  const colors = { mal: "var(--mal)", rev: "var(--rev)", ben: "var(--ben)" };
  keys.forEach((k, i) => {
    const d = days.get(k);
    const x = L + i * bw + bw * 0.2, w = Math.max(6, bw * 0.6);
    let acc = 0;
    for (const v of ["ben", "rev", "mal"]) {
      if (!d[v]) continue;
      const top = y(acc + d[v]), bottom = y(acc);
      chart.append(svg("rect", { x, y: top, width: w, height: Math.max(0, bottom - top - 1), fill: colors[v] }));
      acc += d[v];
    }
    chart.append(svg("text", { x: x + w / 2, y: y(acc) - 6, "text-anchor": "middle", "font-size": 12, "font-weight": 600, fill: "var(--ink)" }, acc));
    chart.append(svg("text", { x: x + w / 2, y: H - 12, "text-anchor": "middle", "font-size": 11.5, fill: "var(--muted)" }, k.slice(5)));
  });
  $("legend").replaceChildren(...["mal", "rev", "ben"].map(v => {
    const sw = h("i"); sw.style.background = colors[v];
    return h("span", {}, sw, LABEL[v]);
  }));
}

/* ---------- How it decides ---------- */
function table(headers, rows, monoCols = []) {
  return h("div", { class: "tbl-wrap" }, h("table", { class: "tbl" },
    h("thead", {}, h("tr", {}, headers.map(x => h("th", { text: x })))),
    h("tbody", {}, rows.length ? rows.map(r => h("tr", {}, r.map((c, i) => h("td", { class: monoCols.includes(i) ? "mono" : null, text: String(c) })))) : h("tr", {}, h("td", { colspan: String(headers.length), text: "None yet" })))));
}

function renderContext() {
  const c = state.ctx;
  $("context").replaceChildren(
    h("div", { class: "panel" },
      h("h2", { text: "How a verdict is made" }),
      h("ol", { class: "steps" },
        h("li", { text: `Repeats of the same rule, host and user within ${THRESHOLDS.dedupeMinutes} minutes are merged into one item.` }),
        h("li", { text: "Each item is checked against the rules below. Every matching rule adds or removes risk, starting from 50." }),
        h("li", { text: `Risk ${THRESHOLDS.malicious}+ leans malicious, ${THRESHOLDS.benign} or less leans benign, anything between needs review.` }),
        h("li", { text: "Confidence drops when evidence conflicts or only one rule matched." }),
        h("li", { text: `Guardrails: under ${THRESHOLDS.minConfidence} confidence, a critical asset, or text trying to instruct an AI means the alert is never auto-labelled. A person reviews it.` }),
        h("li", { text: "Every analyst decision becomes a past case, and future alerts with the same rule and user or host use it as evidence." }),
      ),
    ),
    h("div", { class: "panel" }, h("h2", { text: "Rules and weights" }), table(["Type", "Rule", "Weight"], SIGNAL_CATALOG.map(s => [s.type, s.label, s.weight]))),
    h("div", { class: "rgrid" },
      h("div", { class: "panel" }, h("h2", { text: "Threat intel (sample)" }), table(["Indicator", "Note"], [...Object.entries(c.intel.ips), ...Object.entries(c.intel.domains)], [0])),
      h("div", { class: "panel" }, h("h2", { text: "Asset criticality" }), table(["Host", "Criticality"], Object.entries(c.assets), [0])),
    ),
    h("div", { class: "rgrid" },
      h("div", { class: "panel" }, h("h2", { text: "Approved change windows" }), table(["Ticket", "Host or user", "Window (UTC)"], c.changes.map(x => [x.id, x.host || x.user, `${x.start.slice(5, 16).replace("T", " ")} → ${x.end.slice(5, 16).replace("T", " ")}`]), [0])),
      h("div", { class: "panel" }, h("h2", { text: "Past cases" }), h("p", { class: "sub", text: "Grows as you agree or override in the queue." }), table(["Rule | entity", "Verdict", "Source"], c.cases.map(x => [x.key, LABEL[x.verdict], x.by === "seed" ? "seed data" : `you, ${x.alertId}`]), [0])),
    ),
    h("div", { class: "panel" },
      h("h2", { text: "Upload format" }),
      h("p", { class: "sub", text: `CSV or JSON, up to ${LIMITS.maxRows} rows and 5 MB. Only the columns below are read. Everything else in the file is ignored. Use "Download CSV template" in the queue for an example.` }),
      h("p", { class: "mono hint", text: TEMPLATE_HEADERS.join(", ") }),
    ),
  );
}

/* ---------- Files ---------- */
function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = h("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function readFile(file) {
  if (!file) return;
  if (file.size > LIMITS.maxBytes) { showError(`"${file.name}" is larger than 5 MB. Split it into smaller files.`); return; }
  if (!/\.(csv|json)$/i.test(file.name)) { showError("Only .csv and .json files can be triaged."); return; }
  try {
    const alerts = parseAlerts(await file.text(), file.name);
    load(alerts, `${file.name} · ${alerts.length} alerts`);
    toast(`Triaged ${alerts.length} alerts from ${file.name}`);
  } catch (err) {
    showError(err instanceof InputError ? err.message : "The file could not be read. Check it is a CSV or JSON export.");
  }
}

function wireFiles() {
  $("btn-sample").addEventListener("click", () => { load(SAMPLE_ALERTS.map(normalize), `Sample data · ${SAMPLE_ALERTS.length} alerts from a fictional company`); toast("Sample data loaded"); });
  $("file-input").addEventListener("change", e => { readFile(e.target.files[0]); e.target.value = ""; });
  $("btn-template").addEventListener("click", () => {
    const example = { id: "EX-1", timestamp: "2026-10-30T09:42:11Z", title: "Encoded PowerShell launched by Excel", rule: "Office child process", source: "Your SIEM", severity: "High", host: "LAPTOP-01", user: "j.doe", process: "powershell.exe", parent_process: "EXCEL.EXE", command_line: "powershell.exe -w hidden -enc SQBFAFgA", asset_criticality: "high" };
    download("cybershield-template.csv", toCSV(TEMPLATE_HEADERS, [example]), "text/csv");
  });
  $("btn-export").addEventListener("click", () => {
    const rows = state.items.filter(it => state.dec[it.alert.id]).map(({ alert: a, result: r }) => {
      const d = state.dec[a.id];
      return { id: a.id, title: a.title, host: a.host, user: a.user, merged_repeats: a.count, engine_verdict: LABEL[d.engineVerdict], engine_risk: d.risk, engine_confidence: d.confidence, analyst_action: d.action, final_verdict: LABEL[d.final], note: d.note, current_signals: r.signals.map(s => s.label).join("; ") };
    });
    if (!rows.length) { toast("Decide at least one alert first"); return; }
    const headers = ["id", "title", "host", "user", "merged_repeats", "engine_verdict", "engine_risk", "engine_confidence", "analyst_action", "final_verdict", "note", "current_signals"];
    download("cybershield-decisions.csv", toCSV(headers, rows), "text/csv");
  });

  // Drag and drop
  const view = $("view-queue");
  let depth = 0;
  view.addEventListener("dragenter", e => { if ([...(e.dataTransfer?.types || [])].includes("Files")) { depth++; $("drop").hidden = false; } });
  view.addEventListener("dragleave", () => { depth = Math.max(0, depth - 1); if (!depth) $("drop").hidden = true; });
  view.addEventListener("dragover", e => e.preventDefault());
  view.addEventListener("drop", e => { e.preventDefault(); depth = 0; $("drop").hidden = true; readFile(e.dataTransfer?.files?.[0]); });
}

/* ---------- Views ---------- */
const VIEWS = ["queue", "report", "context"];
function showView(v) {
  if (!VIEWS.includes(v)) v = "queue";
  for (const name of VIEWS) {
    $(`view-${name}`).hidden = name !== v;
    $(`tab-${name}`).setAttribute("aria-selected", String(name === v));
  }
  if (v === "report") renderReport();
  if (v === "context") renderContext();
  if (location.hash !== `#${v}`) history.replaceState(null, "", `#${v}`);
}

function renderAll() {
  $("dataset-name").textContent = state.datasetName || "No data loaded";
  renderKpis();
  renderChips();
  renderList();
  renderDetail();
  if (!$("view-report").hidden) renderReport();
  if (!$("view-context").hidden) renderContext();
}

document.querySelectorAll(".tab").forEach(t => t.addEventListener("click", () => showView(t.dataset.view)));
window.addEventListener("hashchange", () => showView(location.hash.slice(1)));
["min-before", "min-after"].forEach(id => $(id).addEventListener("input", () => { renderKpis(); renderReport(); }));
wireFiles();
load(SAMPLE_ALERTS.map(normalize), `Sample data · ${SAMPLE_ALERTS.length} alerts from a fictional company`);
showView(location.hash.slice(1) || "queue");
