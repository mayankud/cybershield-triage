// Triage engine. No DOM or network here so it can be tested in Node.

export const VERDICTS = ["mal", "rev", "ben"];
export const LABEL = { mal: "Likely malicious", rev: "Needs review", ben: "Likely benign" };

export const THRESHOLDS = {
  malicious: 70,      // risk at or above this leans malicious
  benign: 30,         // risk at or below this leans benign
  minConfidence: 70,  // FR-5: below this, always route to a human
  dedupeMinutes: 15,  // FR-2: same rule, host and user inside this window are merged
};

// Documentation of every rule, shown on the "How it decides" page. Keep in step with collectSignals.
export const SIGNAL_CATALOG = [
  { type: "log", label: "Office app started a script engine", weight: "+35" },
  { type: "log", label: "MFA prompt flooding (5+ prompts, +15 more if one was approved)", weight: "+25 to +40" },
  { type: "intel", label: "IP on threat intel list", weight: "+40" },
  { type: "intel", label: "Domain on threat intel list", weight: "+35" },
  { type: "case", label: "Analysts confirmed similar alerts as malicious", weight: "+20 to +35" },
  { type: "log", label: "Account added to a privileged group", weight: "+25" },
  { type: "log", label: "Large upload (1 GB+), more if to personal storage", weight: "+15 to +25" },
  { type: "log", label: "Encoded or obfuscated command", weight: "+20" },
  { type: "log", label: "Regular-interval connections (beaconing)", weight: "+15" },
  { type: "log", label: "Sign-in from a new country", weight: "+15" },
  { type: "log", label: "Text in the log tries to instruct an AI", weight: "+15" },
  { type: "log", label: "High or critical source severity", weight: "+10" },
  { type: "log", label: "Low or informational source severity", weight: "−10" },
  { type: "case", label: "Analysts closed similar alerts as benign", weight: "−20 to −30" },
  { type: "asset", label: "Signed binary common across the fleet (50+ hosts)", weight: "−30" },
  { type: "case", label: "Matches an approved change ticket window", weight: "−35" },
  { type: "asset", label: "Source is an approved internal scanner", weight: "−40" },
];

// Text that addresses an AI or tries to steer the verdict. Logs are data, never instructions.
const INJECTION_PATTERNS = [
  /ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)/i,
  /disregard\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)/i,
  /\b(mark|classify|label|treat)\s+(this\s+)?(alert\s+|event\s+|log\s+)?as\s+(benign|safe|harmless|a\s+false\s+positive|false\s+positive)/i,
  /\byou\s+are\s+(now\s+)?(an?\s+)?(ai|assistant|language\s+model|llm)\b/i,
  /\b(system|developer)\s+prompt\b/i,
  /\bAI\s+(assistant|model|analyst)\s*:/i,
];

const TEXT_FIELDS = ["title", "command_line", "raw", "user_agent", "process", "domain"];

const clamp = (n, lo, hi) => Math.min(hi, Math.max(lo, n));
const lower = s => (typeof s === "string" ? s.toLowerCase() : "");

/** Key used to match an alert against past analyst decisions. */
export function caseKey(a) {
  const rule = lower(a.rule || a.title);
  const who = lower(a.user && a.user !== "-" ? a.user : a.host);
  return `${rule}|${who}`;
}

/** FR-2: merge repeats of the same rule, host and user inside the window. Input is not mutated. */
export function dedupe(alerts, windowMinutes = THRESHOLDS.dedupeMinutes) {
  const winMs = windowMinutes * 60 * 1000;
  const sorted = [...alerts].sort((x, y) => (x.ts ?? 0) - (y.ts ?? 0));
  const open = new Map();
  const out = [];
  for (const a of sorted) {
    const key = `${lower(a.rule || a.title)}|${lower(a.host)}|${lower(a.user)}`;
    const g = open.get(key);
    if (g && a.ts != null && g.lastTs != null && a.ts - g.lastTs <= winMs) {
      g.item.count += a.count ?? 1;
      g.item.mergedIds.push(a.id);
      g.lastTs = a.ts;
      continue;
    }
    const item = { ...a, count: a.count ?? 1, mergedIds: [] };
    open.set(key, { item, lastTs: a.ts });
    out.push(item);
  }
  return out;
}

export function findInjection(a) {
  for (const f of TEXT_FIELDS) {
    const v = a[f];
    if (typeof v !== "string" || !v) continue;
    for (const re of INJECTION_PATTERNS) {
      const m = v.match(re);
      if (m) return { field: f, match: m[0].slice(0, 120) };
    }
  }
  return null;
}

/** Collect the signals for one alert. Each signal has a signed weight and a plain-language detail. */
export function collectSignals(a, ctx) {
  const s = [];
  const add = (id, type, weight, label, detail) => s.push({ id, type, weight, label, detail });
  const intel = ctx.intel || { ips: {}, domains: {} };

  const parent = lower(a.parent_process);
  const proc = lower(a.process);
  const cmd = lower(a.command_line);

  if (/(winword|excel|powerpnt|outlook|onenote)\.exe$/.test(parent) && /(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$/.test(proc)) {
    add("office_shell", "log", 35, "Office app started a script engine", `${a.parent_process} launched ${a.process}`);
  }
  if (/\s-(e|en|enc|encodedcommand)\s/.test(` ${cmd} `) || cmd.includes("frombase64string")) {
    add("encoded_cmd", "log", 20, "Encoded or obfuscated command", "Command line hides its content with base64 encoding");
  }
  for (const ip of [a.dest_ip, a.src_ip]) {
    if (ip && Object.hasOwn(intel.ips, ip)) add(`intel_ip_${ip}`, "intel", 40, "IP on threat intel list", `${ip}: ${intel.ips[ip]}`);
  }
  const hay = `${lower(a.domain)} ${cmd} ${lower(a.raw)}`;
  for (const d of Object.keys(intel.domains)) {
    if (hay.includes(d.toLowerCase())) { add(`intel_dom_${d}`, "intel", 35, "Domain on threat intel list", `${d}: ${intel.domains[d]}`); break; }
  }
  if (a.connection_count >= 5 && a.interval_s > 0 && a.interval_s <= 300) {
    add("beacon", "log", 15, "Regular-interval connections", `${a.connection_count} connections every ${a.interval_s}s, a beaconing pattern`);
  }
  if (a.mfa_pushes >= 5) {
    const approved = lower(a.mfa_result) === "approved";
    add("mfa_fatigue", "log", approved ? 40 : 25, "MFA prompt flooding", `${a.mfa_pushes} MFA prompts${approved ? ", and the user approved one" : ""}`);
  }
  if (a.new_country === true) add("new_country", "log", 15, "Sign-in from a new country", "First sign-in from this country for the user");
  if (/(domain admins|enterprise admins|schema admins|administrators)/.test(lower(a.group)) && /add|creat/.test(lower(a.event_action))) {
    add("priv_group", "log", 25, "Account added to a privileged group", `Added to ${a.group}`);
  }
  if (a.bytes_out >= 1e9) {
    const personal = /personal|consumer/.test(lower(a.dest_category));
    add("large_upload", "log", personal ? 25 : 15, personal ? "Large upload to personal storage" : "Large outbound transfer", `${(a.bytes_out / 1e9).toFixed(1)} GB sent${a.dest_category ? ` to ${a.dest_category}` : ""}`);
  }

  // Context that lowers risk
  if ((ctx.scanners || []).includes(a.src_ip)) {
    add("scanner", "asset", -40, "Source is an approved scanner", `${a.src_ip} is registered as an internal vulnerability scanner`);
  }
  const ch = (ctx.changes || []).find(c =>
    (lower(c.host) && lower(c.host) === lower(a.host) || lower(c.user) && lower(c.user) === lower(a.user)) &&
    a.ts != null && a.ts >= c.startTs && a.ts <= c.endTs);
  if (ch) add("change", "case", -35, "Matches an approved change", `${ch.id}: ${ch.summary}`);
  if (a.signed === true && a.prevalence >= 50) {
    add("prevalent", "asset", -30, "Signed and common across the fleet", `Signed binary seen on ${a.prevalence} hosts`);
  }

  // Past analyst decisions (the feedback loop)
  const key = caseKey(a);
  const past = (ctx.cases || []).filter(c => c.key === key && c.alertId !== a.id);
  const ben = past.filter(c => c.verdict === "ben").length;
  const mal = past.filter(c => c.verdict === "mal").length;
  if (ben > 0) add("past_benign", "case", -Math.min(30, 15 + 5 * ben), "Analysts closed similar alerts as benign", `${ben} past decision${ben > 1 ? "s" : ""} on this rule and entity`);
  if (mal > 0) add("past_mal", "case", Math.min(35, 20 + 5 * mal), "Analysts confirmed similar alerts as malicious", `${mal} past decision${mal > 1 ? "s" : ""} on this rule and entity`);

  const sev = lower(a.severity);
  if (sev === "high" || sev === "critical") add("severity", "log", 10, "High source severity", `SIEM rated it ${a.severity}`);
  if (sev === "low" || sev === "informational" || sev === "info") add("severity", "log", -10, "Low source severity", `SIEM rated it ${a.severity}`);

  const inj = findInjection(a);
  if (inj) add("injection", "log", 15, "Text in the log tries to instruct an AI", `Found in ${inj.field}. Treated as data and ignored`);

  return s;
}

/** Score one alert and apply the product guardrails. */
export function assess(a, ctx = {}) {
  const signals = collectSignals(a, ctx);
  const sum = signals.reduce((t, x) => t + x.weight, 0);
  const risk = clamp(50 + sum, 1, 99);

  let raw = risk >= THRESHOLDS.malicious ? "mal" : risk <= THRESHOLDS.benign ? "ben" : "rev";
  let confidence = Math.round(50 + Math.abs(risk - 50));
  const pos = signals.some(x => x.weight > 0);
  const neg = signals.some(x => x.weight < 0);
  if (pos && neg) confidence -= 10;          // conflicting evidence
  if (signals.length < 2) confidence -= 10;  // thin evidence
  confidence = clamp(confidence, 1, 99);

  const criticality = lower(a.asset_criticality) || lower((ctx.assets || {})[a.host]) || "unknown";
  const flags = { forcedFrom: null, forcedWhy: null, injection: signals.some(x => x.id === "injection"), criticality };

  let verdict = raw;
  if (raw !== "rev" && confidence < THRESHOLDS.minConfidence) {
    verdict = "rev"; flags.forcedFrom = raw; flags.forcedWhy = "low_confidence";
  } else if (raw === "ben" && criticality === "critical") {
    verdict = "rev"; flags.forcedFrom = raw; flags.forcedWhy = "critical_asset";
  } else if (raw === "ben" && flags.injection) {
    verdict = "rev"; flags.forcedFrom = raw; flags.forcedWhy = "injection";
  }

  return { risk, rawVerdict: raw, verdict, confidence, signals, flags, reason: explain(a, risk, verdict, signals, flags) };
}

export function explain(a, risk, verdict, signals, flags) {
  const up = signals.filter(x => x.weight > 0).sort((x, y) => y.weight - x.weight);
  const down = signals.filter(x => x.weight < 0).sort((x, y) => x.weight - y.weight);
  const parts = [];
  if (!signals.length) parts.push("No known attack or benign patterns matched, so a person should look at it.");
  if (up.length) parts.push(`Pointing to an attack: ${up.slice(0, 3).map(x => x.label.toLowerCase()).join(", ")}.`);
  if (down.length) parts.push(`Pointing to normal activity: ${down.slice(0, 3).map(x => x.label.toLowerCase()).join(", ")}.`);
  parts.push(`Overall risk ${risk} out of 100.`);
  if (flags.forcedWhy === "low_confidence") parts.push(`The engine leaned ${LABEL[flags.forcedFrom].toLowerCase()}, but confidence was below ${THRESHOLDS.minConfidence}, so it goes to an analyst.`);
  if (flags.forcedWhy === "critical_asset") parts.push("The asset is critical, so it is never auto-labelled benign.");
  if (flags.forcedWhy === "injection") parts.push("The log tried to instruct the AI, so it is never auto-labelled benign.");
  return parts.join(" ");
}

/** Assess a whole queue: dedupe, then score each item. */
export function triage(alerts, ctx) {
  return dedupe(alerts).map(a => ({ alert: a, result: assess(a, ctx) }));
}

/** Weekly-report style summary. Minutes are analyst inputs, not facts. */
export function summarise(items, decisions, baselineMin, assistedMin) {
  const byVerdict = { mal: 0, rev: 0, ben: 0 };
  for (const it of items) byVerdict[it.result.verdict]++;
  const ds = Object.values(decisions);
  const agreed = ds.filter(d => d.action === "agree").length;
  const saved = Math.max(0, baselineMin - assistedMin);
  return {
    total: items.length,
    rawTotal: items.reduce((t, it) => t + (it.alert.count || 1), 0),
    byVerdict,
    decided: ds.length,
    agreeRate: ds.length ? Math.round((agreed / ds.length) * 100) : null,
    overrides: ds.length - agreed,
    hoursSaved: (ds.length * saved) / 60,
    hoursProjected: (items.length * saved) / 60,
    injections: items.filter(it => it.result.flags.injection).length,
  };
}
