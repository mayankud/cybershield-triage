// Safe parsing of user-supplied alert files.
// Uploaded data is untrusted: only known fields are copied, every value is length-capped,
// and nothing is ever evaluated or inserted into the page as HTML.

export const LIMITS = { maxBytes: 5 * 1024 * 1024, maxRows: 5000, maxField: 2000 };

const STRING_FIELDS = [
  "id", "title", "rule", "source", "severity", "host", "user", "process", "parent_process",
  "command_line", "src_ip", "dest_ip", "domain", "dest_category", "mfa_result", "group",
  "event_action", "asset_criticality", "user_agent", "raw",
];
const NUMBER_FIELDS = ["dest_port", "bytes_out", "connection_count", "interval_s", "mfa_pushes", "prevalence", "count"];
const BOOL_FIELDS = ["new_country", "signed"];

export const TEMPLATE_HEADERS = ["id", "timestamp", "title", "rule", "source", "severity", "host", "user",
  "process", "parent_process", "command_line", "src_ip", "dest_ip", "domain", "bytes_out", "dest_category",
  "connection_count", "interval_s", "mfa_pushes", "mfa_result", "new_country", "group", "event_action",
  "signed", "prevalence", "asset_criticality", "raw"];

export class InputError extends Error {}

/** RFC 4180-style CSV parser. Handles quoted fields, escaped quotes and CRLF. */
export function parseCSV(text) {
  const rows = [];
  let row = [], field = "", i = 0, quoted = false;
  const s = text.replace(/^﻿/, "");
  while (i < s.length) {
    const c = s[i];
    if (quoted) {
      if (c === '"') {
        if (s[i + 1] === '"') { field += '"'; i += 2; continue; }
        quoted = false; i++; continue;
      }
      field += c; i++; continue;
    }
    if (c === '"' && field === "") { quoted = true; i++; continue; }
    if (c === ",") { row.push(field); field = ""; i++; continue; }
    if (c === "\r") { i++; continue; }
    if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; i++; continue; }
    field += c; i++;
  }
  if (quoted) throw new InputError("The CSV has an unclosed quote. Check that every quoted value ends with a quote.");
  if (field !== "" || row.length) { row.push(field); rows.push(row); }
  const nonEmpty = rows.filter(r => r.some(v => v.trim() !== ""));
  if (!nonEmpty.length) return [];
  const headers = nonEmpty[0].map(h => h.trim().toLowerCase());
  return nonEmpty.slice(1).map(r => {
    const o = Object.create(null);
    headers.forEach((h, j) => { if (h) o[h] = r[j] ?? ""; });
    return o;
  });
}

function str(v) {
  if (v == null) return undefined;
  const t = String(v).trim();
  if (!t) return undefined;
  return t.length > LIMITS.maxField ? t.slice(0, LIMITS.maxField) + "…" : t;
}
function num(v) {
  if (v == null || v === "") return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}
function bool(v) {
  if (typeof v === "boolean") return v;
  const t = String(v ?? "").trim().toLowerCase();
  if (["true", "yes", "1", "y"].includes(t)) return true;
  if (["false", "no", "0", "n"].includes(t)) return false;
  return undefined;
}

/** Copy only known fields from an untrusted record into a fresh object. */
export function normalize(rec, index) {
  if (!rec || typeof rec !== "object" || Array.isArray(rec)) {
    throw new InputError(`Row ${index + 1} is not an object.`);
  }
  const get = k => (Object.prototype.hasOwnProperty.call(rec, k) ? rec[k] : undefined);
  const a = {};
  for (const k of STRING_FIELDS) { const v = str(get(k)); if (v !== undefined) a[k] = v; }
  for (const k of NUMBER_FIELDS) { const v = num(get(k)); if (v !== undefined) a[k] = v; }
  for (const k of BOOL_FIELDS) { const v = bool(get(k)); if (v !== undefined) a[k] = v; }
  const ts = Date.parse(String(get("timestamp") ?? ""));
  a.ts = Number.isFinite(ts) ? ts : null;
  a.id = a.id || `ROW-${index + 1}`;
  a.title = a.title || a.rule || "Untitled alert";
  a.host = a.host || "-";
  a.user = a.user || "-";
  return a;
}

/** Parse a CSV or JSON file's text into normalized alerts. */
export function parseAlerts(text, filename = "") {
  if (typeof text !== "string") throw new InputError("Could not read the file as text.");
  if (text.length > LIMITS.maxBytes) throw new InputError("The file is larger than 5 MB. Split it into smaller files.");
  const trimmed = text.trim();
  if (!trimmed) throw new InputError("The file is empty.");

  let records;
  const looksJson = /\.json$/i.test(filename) || trimmed.startsWith("[") || trimmed.startsWith("{");
  if (looksJson) {
    let data;
    try { data = JSON.parse(trimmed); }
    catch { throw new InputError("The JSON could not be read. Check it is a valid array of alert objects."); }
    records = Array.isArray(data) ? data : Array.isArray(data?.alerts) ? data.alerts : null;
    if (!records) throw new InputError('JSON must be an array of alerts, or an object with an "alerts" array.');
  } else {
    records = parseCSV(trimmed);
  }
  if (!records.length) throw new InputError("No alerts found in the file.");
  if (records.length > LIMITS.maxRows) throw new InputError(`The file has ${records.length} rows. The limit is ${LIMITS.maxRows}.`);

  const seen = new Set();
  return records.map((r, i) => {
    const a = normalize(r, i);
    let id = a.id, n = 2;
    while (seen.has(id)) id = `${a.id}-${n++}`;
    seen.add(id);
    a.id = id;
    return a;
  });
}

/** Spreadsheet formula injection guard for exported CSV cells. */
export function csvCell(v) {
  let t = v == null ? "" : String(v);
  if (/^[=+@\t\r]|^-./.test(t)) t = "'" + t;
  return /[",\n\r]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t;
}

export function toCSV(headers, rows) {
  return [headers.map(csvCell).join(","), ...rows.map(r => headers.map(h => csvCell(r[h])).join(","))].join("\r\n");
}
