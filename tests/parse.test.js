import { test } from "node:test";
import assert from "node:assert/strict";
import { parseCSV, parseAlerts, normalize, csvCell, toCSV, LIMITS, InputError } from "../site/js/parse.js";

test("CSV parser handles quotes, embedded commas, escaped quotes and CRLF", () => {
  const rows = parseCSV('id,title,raw\r\n1,"Hello, world","say ""hi"""\r\n2,plain,\r\n');
  assert.equal(rows.length, 2);
  assert.equal(rows[0].title, "Hello, world");
  assert.equal(rows[0].raw, 'say "hi"');
  assert.equal(rows[1].raw, "");
});

test("CSV with an unclosed quote is rejected with a clear message", () => {
  assert.throws(() => parseCSV('id,title\n1,"broken'), InputError);
});

test("JSON array and { alerts: [] } are both accepted", () => {
  assert.equal(parseAlerts('[{"id":"a","title":"t"}]', "x.json").length, 1);
  assert.equal(parseAlerts('{"alerts":[{"id":"a"},{"id":"b"}]}', "x.json").length, 2);
});

test("invalid JSON gives a readable error", () => {
  assert.throws(() => parseAlerts("[{oops", "x.json"), /could not be read/);
});

test("unknown fields are dropped and prototype pollution keys are ignored", () => {
  const [a] = parseAlerts('[{"id":"a","__proto__":{"polluted":true},"constructor":{"x":1},"evil":"<script>alert(1)</script>","title":"ok"}]', "x.json");
  assert.equal(a.evil, undefined);
  assert.equal(({}).polluted, undefined);
  assert.equal(Object.prototype.polluted, undefined);
  assert.equal(a.title, "ok");
});

test("HTML in fields is kept as plain text, not interpreted", () => {
  const [a] = parseAlerts('[{"title":"<img src=x onerror=alert(1)>"}]', "x.json");
  assert.equal(a.title, "<img src=x onerror=alert(1)>");
});

test("long fields are capped", () => {
  const [a] = parseAlerts(JSON.stringify([{ raw: "x".repeat(10000) }]), "x.json");
  assert.ok(a.raw.length <= LIMITS.maxField + 1);
});

test("row limit is enforced", () => {
  const many = JSON.stringify(Array.from({ length: LIMITS.maxRows + 1 }, (_, i) => ({ id: String(i) })));
  assert.throws(() => parseAlerts(many, "x.json"), /limit/);
});

test("types are coerced safely", () => {
  const a = normalize({ bytes_out: "1500", signed: "yes", new_country: "0", mfa_pushes: "abc", timestamp: "not a date" }, 3);
  assert.equal(a.bytes_out, 1500);
  assert.equal(a.signed, true);
  assert.equal(a.new_country, false);
  assert.equal(a.mfa_pushes, undefined);
  assert.equal(a.ts, null);
  assert.equal(a.id, "ROW-4");
});

test("duplicate ids are made unique", () => {
  const out = parseAlerts('[{"id":"a"},{"id":"a"},{"id":"a"}]', "x.json");
  assert.deepEqual(out.map(x => x.id), ["a", "a-2", "a-3"]);
});

test("exported CSV neutralises spreadsheet formulas", () => {
  assert.equal(csvCell("=HYPERLINK(\"http://evil\")"), "\"'=HYPERLINK(\"\"http://evil\"\")\"");
  assert.equal(csvCell("+1"), "'+1");
  assert.equal(csvCell("-2"), "'-2");
  assert.equal(csvCell("@SUM(A1)"), "'@SUM(A1)");
  assert.equal(csvCell("normal"), "normal");
  assert.equal(toCSV(["a"], [{ a: "x,y" }]), 'a\r\n"x,y"');
});
