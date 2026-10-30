// Sample organisation context the engine reasons with.
// Everything here is fictional. IPs use documentation ranges (RFC 5737) and domains use .example (RFC 2606).
// To adapt the tool to a real environment, replace these lists. Never put secrets here: this file is public.

const changes = [
  { id: "CHG-3412", host: "APP-SRV-03", user: "svc_backup", summary: "Backup service account password rotation", start: "2026-10-29T06:30:00Z", end: "2026-10-29T09:30:00Z" },
  { id: "CHG-3420", host: "DC-01", user: "", summary: "Monthly patching scheduled task", start: "2026-10-28T22:00:00Z", end: "2026-10-29T02:00:00Z" },
];

export function defaultContext() {
  return {
    org: "Halden Freight (fictional)",
    intel: {
      ips: {
        "203.0.113.66": "Command-and-control server for a known loader family (sample intel)",
        "198.51.100.23": "Seen scanning many organisations this week (sample intel)",
      },
      domains: {
        "cdn-docsync.example": "Registered 3 days ago, hosts a malware loader (sample intel)",
      },
    },
    scanners: ["10.1.0.25"],
    assets: {
      "DC-01": "critical",
      "FIN-LT-0142": "high",
      "WH-SRV-07": "high",
      "WEB-PUB-02": "medium",
      "APP-SRV-03": "medium",
    },
    changes: changes.map(c => ({ ...c, startTs: Date.parse(c.start), endTs: Date.parse(c.end) })),
    cases: [
      { key: "account added to privileged group|j.patel", verdict: "ben", alertId: "seed-1", note: "Approved under CHG-3381 last month", by: "seed" },
    ],
  };
}
