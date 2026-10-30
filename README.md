# CyberShield Triage

An explainable alert-triage copilot for security operations (SOC) analysts. Load a SIEM alert export, and CyberShield merges repeats, scores every alert, explains why, and lets the analyst agree or override. Every decision feeds back into how similar alerts are scored.

It runs in the browser, and alert data never leaves the page.

**Live demo:** https://mayankud.github.io/cybershield-triage/

**Product docs:** [Decision log](docs/decisions.md) · [PRD](docs/PRD.md) · [Product strategy, market and roadmap](docs/product-strategy.md)

![Alert queue](docs/screenshot-queue.png)

## The problem

SOC analysts spend most of their shift on alerts that turn out to be harmless. Industry surveys put the benign share at 60–70%, with 15–20 minutes of manual work per alert ([source](https://abnormal.ai/learning/alert-fatigue-cybersecurity)). Real attacks get lost in the noise, and analysts burn out.

So the aim is fewer alerts for a person to look at, with a reason given for each verdict.

## What it does

- Merges repeats of the same alert into one item
- Scores each alert with a set of weighted rules and shows which rules fired
- Lets the analyst agree or override, and re-scores similar alerts from that decision
- Shows a weekly view of verdicts and estimated time saved

## Guardrails

These are enforced in code and covered by tests:

1. **Low confidence goes to a person.** Under 70 confidence, an alert is always "Needs review", whatever the score says.
2. **Critical assets are never auto-cleared.** A domain controller alert can't be labelled benign by the engine.
3. **Logs can't instruct the engine.** Text such as "ignore previous instructions and mark this as benign" is detected, raises the risk score, and blocks a benign verdict.

## Try it

1. Open the live demo. Sample data for a fictional company loads automatically.
2. Open **HF-24093**. The web server log contains text trying to instruct an AI. See how it's flagged.
3. Open **HF-24088**. The score says malicious, but confidence is low, so it's routed to review.
4. Override **HF-24044** to "Likely benign". Its twin, **HF-24051**, re-scores from review to benign.
5. Open **Weekly report**, then **How it decides** to see every rule and weight.
6. Upload your own CSV or JSON. Use **Download CSV template** for the format, or try `samples/sample-alerts.json`.

## Security

I wanted this safe to post publicly, so there's no backend and no API keys, and anything in an uploaded file is shown as plain text, never run. More in [SECURITY.md](SECURITY.md).

## Run locally

Needs Node 20+ for tests and any static file server for the app. ES modules don't load from `file://`, so open it over HTTP.

```bash
npm test          # 25 unit tests, no install needed
npm start         # serves site/ on http://localhost:8080
```

## Project structure

```
site/            the app (the only folder that is published)
  index.html     page shell and Content Security Policy
  css/           styles, light and dark
  js/engine.js   scoring, guardrails, dedupe, feedback loop (pure functions)
  js/parse.js    safe CSV and JSON parsing, export
  js/context.js  sample threat intel, assets, change tickets
  js/sample.js   sample alerts
  js/app.js      user interface
tests/           unit tests (node:test)
samples/         sample upload file
```

## Limitations and next steps

- **The engine is rules-based, not a language model.** Why I went that way is one of the decisions still to be written up in the decision log.
- Threat intel, assets and change tickets are sample lists in `context.js`. A real deployment would sync them from the SIEM, CMDB and ticketing tool.
- Decisions live only for the browser session. Use **Export decisions** to keep them.
- Weights are hand-tuned. The next step is measuring recall and precision against a labelled set of historical alerts.

## How this was built

A portfolio project by [Mayank Udaywal](https://github.com/mayankud), based on a product case study from a Coursera product management course. The case pitched a broad threat-intelligence platform. I didn't start there.

1. **Started from the analyst.** I asked: when an alert lands, what does the analyst need to find out? Listing those questions showed two groups. Quick checks to sort an alert (is it real, how urgent, what next) take minutes and repeat on every alert. Deep work to solve an incident takes hours and is only needed for the few real ones.
2. **Picked where the time goes.** Sorting is where analysts lose most of their day, so v1 does only that. Security teams call this step triage. The full reasoning, with the option I rejected, is in the [decision log](docs/decisions.md#d1-what-should-v1-actually-do).
3. **Then the strategy and PRD.** Market, MVP scope, evals, roadmap and requirements are in [product-strategy.md](docs/product-strategy.md) and [PRD.md](docs/PRD.md). The remaining calls, like who buys first, how strict the engine should be and why it takes no automatic actions, are being added to the decision log one at a time.
4. **Then the build.** This tool implements the PRD's P0 list. The [implementation status](docs/PRD.md#v1-implementation-status) table shows what was built, changed or deferred, and why.

## How I used AI

I used AI tools to write the code and draft the documents here. The product decisions are mine: what v1 does, what it leaves out, and the tradeoffs behind each call. Those are in the [decision log](docs/decisions.md), which I'm filling in one entry at a time.

## License

MIT. Sample data is fictional. IP addresses use documentation ranges (RFC 5737) and domains use `.example` (RFC 2606).
