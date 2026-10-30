# Decision log

How I made the key calls on CyberShield. Each entry follows the order I worked through it: the question I started with, what I found, the options, and only then the decision. The point is to show the reasoning, not just the result.

---

## D1. What should v1 actually do?

**My starting question:** when an alert lands, what does the analyst need to find out?

**The questions an analyst asks:**

1. Is this real, or a false alarm?
2. Who's the user, and what's the machine? A laptop, or a domain controller?
3. Have we seen this before? How was it closed last time?
4. Does it match known attacker behaviour?
5. How urgent is it? Is it spreading to other systems?
6. What's the next step, and who owns it?
7. How did the attacker get in?
8. What did they access or take?
9. How do we clean it up and stop it happening again?

**What I noticed:** the questions split into two groups.

- **Questions 1–6** are quick checks to **sort** the alert: is it real, how urgent, what next. They take minutes, and they're asked of every alert.
- **Questions 7–9** are deep work to **solve** an incident. They take hours or days, and they're only needed for the few alerts that turn out to be real.

The sorting questions are where analysts lose most of their time, because they repeat them on hundreds of alerts a day and 60–70% turn out to be harmless. Security teams call this sorting step **triage**.

**Options:**

- **(a) Answer all nine questions:** sort and solve. It matches the case's "full platform" pitch and what GuardWare does, but it's a lot for a small team in 12 months.
- **(b) Answer only the sorting questions (1–6):** narrow, but it targets the biggest time cost. Solving stays with the customer's existing tools.

**Decision:** (b). v1 helps the analyst sort, and leaves solving to them.

**Why:** the sorting questions are asked on every alert, so that's where the hours go. A small team can do them well in 12 months. Solving means competing with GuardWare on its own ground.

**What would change my mind:** if analysts say sorting is already fast for them and their real pain is the deep investigation.

---

*More decisions to come: who buys first, the miss-nothing tradeoff, why no auto-actions, rules engine vs LLM, the confidence cut-off, the success metric and the budget structure.*
