# Autonomous IDOR Assessment Agent

A lightweight, **local** browser-based agent that finds **Insecure Direct Object
Reference (IDOR) / broken object-level authorization** issues with minimal input.
Point it at a URL, click **Scan**, and it behaves like a consultant doing
reconnaissance and authorization testing: it crawls with a real browser,
discovers APIs/parameters/objects, ranks what's likely authorization-sensitive,
and tests object-level access across authorization contexts — automatically.

Runs entirely on your laptop. No cloud, no Docker, no Kubernetes.

> ⚠️ **Authorized use only.** Scan only systems you have explicit permission to
> test. The agent requires you to confirm authorization, is **read-only** (issues
> only `GET` requests, never submits forms or state-changing actions), and will
> not contact any host other than the targets you enter.

---

## What's autonomous

You provide **only a target URL (or a list).** The agent automatically:

- **Crawls** with a real Chromium browser (Playwright) — pages, links, navigation,
  and the **XHR/fetch traffic** the app fires (so SPAs and APIs are discovered).
- **Discovers APIs** from observed network calls, **OpenAPI/Swagger** descriptors,
  `sitemap.xml`/`robots.txt`, and by parsing JavaScript for endpoint hints.
- **Discovers parameters & object references** (IDs, UUIDs, sequential numbers,
  hashes) from query strings, paths, and JSON request bodies — no manual entry.
- **Ranks IDOR candidates** by authorization-sensitivity (`userId`, `accountId`,
  `invoiceId`, …) and ID guessability, so the right things get tested first.
- **Infers ownership and tests authorization** across contexts (see below).
- **Scores confidence, reduces noise, and reports** — HTML, PDF, JSON.

### Authorization contexts (how ownership is inferred without a manual map)

The agent always tests an **anonymous** context and one context per **captured
login session**. It learns what each context can reach on its own, then:

- **Forced browsing** — can the *anonymous* context reach user-scoped objects?
- **Cross-user / vertical** — can one user reach another user's (or an admin's)
  objects? Ownership is inferred from each context's own reachable set, so you
  never hand-build an ownership map.
- **Enumeration** — are sequential IDs reachable in bulk by one user?

## Sessions: one-time capture (no manual headers)

Authenticated testing needs real sessions, but you never copy headers by hand.
Run the capture helper once per user — a browser opens, you log in, and the
session (cookies, `Authorization` headers, localStorage tokens) is saved:

```bash
python capture_session.py https://target.example.com user_a --role user
python capture_session.py https://target.example.com user_b --role user
```

Captured sessions appear in the sidebar automatically. **Two users** unlock
cross-user testing. With **no** sessions, the agent still runs unauthenticated
forced-browsing and enumeration checks.

## Scan modes

| Mode | Crawl | Checks | AI |
|------|-------|--------|----|
| **Quick** | shallow, fast | forced-browsing + light enumeration | off |
| **Standard** | full crawl + per-context ownership | all checks | off |
| **Deep** | max depth + extensive discovery | all checks | on (if key set) |

## Install & run

```bash
pip install -r requirements.txt
playwright install chromium      # one-time: browser recon, capture, PDF export

streamlit run app.py
# or
python app.py                    # auto-relaunches under Streamlit and opens a browser
```

Then: tick **authorized** → enter a URL → pick a mode → **Scan**.

## Dashboard

Per-target status (URL, mode, start/end, contexts), result cards (pages, APIs,
parameters, objects, requests seen, risk rating), **ranked candidate list**,
findings with evidence, a color-coded **authorization matrix**, a live scan log,
and **HTML / PDF / JSON** export. Scan history is stored in local SQLite.

## Project structure

```
idor_scanner/
├── app.py                 # Streamlit dashboard (entry point)
├── capture_session.py     # one-time login session capture (CLI)
├── requirements.txt
├── README.md
├── core/
│   ├── browser.py         # Playwright recon: crawl, network capture, API/JS/session
│   ├── analysis.py        # parameter prioritization + candidate ranking
│   ├── ai.py              # optional AI reasoning (graceful fallback)
│   ├── auto_scanner.py    # autonomous orchestrator (scan modes + contexts)
│   ├── discovery.py       # HTTP crawl + parameter/object extraction
│   ├── identifiers.py     # ID classification + sequence detection
│   ├── comparison.py      # similarity / denial detection / redaction
│   ├── scoring.py         # confidence + severity
│   ├── scope.py           # SAFETY: authorization gate + host allow-list
│   ├── session.py         # HTTP principals + rate limiter
│   ├── storage.py         # SQLite scan history
│   ├── reporting.py       # HTML / JSON / PDF exports
│   └── models.py          # dataclasses
├── templates/report.html.j2
└── samples/               # dashboard mockup + screenshot
```

## Safety model

- **Authorization required** before any request is sent.
- **Scope allow-list** — only the hosts of the targets you entered are contacted.
- **Read-only** — only `GET`/`HEAD`/`OPTIONS`; forms are mapped, never submitted.
- **Rate limited**, **enumeration capped**, **evidence redacted** (emails and long
  digit runs masked; snippets length-capped).
- Only finding **metadata** is ever sent to the optional AI layer — never bodies.

## Honest limitations

- **Login can't be fully unattended** without credentials; the one-time capture
  step is the safe, automated substitute — after it, scanning is hands-off.
- Strict cross-user confirmation needs **two** captured sessions.
- WebSocket/GraphQL are discovered (URLs/operations) but not deeply fuzzed.
- Results are point-in-time; validate findings before remediation sign-off.

## Troubleshooting

- **Browser won't launch / PDF fails** → `playwright install chromium`; on some
  Linux/container hosts enable **Chromium --no-sandbox** (sidebar → Advanced, or
  `--no-sandbox` on the capture CLI).
- **`python app.py` doesn't open** → use `streamlit run app.py`.
- **Target “blocked”** → its host wasn't among your entered targets, or you didn't
  confirm authorization.
