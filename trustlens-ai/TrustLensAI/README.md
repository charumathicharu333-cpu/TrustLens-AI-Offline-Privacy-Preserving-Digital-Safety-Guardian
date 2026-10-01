# TrustLens AI

**Think Before You Trust. Detect. Explain. Visualize. Protect. Learn.**

An offline-first digital safety assistant. TrustLens uses explainable local rules to inspect messages and URL structure, describe social-engineering patterns, visualize a possible attack path, and suggest safer next steps. It does not claim a black-box AI model or calibrated confidence score.

## Run locally

Requires Python 3.10+ and no third-party packages.

```bash
python3 server.py
```

Open `http://127.0.0.1:8000`. Stop with Ctrl+C. The server binds only to loopback; it is not exposed on your network. Core analysis runs offline. The app uses system fonts and makes no external requests.

## Features

- Offline deterministic text and URL checks, with human-readable reasons.
- Social-engineering patterns: urgency, fear, authority, reward, greed, threats, secrecy, emotional pressure.
- Sensitive-request checks for payments, credentials, and OTPs.
- URL structure checks for HTTP, raw IPs, long links, encoded characters, unusual TLDs, and sensitive paths.
- Digital Trust Passport, explainable 0–100 risk score, safe recommendations, and a possible attack path.
- Safe what-if education, Cyber Mentor lesson, fictional demo examples, family display mode.
- Local SQLite history and local browser learning points with clear-history controls.
- Responsive dark dashboard; no framework/build step needed.

## Architecture

`index.html` is a self-contained interface. `server.py` uses Python's standard library HTTP server, deterministic local rules, and SQLite. `tests/test_engine.py` contains 26 unit tests. API routes include `POST /api/analyze`, `GET /api/analysis/history`, `DELETE /api/analysis/history`, `GET /api/demo/examples`, `GET /api/knowledge-base`, and `GET /api/system/status`.

The same preview page includes a browser-local fallback analyzer so the visual preview remains interactive when opened without the Python server. The authoritative local app uses `server.py`.

## Testing

```bash
python3 -m unittest discover -s tests -v
```

## Privacy and safety

No cloud AI, telemetry, threat-intelligence service, or external lookup is used. History stores scan timestamp, risk label, score, and category, not the analyzed text. Learning points are saved in browser local storage. Clear these from the dashboard's history control and Privacy Center. The analyzer does not save message text, credentials, or OTP values.

Risk score is a transparent sum of rule weights capped at 100. It is not a probability. Model confidence is reported as `null` because no calibrated model is included. A low score is not proof that something is safe. URL checks are structural only, not live reputation or redirect checks. Tamil text is accepted, but current pattern rules and explanations are English-focused; no claim of Tamil-language scam classification is made.

## Demo flow

1. Start the app and select **Bank warning**.
2. Review the risk score, detected pressure signals, and Trust Passport.
3. Select the nodes in **Possible attack path** for explanations.
4. Try **SHARE OTP** and compare the safer **IGNORE** choice.
5. Open Privacy Center to confirm all processing is local.

All examples are fictional educational simulations. No real attack or credential collection is performed.

## Project contents

- `server.py` — local app, API, analysis, SQLite history.
- `index.html` — responsive application UI and standalone preview.
- `tests/test_engine.py` — automated test suite.
- `knowledge_base.json` — offline educational reference categories.
- `.env.example` — optional-service configuration placeholder; no keys required.

## Limitations and future scope

This hackathon implementation is a deterministic rules engine, not a trained ML/NLP model. Sender identity and brand ownership cannot be authenticated without independent verification. Redirect chains and domain reputation are not queried. Future work could add a tested local classifier, curated multilingual patterns, browser extension, encrypted database, and user-consented reputation lookup while preserving the offline core.

## Why Offline?

Messages can contain intimate, financial, or identifying details. The core should not need to transmit that content to a cloud provider to give a useful first-pass explanation. Local analysis reduces exposure and stays useful during network outages.
