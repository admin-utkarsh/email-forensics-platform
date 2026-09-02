# Sentinel — AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

Built for SIH: a working prototype (not a mockup) that detects phishing/BEC/spoofed
emails, reconstructs the SMTP relay path, geolocates the probable origin, and
generates a forensic report — all from real email header/body analysis.

## What's actually real vs. what to scale up for later rounds

**Real, working logic (not hardcoded):**
- Full RFC 5322 header parsing, `Received:` chain reconstruction, and origin-IP extraction
- SPF/DKIM/DMARC verdict parsing + From/Return-Path/Reply-To alignment checks (classic spoofing indicator)
- A genuinely trained Naive Bayes phishing/BEC text classifier (pure Python, word + bigram features, Laplace smoothing — no compiled dependencies, so it runs on any machine including locked-down/managed Windows laptops), plus rule-based urgency/impersonation-language detection
- URL heuristics (IP-literal links, shorteners, punycode, `@`-obfuscation)
- Domain intelligence: typosquat/lookalike-brand detection (fuzzy match), suspicious-TLD check, DNS resolvability
- IP geolocation via a live API call (ip-api.com) with ISP/proxy/hosting-provider flags
- A weighted, explainable 0–100 risk score with a full breakdown (good for judge Q&A — "why did it flag this?")

**Prototype-scale, documented for scaling up:**
- The classifier is trained on ~90 embedded examples (`backend/nlp_model.py`). It genuinely
  works and demos well, but for the final round, retrain it on a real dataset (Enron-spam,
  Nazario phishing corpus, or your own labeled set) using `train_from_csv()` — the classifier
  logic doesn't change, just the training data.
- Case storage is in-memory (resets on restart). Swap for SQLite/Postgres for persistence —
  the `CASES` dict in `backend/main.py` is the only place that needs to change.
- No authentication/multi-user support yet — add if judges want to see role-based access.
- WHOIS registration-date lookups aren't wired in (DNS resolvability is). Add `python-whois`
  if you want "domain age" as a signal — genuinely new domains are a strong fraud indicator.

## Architecture

```
frontend/index.html   →  static dashboard (paste/upload email, view results, case history)
backend/main.py        →  FastAPI app, wires everything together
backend/header_analysis.py  →  header parsing, relay chain, SPF/DKIM/DMARC, alignment
backend/nlp_model.py        →  trained classifier + linguistic/URL heuristics
backend/intel.py            →  domain intelligence + IP geolocation
backend/risk_engine.py      →  weighted fraud-score fusion
```

## Run it locally

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Then just open `frontend/index.html` directly in your browser (double-click it, or
`open frontend/index.html`). It's already configured to call `http://localhost:8000`.

Two sample emails are included in `sample_emails/` (one phishing, one legitimate) —
the frontend also has "Load phishing sample" / "Load legitimate sample" buttons for
an instant demo without needing a real email.

**Note on geolocation:** the IP geolocation lookup calls a live external API
(ip-api.com). It'll work as soon as your backend has normal internet access —
just not inside this build/test sandbox, which has restricted egress. Deploy it
anywhere with internet access (your laptop, a cloud VM, Render, Railway, etc.)
and the map will populate.

## Deploying for the judges

Simplest path for a hackathon demo:
1. **Backend:** deploy `backend/` to [Render](https://render.com) or
   [Railway](https://railway.app) (free tiers work fine) — both auto-detect
   `requirements.txt` and can run `uvicorn main:app --host 0.0.0.0 --port $PORT`.
2. **Frontend:** change `API_BASE` at the top of the `<script>` in `index.html`
   to your deployed backend URL, then host the single HTML file on
   [Vercel](https://vercel.com), [Netlify](https://netlify.com), or GitHub Pages.
3. Or just run both on your own laptop during the demo — `uvicorn` + opening the
   HTML file works fine for an internal/college round.

## How to present the fraud score to judges

The score is a transparent, weighted sum (see `backend/risk_engine.py`) — not a
black box. Each analyzed email's dashboard shows the exact contribution of each
signal (ML text score, auth failures, domain mismatch, suspicious links, etc.),
which is good material for explaining your methodology during Q&A.

## Suggested next steps before the next round

1. Retrain the classifier on a real phishing/ham dataset (biggest credibility boost).
2. Add a persistent database (SQLite is a 20-minute change) so the case history survives restarts.
3. Add WHOIS domain-age lookup as an extra fraud signal.
4. Add an "Report as Malicious" analyst action + exportable PDF report for the forensic-reporting requirement in the problem statement.
5. If you want live email ingestion (not just paste/upload), an IMAP polling script feeding the same `/api/analyze/text` endpoint is a small addition.
