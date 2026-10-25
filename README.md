# Sentinel backend

Backend for [Sentinel](../sentinel-frontend), a financial scam detector. It exposes
`POST /analyze` and returns a 0–100 risk score, a risk category, and explainable
warning signs.

The design is deliberately **hybrid**:

1. **Rules** — context-aware regular expressions for high-confidence signals.
2. **Phrase corpus** — a curated phrase list matched with token-level
   Aho–Corasick, specificity weights, negation checks, and per-category caps.
3. **URL checks** — static analysis only; user-supplied links are never fetched.
4. **Scoring** — weighted findings with severity floors and a hard cap.
5. **Optional LLM** — off by default; it can add warnings and raise the score,
   never lower it.

No external service is required to run the core analysis.

## Quick start

Requires Python 3.9+.

```bash
cd sentinel-backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

uvicorn app.main:app --reload --port 8000
```

Open <http://localhost:8000/docs> for the interactive API docs, or check health:

```bash
curl http://localhost:8000/health
```

Run the tests:

```bash
pytest
```

## Connect the frontend

The Vite dev server forwards `/analyze` to `http://localhost:8000` by default.
In `sentinel-frontend/.env.local`:

```bash
VITE_USE_MOCK_API=false
API_PROXY_TARGET=http://localhost:8000
```

Restart `npm run dev`. The header badge changes from “Mock data” to “Live API”.

## API

### `POST /analyze`

```bash
curl -s http://localhost:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{
    "message": "Our AI trading bot guarantees 40% returns every month with zero risk. Send USDT to this wallet.",
    "url": null
  }'
```

Response:

```json
{
  "risk_score": 100,
  "risk_level": "critical",
  "warnings": [
    {
      "title": "Guaranteed high returns",
      "description": "The message promises returns that cannot be guaranteed...",
      "severity": "critical",
      "evidence": ["guarantees 40% returns", "ZERO risk"]
    }
  ]
}
```

- `message`: required, trimmed, 1–5,000 characters.
- `url`: optional `http`/`https` link, up to 2,048 characters.
- Invalid input returns `422` with FastAPI's `detail` list; oversized bodies return
  `413`; rate limiting returns `429` with `Retry-After`.

### `GET /health`

Returns `{"status": "ok", "version": "0.1.0"}`.

## How the analysis works

### 1. Rules

`app/analysis/rules.py` contains named rules such as guaranteed returns, crypto
payment, secrecy, urgency, withdrawal conditions, credential requests, insider
claims, price predictions, and recovery scams. Each rule has a severity, a weight,
and one or more patterns.

Before a match counts, `is_negated()` checks the preceding words. This keeps
“We do **not** guarantee returns” or “We will **never** ask for your password”
from being treated as a scam signal.

### 2. Phrase corpus

`app/data/scam_phrases.json` is a curated corpus of **736 phrases in 36
categories**. Each phrase has a category, weight, and severity. The corpus is
drawn from public scam guidance and research datasets (FTC phishing and imposter
guidance, IRS Dirty Dozen, the Nazario phishing corpus, and more). The `sources`
array at the top of the file records the exact URLs and what each one informed.

Categories cover the campaigns that show up most in real inboxes and SMS:
investment/trading, crypto and wallet drains, payment and gift-card demands,
credential and one-time-code requests, delivery and redelivery fees, account
suspension and verification pressure, tech support, job/task and money-mule
recruiting, loans and debt relief, tax/IRS and government refunds, utility
disconnection, subscription billing, prizes and lotteries, romance, secrecy and
isolation, urgency, threats, impersonation, and recovery-fee scams.

Matching is not a naive word count:

- Text and phrases are tokenized, so `Guaranteed-returns` matches
  `guaranteed returns`, but `100x` does not match inside `100xyz`.
- An Aho–Corasick automaton finds every phrase in one pass.
- Negated matches are discarded.
- Within a category, overlapping matches keep only the most specific phrase, so
  “guaranteed” and “guaranteed returns” do not double count.
- Each category has a cap (`cap` in the JSON, default 18), so repeating a phrase
  cannot inflate the score.
- A corpus finding whose `rule_group` matches an existing rule warning is merged
  into that warning. You get one warning with combined evidence, not two.
- Broad phrases that appear in ordinary mail (“today only”, “no risk”) are kept
  at `medium` severity so a lone generic phrase cannot force a high score.

Adding phrases is a data change, not a code change:

```json
{
  "text": "send usdt to this wallet",
  "category": "payment",
  "weight": 25,
  "severity": "critical"
}
```

Categories, descriptions, and caps live in the `categories` object of the same
file.

### Campaign rules

`rules.py` also defines `_CAMPAIGN_RULES` for the highest-volume bulk categories:
casino/betting spam, missed delivery and redelivery, missed-call/voicemail
notices, and easy-money task or reshipping job offers. They complement the
lexicon and are intentionally low-weight so one ambiguous phrase stays medium.

### 3. URL checks

`analyze_url()` parses the link and looks for raw IPs, `xn--` domains, userinfo
tricks (`paypal.com@evil.example`), shorteners, suspicious TLDs, lookalike brand
names, executable downloads, non-standard ports, and high-pressure paths.

It never makes a network request to the link. Fetching arbitrary user URLs from
the server would add SSRF risk, latency, and privacy problems. If you later add
a reputation lookup, use a dedicated service such as Google Safe Browsing or a
phishing feed rather than fetching the page yourself.

### 4. Scoring

```text
score = min(100, max(sum(weights), severity_floor(strongest_warning)))
```

| Score | Level |
| --- | --- |
| 0–24 | low |
| 25–49 | medium |
| 50–74 | high |
| 75–100 | critical |

Severity floors keep a single strong warning from producing a “low risk” label:

| Strongest warning | Minimum score |
| --- | --- |
| low | 0 |
| medium | 25 |
| high | 50 |
| critical | 75 |

The weights are **heuristics**, not calibrated probabilities. The next step for
production is to collect labeled examples and fit a small model over features
such as rule categories, lexicon categories, URL signals, and message length.
Logistic regression is enough; the output should stay explainable.

### 5. Optional LLM

Set `LLM_ENABLED=true` and `LLM_API_KEY` to use any OpenAI-compatible
chat-completions endpoint:

```bash
LLM_ENABLED=true
LLM_API_KEY=...
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
LLM_TIMEOUT_SECONDS=12
```

The message is sent as untrusted data with a prompt-injection warning. The model's
JSON is validated; evidence quotes must actually appear in the message; its score
can only raise the rule + lexicon score. If the call fails or times out, the
request still succeeds with the deterministic result. Set `LLM_BASE_URL` to a
local Ollama or vLLM endpoint if messages must not leave your infrastructure.

## Configuration

Copy `.env.example` to `.env` or set environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `ENVIRONMENT` | `development` | Deployment label |
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Browser origins allowed to call directly |
| `TRUST_PROXY_HEADERS` | `false` | Use `X-Forwarded-For` for rate limiting behind a trusted proxy |
| `RATE_LIMIT_PER_MINUTE` | `30` | Per-IP limit for `/analyze` |
| `MAX_REQUEST_BYTES` | `32768` | Content-Length limit |
| `LEXICON_ENABLED` | `true` | Use the phrase corpus |
| `LLM_ENABLED` | `false` | Enable the optional model |
| `LLM_API_KEY` | empty | Provider key |
| `LLM_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible endpoint |
| `LLM_MODEL` | `gpt-4o-mini` | Model name |
| `LLM_TIMEOUT_SECONDS` | `12` | Model timeout before falling back |

In development the Vite proxy makes requests same-origin, so CORS is only needed
when the frontend is built with `VITE_API_BASE_URL` pointing at this service.

## Privacy and safety

- Messages are not logged. Logs contain score, level, warning count, message
  length, and duration only.
- The rule and lexicon layers run locally with no external calls.
- The LLM is opt-in and can be pointed at a local model.
- Rate limiting is in-process. Use Redis or your gateway when running multiple
  workers.
- CORS should be restricted to your real frontend origin in production.
- This is an automated estimate, not financial advice.

## Project structure

```text
app/
├── main.py                 FastAPI app, CORS, rate limit, error handling
├── config.py               Environment-backed settings
├── schemas.py              Request/response models
├── limits.py               In-process sliding-window limiter
├── analysis/
│   ├── engine.py           Orchestrates rules, lexicon, URL checks, LLM
│   ├── rules.py            Context-aware regex rules and URL checks
│   ├── lexicon.py          Aho-Corasick phrase matcher and category caps
│   ├── text.py             Tokenization, negation, quote cleanup
│   ├── scoring.py          Dedupe, merge, score, level, response
│   ├── llm.py              Optional OpenAI-compatible second opinion
│   └── types.py            Finding, severity ranks and floors
└── data/
    └── scam_phrases.json   Curated, weighted phrase corpus + sources
benchmarks/
├── evaluate.py             Dataset-agnostic scoring and metrics
├── download.py             Manifest-driven downloader (writes to benchmarks/data)
└── manifests/              One JSON per dataset (columns, labels, source, license)
tests/
├── test_analysis.py        Rule engine and scoring
├── test_api.py             HTTP contract, validation, CORS
├── test_lexicon.py         Phrase matching, negation, caps, merging
└── test_campaign_phrases.py Campaign-level phrase coverage
```

## Benchmarks

`benchmarks/` scores the deterministic engine (no LLM) against labelled public
corpora. Raw datasets contain real phone numbers, emails, and personal messages,
so they are **not committed** — they download into `benchmarks/data/`, which is
gitignored. Only the harness and manifests are versioned.

```bash
cd sentinel-backend
python -m benchmarks.download --all          # UCI SMS, Enron-Spam, wspr SMS phishing
python -m benchmarks.evaluate --list         # show which datasets are present
python -m benchmarks.evaluate uci_sms sms_5971 --thresholds 25,50
```

Each manifest declares the file, delimiter, encoding, and which columns hold the
text and label, so adding a dataset is a JSON file, not code. Labels are
normalized across spellings (`spam`, `Spam`, `smishing`, `phishing`, `ham`,
`0`/`1`). Use `--json report.json` to save full metrics, false alarms, and missed
scams.

Measured on the committed corpus (deterministic score, threshold 50):

| Dataset | Messages | Scam | Precision | Recall |
| --- | --- | --- | --- | --- |
| `uci_sms` | 5,572 | 747 | 0.98 | 0.06 |
| `sms_5971` | 5,971 | 1,127 | 0.98 | 0.05 |
| `enron_spam` | 33,665 | 17,120 | 0.86 | 0.05 |
| `wspr_sms_phishing` | 68,029 | 68,029 | 1.00 | 0.01 |

Read these carefully. The SMS and Enron corpora label **all** unsolicited
marketing as “spam”, so their recall reflects how much *promotional* bulk mail
Sentinel flags, not scam detection. `wspr_sms_phishing` is almost entirely
non-English casino/lottery spam, which the English corpus intentionally does not
cover. Precision stays high throughout, which is the important property for a
tool that must not cry wolf. At the medium threshold (25) recall roughly doubles
across every corpus.

## Known limitations

- English only.
- The corpus covers known wording; paraphrasing and new scam formats can slip
  through. Recall on general “spam” corpora is low by design, because those
  labels include ordinary marketing that is not a scam.
- Non-English bulk SMS (a large share of global spam) is out of scope until
  multilingual phrases are added.
- We do not fetch or reputation-check URLs at analysis time.
- Weights are evidence-strength heuristics, not calibrated probabilities.

These are deliberate trade-offs for a fast, explainable first version. The next
useful additions are multilingual phrases, URL reputation feeds, and fitting a
small explainable model over the existing features using the benchmark harness.

## Docker

```bash
docker build -t sentinel-backend .
docker run --rm -p 8000:8000 sentinel-backend
```
# sentinel backend
