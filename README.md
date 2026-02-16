<p align="center">
  <h1 align="center">🍯 Agentic Honeypot</h1>
  <p align="center">
    <strong>Multi-Agent AI System for Scam Detection & Intelligence Extraction</strong>
  </p>
  <p align="center">
    <em>"Uski Baaton Me Uljhana" — Trap scammers using their own words</em>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/FastAPI-0.109+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
    <img src="https://img.shields.io/badge/LangChain-0.1+-1C3C3C?style=for-the-badge&logo=langchain&logoColor=white" alt="LangChain">
    <img src="https://img.shields.io/badge/LLM-120B_params-purple?style=for-the-badge&logo=openai&logoColor=white" alt="LLM">
    <img src="https://img.shields.io/badge/Render-deployed-46E3B7?style=for-the-badge&logo=render&logoColor=white" alt="Render">
  </p>
</p>

---

## 🎯 What Is This?

An **AI-powered cybersecurity honeypot** that doesn't just detect scams — it **engages scammers** using their own narrative against them, extracting actionable intelligence like bank accounts, UPI IDs, phone numbers, and phishing links — all without the scammer ever realizing they're being investigated.

### Traditional vs Our Approach

| Traditional Approach | 🍯 Agentic Honeypot |
|:---:|:---:|
| ❌ Block the scammer | ✅ **Engage** the scammer |
| ❌ Ignore the message | ✅ **Analyze** for intelligence |
| ❌ Warn the user | ✅ **Extract** bank accounts, UPIs, links |
| ❌ Single response strategy | ✅ **3 AI agents compete** for the best reply |

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🤖 **Multi-Agent System** | 3 AI agents run **in parallel** with different trapping strategies |
| 🪤 **"Uski Baaton Me Uljhana"** | Uses scammer's **own words** as weapons — they never suspect detection |
| 🏆 **AI Response Scoring** | Weighted scoring system picks the **optimal reply** automatically |
| 🔀 **Intelligence Merging** | Combines intel from **ALL 3 agents**, not just the winner |
| 🔍 **Dual Extraction Pipeline** | Regex + 3× LLM extraction — nothing slips through |
| ⚡ **25s Timeout with Partial Results** | `asyncio.wait()` with timeout — agents that finish in time are used, laggards are cancelled |
| 🛡️ **Graceful Fallback** | 3-tier execution: Structured → Raw Parse → Smart Context-Aware fallback |
| 📡 **Auto Callback** | Sends a full intelligence report to the GUVI endpoint after ≥18 messages |
| 🌐 **Auto Language Detection** | Detects Hindi / Hinglish / English from the scammer's actual message — responds in the same language |
| 🧹 **Smart Deduplication** | Phone numbers normalized (+91 / 10-digit), UPI & email case-insensitive dedup, all payload arrays deduplicated |
| 🗂️ **Session Intelligence Accumulation** | Intel accumulates across conversation turns per session, ensuring nothing is lost |
| 📋 **Rich Conversation Logging** | Every turn is logged to `conversation_log.txt` with timestamps, intel, and agent competition results |

---

## 🏗️ Architecture

```
                              ┌──────────────────────────────┐
 ┌──────────────┐             │     POST /analyze            │
 │   Scammer    │────────────▶│                              │
 │  (Message)   │             │  1. Parse & Validate         │
 └──────────────┘             │  2. Language Detection       │
                              │  3. Regex Intel Scan         │
                              │  4. Determine Missing Fields │
                              │                              │
                              │  ┌── asyncio.wait(25s) ───┐  │
                              │  │                        │  │
                              │  │ 🧓 Confused Uncle      │──│──▶ LLM (temp=0.7)
                              │  │ 🙋 Eager Victim        │──│──▶ LLM (temp=0.85)
                              │  │ 😰 Worried Citizen     │──│──▶ LLM (temp=0.9)
                              │  │                        │  │
                              │  └────────────────────────┘  │
                              │                              │
                              │  5. Score All Responses      │
                              │  6. Pick 👑 Best Reply       │
                              │  7. Merge Intel from ALL     │
                              │  8. Deduplicate Everything   │
                              │  9. Accumulate Session Intel │
                              │ 10. Log & Callback (if ready)│
                              └──────────────┬───────────────┘
                                             │
                              ┌──────────────▼───────────────┐
                              │    GUVI Callback Endpoint     │
                              │    (Final Scam Report)        │
                              └──────────────────────────────┘
```

---

## 🎭 The Three Agents

Each agent shares the same base persona ("Ramesh", 55-year-old retired government clerk) but uses a **completely different strategy**:

### 🧓 Agent 1: The Confused Uncle
| | |
|---|---|
| **Temperature** | `0.7` — Focused, predictable |
| **Strategy** | Mirrors scammer's words back with genuine confusion |
| **Strength** | Forces scammers to repeat and clarify → they share MORE details |
| **Example** | Scammer: *"Your account is blocked"* → *"Which account sir? SBI or PNB? Can you tell me the account number you see on your side?"* |

### 🙋 Agent 2: The Eager Victim
| | |
|---|---|
| **Temperature** | `0.85` — Balanced creativity |
| **Strategy** | Over-cooperates, but "technical problems" require scammer's details |
| **Strength** | Turns every scammer request BACK on them naturally |
| **Example** | Scammer: *"Transfer ₹5000"* → *"Yes sir immediately! But app is asking sender's UPI ID to verify, what should I enter?"* |

### 😰 Agent 3: The Worried Citizen
| | |
|---|---|
| **Temperature** | `0.9` — Most creative, varied |
| **Strategy** | Genuinely scared, demands scammer prove their identity |
| **Strength** | Fear-driven questions extract employee IDs, names, phone numbers |
| **Example** | Scammer: *"I am from RBI"* → *"Oh my god sir! Please give me your employee ID and direct phone number, my son said I should always note it down!"* |

---

## 🏆 Scoring System

After all agents respond, each is scored and the **highest-scoring reply** is sent:

| Component | Weight | What It Measures |
|---|---|---|
| **New Intel Extracted** | 40% | Genuinely new items found (phishing links = 15pts, bank = 12pts, UPI = 10pts, phone = 8pts, employee IDs = 6pts, email = 5pts) |
| **Targets Missing Fields** | 30% | +15 bonus if the reply asks about fields we haven't captured yet |
| **Scam Confidence** | 15% | Higher confidence → higher score |
| **Reply Naturalness** | 15% | Sweet spot: 20-200 characters |
| **Safety Penalty** | -20 each | Heavy penalty for danger words (*scam, fraud, police, etc.*) |
| **Repetition Penalty** | -10 to -25 | Penalizes high word overlap with previous replies |

> **Important:** The winning agent's reply goes to the scammer, but intelligence is **merged from ALL agents**.

---

## 🛡️ 3-Tier Execution (Anti-Hallucination)

Each agent has **3 fallback layers** to guarantee a unique, contextual response:

| Tier | Strategy | LLM Required? |
|:---:|---|:---:|
| **Tier 1** | Structured Pydantic output via `with_structured_output()` | ✅ Yes |
| **Tier 2** | Raw text + manual JSON extraction (3 parse methods: direct, regex, text cleanup) | ✅ Yes |
| **Tier 3** | Smart context-aware fallback — analyzes scammer's message keywords | ❌ No LLM |

```
Tier 3 analyzes the scammer's actual message:
├── Detects: bank names (SBI, PNB, HDFC...)
├── Detects: OTP/PIN/CVV keywords
├── Detects: links, URLs
├── Detects: UPI keywords (paytm, phonepe, gpay)
├── Detects: names ("Mr. Sharma")
├── Detects: urgency (block, suspend)
├── Detects: employee/officer references
├── Detects: language (Hindi/Hinglish/English)
└── Picks persona-specific reply → random selection

Result: 20+ replies × 3 personas × 2 languages = 120+ unique responses
         → SAME reply NEVER repeats
```

---

## 🔄 Timeout & Partial Results

The system uses `asyncio.wait()` instead of `asyncio.gather()` for **graceful timeout handling**:

| Scenario | Behavior |
|---|---|
| All 3 agents finish in ≤25s | All results scored, best one picked |
| 2 agents finish, 1 times out | Timed-out agent cancelled, remaining 2 compete normally |
| 1 agent finishes | That agent's response (from any tier) is used |
| **No agents finish** | `generate_smart_fallback()` creates a context-aware response |

> The system **never hangs** — there is always a response within the timeout window.

---

## 🧹 Deduplication Pipeline

Intelligence is deduplicated at multiple levels:

| Stage | What It Does |
|---|---|
| **Phone Numbers** | Normalizes `+91XXXXXXXXXX` and `XXXXXXXXXX` to the same canonical form |
| **UPI IDs** | Case-insensitive dedup, strips domain suffixes |
| **Email Addresses** | Case-insensitive dedup, strips domain suffixes |
| **All Arrays** | `deduplicate_payload_arrays()` runs on every exit path (callback, response, fallback) |
| **Session Accumulation** | `accumulate_session_intelligence()` deduplicates after every turn |

---

## 🔍 Scam Type Detection

The system classifies scams into **named types** using both LLM analysis and keyword-based inference:

| Scam Type | Triggers |
|---|---|
| `phishing` | Links, URLs, "click", "verify credentials", "download" |
| `bank_fraud` | Bank names, "account blocked", OTP/CVV/PIN requests, RBI impersonation |
| `upi_fraud` | UPI keywords, QR codes, collect requests, "scan", "send money" |
| `lottery_scam` | "congratulations", "winner", "prize" |
| `tech_support` | "Microsoft", "virus", "antivirus" |
| `job_scam` | "hiring", "work from home", "salary" |
| `customs_scam` | "parcel", "courier", "shipment" |
| `legal_threat` | "arrest", "warrant", "court", "case filed" |
| `investment_scam` | "crypto", "bitcoin", "trading", "mutual fund" |
| `insurance_scam` | "policy", "claim", "LIC", "premium" |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- An Ollama API key
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/honeypot.git
cd honeypot

# Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt
```

### Environment Variables

Create a `.env` file in the root directory:

```env
OLLAMA_API_KEY=your_ollama_api_key_here
HONEYPOT_API_KEY=your_secret_api_key_here
```

| Variable | Purpose |
|---|---|
| `OLLAMA_API_KEY` | Authentication for the Ollama LLM API (`gpt-oss:120b-cloud`) |
| `HONEYPOT_API_KEY` | Secures the `/analyze` endpoint via `x-api-key` header |

### Run Locally

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at `http://localhost:8000`

---

## 📡 API Reference

### `POST /analyze` — Multi-Agent Analysis

The core endpoint. Runs 3 agents in parallel, scores responses, returns the best one.

**Headers:**
```
x-api-key: your_secret_api_key_here
Content-Type: application/json
```

**Request Body:**
```json
{
  "sessionId": "session-abc-123",
  "message": {
    "sender": "scammer",
    "text": "Your bank account is blocked! Click this link immediately: bit.ly/verify-now",
    "timestamp": "2026-02-12T00:30:00Z"
  },
  "conversationHistory": [
    {
      "sender": "scammer",
      "text": "Hello, this is State Bank of India calling.",
      "timestamp": "2026-02-12T00:28:00Z"
    },
    {
      "sender": "user",
      "text": "Haan ji, boliye?",
      "timestamp": "2026-02-12T00:29:00Z"
    }
  ],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "Link not opening sir, error aa raha hai. Please send full link again? Also app is asking for your UPI ID to verify from my side, please share."
}
```

**Behind the scenes:** 3 agents competed, intel merged & deduplicated, conversation logged, session intelligence accumulated, callback sent if threshold met.

### Other Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `GET /analyze` | GET | Health probe (prevents 405 from uptime monitors) |
| `GET /health` | GET | Returns `{ "status": "healthy", "timestamp": "..." }` |
| `GET\|HEAD\|POST /ping` | ANY | Keep-alive for UptimeRobot |
| `GET /` | GET | API info & version |
| `POST /debug` | POST | Echoes raw request (development only) |

---

## 🔍 Intelligence Extraction

### 3-Layer Pipeline

```
Layer 1: REGEX (Pre-LLM)
├── Bank accounts (16-digit numbers)
├── UPI IDs (*@upi, *@paytm, *@ybl, *@oksbi, etc.)
├── Phone numbers (+91XXXXXXXXXX, 10-digit)
├── URLs & short links (https://..., bit.ly/...)
├── Email addresses
├── Names ("my name is X", "I am X")
├── Employee IDs ("Employee ID: XXX")
└── Case references ("Case #XXX", "Ref: XXX")

Layer 2: LLM EXTRACTION (×3 agents)
├── Context-aware extraction
├── Structured JSON output via Pydantic
└── Each agent may catch different intel

Layer 3: MERGE & DEDUP
├── Combine intel from ALL 3 agents
├── Normalize phone numbers (+91... = 10-digit)
├── Case-insensitive UPI dedup
├── Case-insensitive email dedup
└── Deduplicate all arrays (order-preserving)
```

### Intelligence Priority

| Priority | Type | Points |
|:---:|---|:---:|
| 🥇 | Phishing Links | 15 |
| 🥈 | Bank Account Numbers | 12 |
| 🥉 | UPI IDs | 10 |
| 4 | Phone Numbers | 8 |
| 5 | Employee / Reference IDs | 6 |
| 6 | Email Addresses | 5 |

---

## 📡 Auto Callback

When the following conditions are met, the system automatically sends a full intelligence report to the GUVI callback endpoint:

| Condition | Threshold |
|---|---|
| Total messages exchanged | ≥ 18 |
| Scam detected | `true` |
| Confidence score | ≥ 0.7 |

**Callback payload includes:**
- `sessionId` — the conversation session identifier
- `scam_type` — detected scam type (tracked per session)
- `scamDetected` — always `true`
- `totalMessagesExchanged` — running count
- `extractedIntelligence` — accumulated & deduplicated intel across all turns
- `agentNotes` — the winning agent's observations

> The callback is sent **at most once** per session (tracked via `session_callback_sent`).

---

## ❓ Troubleshooting

### ❌ API returns 401 Unauthorized
- Ensure `.env` file exists and has `HONEYPOT_API_KEY`.
- Check if your request header key is exactly `x-api-key`.
- Verify no extra spaces in `.env` value (the code trims whitespace).
- Restart server after `.env` changes.

### ❌ All agents timing out
- The 25-second timeout may not be enough if the LLM endpoint is slow.
- Check `OLLAMA_API_KEY` is valid and the Ollama endpoint is reachable.
- The system will still return a smart fallback response — it never errors out.

---

## 📦 Project Structure

```
honeypot/
├── main.py                  # 🧠 Complete application (~1810 lines)
│   ├── Pydantic Models      #    Request/Response schemas (Message, Metadata, HoneypotRequest, HoneypotResponse, etc.)
│   ├── BASE_SYSTEM_PROMPT   #    Shared agent instructions (~120 lines of detailed persona & rules)
│   ├── TACTICAL_PERSONAS    #    3 agent definitions (confused_uncle, eager_victim, worried_citizen)
│   ├── score_response()     #    Multi-factor scoring algorithm with repetition penalty
│   ├── merge_intelligence() #    Multi-agent intel merge & dedup
│   ├── deduplicate_*()      #    Phone normalization, UPI/email dedup, array dedup
│   ├── generate_smart_fallback()  # 120+ context-aware fallback replies
│   ├── detect_language_from_message()  # Hindi/Hinglish/English auto-detection
│   ├── infer_scam_type_from_message()  # Keyword-based scam classification
│   ├── run_single_agent()   #    Individual agent runner (3-tier: structured → raw → fallback)
│   ├── send_callback()      #    GUVI callback with deduplication
│   ├── POST /analyze        #    Core multi-agent endpoint
│   └── Utilities            #    Logging, regex extraction, formatting, session tracking
│
├── llm_config.py            # ⚙️ LLM configuration helper
├── requirements.txt         # 📦 Dependencies (7 packages)
├── .env                     # 🔑 API keys (gitignored)
├── README.md                # 📖 This file
└── conversation_log.txt     # 📝 Auto-generated conversation logs
```

---

## 🛠️ Tech Stack

| Component | Technology | Why |
|---|---|---|
| **Framework** | FastAPI | Async-native, auto-generated docs, blazing fast |
| **LLM** | `gpt-oss:120b-cloud` via Ollama | 120B parameter model for intelligent conversation |
| **Orchestration** | LangChain + LangChain-Ollama | Structured prompts, typed outputs, chain composition |
| **Validation** | Pydantic v2 | Forces LLM to output valid JSON schemas |
| **Parallelism** | `asyncio.wait()` with timeout | 3 agents in parallel with graceful timeout & partial results |
| **Server** | Uvicorn | High-performance ASGI server |
| **Config** | python-dotenv | Loads `.env` for API keys |
| **Callbacks** | `requests` | Sends intelligence reports to GUVI endpoint |

---

## ☁️ Deployment

### Deploy on Render

1. Push the repository to GitHub
2. Connect the repo on [Render Dashboard](https://dashboard.render.com)
3. Configure build & start:
   - **Build:** `pip install -r requirements.txt`
   - **Start:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - **Health Check:** `GET /health`
4. Set environment variables (`OLLAMA_API_KEY`, `HONEYPOT_API_KEY`) in Render dashboard
5. Deploy!

### Keep-Alive Setup

To prevent Render free-tier cold starts:
1. Set up [UptimeRobot](https://uptimerobot.com) (free)
2. Add HTTP monitor: `GET https://your-app.onrender.com/ping`
3. Interval: every 5-8 minutes

---

## 🔄 How It Works (End-to-End)

```
Scammer sends message
      │
      ▼
POST /analyze (API key verified)
      │
      ▼
Parse request → Extract session, message, history
      │
      ▼
Detect language from scammer's message (Hindi / Hinglish / English)
      │
      ▼
Regex scan → Find known intel (bank, UPI, phone, links, emails, employee IDs)
      │
      ▼
Determine missing fields → What do we still need?
      │
      ▼
┌─────────────────────────────────────────────┐
│       asyncio.wait(timeout=25s) — PARALLEL  │
│                                             │
│  🧓 Confused Uncle  ──▶ LLM ──▶ Score: 34  │
│  🙋 Eager Victim    ──▶ LLM ──▶ Score: 49  │ ◀── 👑 Winner!
│  😰 Worried Citizen ──▶ LLM ──▶ Score: 48  │
│                                             │
└─────────────────────────────────────────────┘
      │
      ▼
Pick best reply (highest score)
      │
      ▼
Merge intel from ALL agents + Deduplicate
      │
      ▼
Accumulate session intelligence across turns
      │
      ▼
Log conversation to conversation_log.txt
      │
      ▼
If ≥18 messages + scam confirmed + confidence ≥0.7
      → POST final report to GUVI callback endpoint
      │
      ▼
Return { "status": "success", "reply": "..." }
      │
      ▼
Scammer receives reply — suspects nothing 🪤
```

---

## 🛡️ Fallback Handling

| Scenario | What Happens |
|---|---|
| Tier 1 fails (structured output) | Tier 2 kicks in — raw text parsed for JSON (3 methods) |
| Tier 2 also fails | Tier 3 — `generate_smart_fallback()` (no LLM, reads scammer's message, 120+ unique replies) |
| 1 agent completely fails | Other 2 compete normally |
| 2 agents fail | Remaining 1 agent's response (from any tier) is used |
| All 3 fail at all tiers | Endpoint-level dynamic fallback using `generate_smart_fallback()` |
| All 3 agents time out | Smart fallback with partially accumulated intel + callback if conditions met |
| Absolute worst case | Last resort: 6 varied language-matched replies (randomly selected, never the same response twice) |

The conversation **never breaks**. The response is **never repeated**.

---

## 📝 Conversation Logging

Every interaction is logged with rich formatting to `conversation_log.txt`:

```
================================================================================
📅 TIMESTAMP: 2026-02-12 01:30:00
🆔 SESSION: session-abc-123
================================================================================

📨 SCAMMER MESSAGE:
Your bank account is blocked! Click this link: bit.ly/fake

📊 CONVERSATION TURN: 3

HONEYPOT RESPONSE:
Scam Detected: True | Confidence: 0.92 | Type: bank_fraud

VICTIM REPLY:
Link not opening sir, error aa raha hai. Please send again?

EXTRACTED INTELLIGENCE:
  • Phishing Links: bit.ly/fake

AGENT NOTES:
[WINNER: eager_victim] Scam detected — phishing link identified | Agents competed: confused_uncle(34), eager_victim(49), worried_citizen(48)
================================================================================
```

---

## 🤝 Contributing

Contributions are welcome! Here are some ideas:

- 🎭 **New Agent Personas** — Add more tactical strategies
- 📊 **Better Scoring** — ML-based response evaluation
- 🗄️ **Persistent Storage** — Replace in-memory dicts with a database
- 🌍 **More Languages** — Add support for regional Indian languages
- 📈 **Analytics Dashboard** — Visualize scam patterns and intel

