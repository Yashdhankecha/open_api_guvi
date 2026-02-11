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
| ⚡ **Zero Extra Latency** | Parallel execution — 3 agents take the **same time as 1** |
| 🛡️ **Graceful Fallback** | If all agents fail, hardcoded response still keeps the conversation alive |
| 📡 **Auto Callback** | Sends a full intelligence report to the GUVI endpoint when threshold is met |
| 🌐 **Multi-Language** | Responds in the scammer's language (Hindi ↔ English ↔ Hinglish) |

---

## 🏗️ Architecture

```
                              ┌──────────────────────────────┐
 ┌──────────────┐             │     POST /analyze            │
 │   Scammer    │────────────▶│                              │
 │  (Message)   │             │  1. Parse & Validate         │
 └──────────────┘             │  2. Regex Intel Scan         │
                              │  3. Determine Missing Fields │
                              │                              │
                              │  ┌── asyncio.gather ──────┐  │
                              │  │                        │  │
                              │  │ 🧓 Confused Uncle      │──│──▶ LLM (temp=0.7)
                              │  │ 🙋 Eager Victim        │──│──▶ LLM (temp=0.85)
                              │  │ 😰 Worried Citizen     │──│──▶ LLM (temp=0.9)
                              │  │                        │  │
                              │  └────────────────────────┘  │
                              │                              │
                              │  4. Score All 3 Responses    │
                              │  5. Pick 👑 Best Reply       │
                              │  6. Merge Intel from ALL 3   │
                              │  7. Log & Accumulate         │
                              │  8. Callback (if ready)      │
                              └──────────────┬───────────────┘
                                             │
                              ┌──────────────▼───────────────┐
                              │    GUVI Callback Endpoint     │
                              │    (Final Scam Report)        │
                              └──────────────────────────────┘
```

---

## 🎭 The Three Agents

Each agent shares the same base persona ("Ramesh", 55-year-old) but uses a **completely different strategy**:

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

After all 3 agents respond, each is scored and the **highest-scoring reply** is sent:

| Component | Weight | What It Measures |
|---|---|---|
| **New Intel Extracted** | 40% | Genuinely new items found (phishing links = 15pts, bank = 12pts, UPI = 10pts) |
| **Targets Missing Fields** | 30% | Bonus if the reply asks about fields we haven't captured yet |
| **Scam Confidence** | 15% | Higher confidence → higher score |
| **Reply Naturalness** | 15% | Sweet spot: 20-200 characters |
| **Safety Penalty** | -20 each | Heavy penalty for danger words (*scam, fraud, police, etc.*) |

> **Important:** The winning agent's reply goes to the scammer, but intelligence is **merged from ALL 3 agents**.

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- An Ollama API key
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/open_api_guvi.git
cd open_api_guvi

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

**Behind the scenes:** 3 agents competed, intel merged, conversation logged, session updated.

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
└── set() deduplication on all fields
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

## 📦 Project Structure

```
open_api_guvi/
├── main.py                  # 🧠 Complete application (~1083 lines)
│   ├── Pydantic Models      #    Request/Response schemas
│   ├── BASE_SYSTEM_PROMPT   #    Shared agent instructions
│   ├── TACTICAL_PERSONAS    #    3 agent definitions
│   ├── score_response()     #    Scoring algorithm
│   ├── merge_intelligence() #    Multi-agent intel merge
│   ├── run_single_agent()   #    Individual agent runner
│   ├── POST /analyze        #    Core multi-agent endpoint
│   └── Utilities            #    Logging, regex, formatting
│
├── requirements.txt         # 📦 Dependencies (8 packages)
├── render.yaml              # 🚀 Render deployment config
├── .env                     # 🔑 API keys (gitignored)
├── .gitignore               # 🚫 Ignore rules
├── PROJECT_EXPLANATION.md   # 📚 Detailed technical docs
├── PANEL_QA_GUIDE.md        # 🎤 Panel Q&A preparation
├── README.md                # 📖 This file
└── conversation_log.txt     # 📝 Auto-generated logs (gitignored)
```

---

## 🛠️ Tech Stack

| Component | Technology | Why |
|---|---|---|
| **Framework** | FastAPI | Async-native, auto-generated docs, blazing fast |
| **LLM** | `gpt-oss:120b-cloud` via Ollama | 120B parameter model for intelligent conversation |
| **Orchestration** | LangChain + LangChain-Ollama | Structured prompts, typed outputs, chain composition |
| **Validation** | Pydantic v2 | Forces LLM to output valid JSON schemas |
| **Parallelism** | `asyncio.gather()` | 3 agents in parallel = same latency as 1 |
| **Server** | Uvicorn | High-performance ASGI server |
| **Deployment** | Render | One-click deploy with `render.yaml` |
| **Monitoring** | UptimeRobot → `/ping` | Prevents cold starts on free tier |

---

## ☁️ Deployment

### Deploy on Render

1. Push the repository to GitHub
2. Connect the repo on [Render Dashboard](https://dashboard.render.com)
3. Render auto-detects `render.yaml` and configures:
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
Regex scan → Find known intel (bank, UPI, phone, links)
      │
      ▼
Determine missing fields → What do we still need?
      │
      ▼
┌─────────────────────────────────────────────┐
│          asyncio.gather() — PARALLEL        │
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
Merge intel from ALL 3 agents
      │
      ▼
Log conversation + Accumulate session intel
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
| 1 agent fails | Other 2 compete normally |
| 2 agents fail | Remaining 1 agent's response is used |
| All 3 fail | Hardcoded fallback: *"Which account is this about? I have multiple. Also your name and employee ID please."* |

The conversation **never breaks**. The scammer always gets a response.

---

## 📝 Conversation Logging

Every interaction is logged with rich formatting:

```
================================================================================
📅 TIMESTAMP: 2026-02-12 01:30:00
🆔 SESSION: session-abc-123
================================================================================

📨 SCAMMER MESSAGE:
Your bank account is blocked! Click this link: bit.ly/fake

HONEYPOT RESPONSE:
Scam Detected: True | Confidence: 0.92 | Type: bank_fraud
Winner Agent: eager_victim (Score: 49.0)

VICTIM REPLY:
Link not opening sir, error aa raha hai. Please send again?

EXTRACTED INTELLIGENCE:
  • Phishing Links: bit.ly/fake
  • Agents Competed: confused_uncle(34), eager_victim(49), worried_citizen(48)
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

---

## 📄 License

This project was built for the **GUVI Hackathon**.

---

<p align="center">
  <strong>🪤 Uski baaton me uljhao. Unhi ke jaaal me phasao. 🎯</strong>
  <br>
  <em>Built with ❤️ to protect innocent people from online scammers.</em>
</p>
