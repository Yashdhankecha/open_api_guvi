# 🍯 Agentic Honey-Pot for Scam Detection & Intelligence Extraction

> **An AI-powered multi-agent FastAPI honeypot that runs 3 agents in parallel to detect scams and extract maximum intelligence — trapping scammers in their own words.**

---

## 📋 Table of Contents

1. [Project Overview](#-project-overview)
2. [Tech Stack](#-tech-stack)
3. [Architecture & Flow](#-architecture--flow)
4. [File Structure](#-file-structure)
5. [Data Models (Pydantic Schemas)](#-data-models-pydantic-schemas)
6. [API Endpoints](#-api-endpoints)
7. [AI Agent — "Ramesh Uncle" Persona](#-ai-agent--ramesh-uncle-persona)
8. [Intelligence Extraction Pipeline](#-intelligence-extraction-pipeline)
9. [Session Management & Callback System](#-session-management--callback-system)
10. [Conversation Logging](#-conversation-logging)
11. [Deployment (Render)](#-deployment-render)
12. [Environment Variables](#-environment-variables)
13. [How It Works (End-to-End)](#-how-it-works-end-to-end)

---

## 🎯 Project Overview

This project is an **Agentic Honeypot** — a cybersecurity tool designed for a **GUVI Hackathon**. Instead of simply blocking scam messages, it takes an offensive approach:

| Traditional Approach | This Honeypot's Approach |
|---|---|
| Block the scammer | **Engage** the scammer |
| Ignore the message | **Analyze** the message for intel |
| Warn the user | **Waste the scammer's time** while extracting bank accounts, UPI IDs, phone numbers, and phishing links |

The system uses an **LLM (Large Language Model)** to role-play as a confused, non-tech-savvy Indian uncle ("Ramesh Uncle") who keeps the scammer engaged while covertly extracting their personal/financial details.

---

## 🛠 Tech Stack

| Component | Technology | Purpose |
|---|---|---|
| **Backend Framework** | FastAPI | High-performance async API server |
| **AI/LLM** | LangChain + ChatOllama | LLM orchestration with structured output |
| **LLM Model** | `gpt-oss:120b-cloud` via Ollama API | The brain of the honeypot agent |
| **Data Validation** | Pydantic v2 | Request/response schema validation |
| **HTTP Client** | Requests | Sending callback results to GUVI endpoint |
| **Environment Mgmt** | python-dotenv | Loading `.env` secrets |
| **Server** | Uvicorn | ASGI server for FastAPI |
| **Deployment** | Render | Cloud hosting platform |

### Dependencies (`requirements.txt`)

```
fastapi>=0.109.0
uvicorn>=0.27.0
pydantic>=2.5.0
langchain>=0.1.0
langchain-ollama>=0.0.1
langchain-core>=0.1.0
python-dotenv>=1.0.0
requests>=2.31.0
```

---

## 🏗 Architecture & Flow

```
┌──────────────┐         ┌──────────────────────────────┐
│   Scammer    │────────▶│     FastAPI  /analyze         │
│  (Message)   │         │                              │
└──────────────┘         │  1. Parse & validate request  │
                         │  2. Analyze known intelligence │
                         │  3. Determine missing fields   │
                         │                              │
                         │  ┌─── asyncio.gather ───────┐ │
                         │  │                          │ │
                         │  │  🧓 Agent 1: Confused     │ │───▶ LLM (temp=0.7)
                         │  │     Uncle                │ │
                         │  │                          │ │
                         │  │  🙋 Agent 2: Eager        │ │───▶ LLM (temp=0.85)
                         │  │     Victim               │ │
                         │  │                          │ │
                         │  │  😰 Agent 3: Worried      │ │───▶ LLM (temp=0.9)
                         │  │     Citizen              │ │
                         │  │                          │ │
                         │  └──────────────────────────┘ │
                         │                              │
                         │  4. Score all 3 responses     │
                         │  5. Pick BEST reply (👑)      │
                         │  6. Merge intel from ALL 3    │
                         │  7. Log + accumulate session  │
                         │  8. Send callback (if ready)  │
                         └──────────┬───────────────────┘
                                    │
                         ┌──────────▼───────────────────────┐
                         │      GUVI Callback Endpoint       │
                         │  hackathon.guvi.in/api/...        │
                         │  (Receives final scam report)     │
                         └───────────────────────────────────┘
```

---

## 📁 File Structure

```
open_api_guvi/
├── main.py               # 🧠 Entire application (872 lines) — API, AI agent, intelligence pipeline
├── requirements.txt      # 📦 Python dependencies
├── render.yaml           # 🚀 Render deployment configuration
├── .env                  # 🔑 API keys (OLLAMA_API_KEY, HONEYPOT_API_KEY)
├── .gitignore            # 🚫 Ignores .env, __pycache__, logs, venv
└── conversation_log.txt  # 📝 Auto-generated conversation logs (gitignored)
```

> **Note:** The entire application lives in a single `main.py` file — models, routes, AI logic, intelligence extraction, and utility functions are all co-located.

---

## 📐 Data Models (Pydantic Schemas)

### Request Models

#### `Message`
```python
{
    "sender": "scammer",        # "scammer" or "user"
    "text": "Your account is blocked! Send OTP now!",
    "timestamp": "2026-02-11T01:00:00Z"  # Optional (str or int)
}
```

#### `Metadata`
```python
{
    "channel": "SMS",           # SMS / WhatsApp / Email / Chat
    "language": "English",      # Language used by scammer
    "locale": "IN"              # Country/region
}
```

#### `HoneypotRequest` (Main Request Body)
```python
{
    "sessionId": "abc-123",
    "message": { ... },                    # Current scammer message
    "conversationHistory": [ ... ],        # Array of previous Message objects
    "metadata": { ... }                    # Channel/language context
}
```
> Supports both `sessionId` / `session_id` and `conversationHistory` / `conversation_history` field naming conventions for flexibility.

### Response Models

#### `HoneypotResponse` (LLM Structured Output)
```python
{
    "status": "success",
    "scamDetected": true,
    "confidenceScore": 0.92,
    "reply": "Oh wait, my screen went dark again. Which bank did you say?",
    "engagementMetrics": {
        "engagementDurationSeconds": 180,
        "totalMessagesExchanged": 5
    },
    "extractedIntelligence": {
        "bankAccounts": ["1234567890123456"],
        "upiIds": ["scammer@paytm"],
        "phoneNumbers": ["+919876543210"],
        "phishingLinks": ["http://bit.ly/fake-link"],
        "emailAddresses": ["fraud@scam.com"]
    },
    "agentNotes": "Scammer is impersonating bank officer...",
    "scamType": "bank_fraud"
}
```

> **Simplified API Response:** The actual response sent to the API caller is a simplified version containing only `status` and `reply` — the full intelligence data is accumulated internally.

---

## 🌐 API Endpoints

### 1. `POST /analyze` — **Multi-Agent Core Endpoint** 🧠
The primary endpoint that runs **3 AI agents in parallel**, scores their responses, and returns the best one.

| Aspect | Detail |
|---|---|
| **Auth** | Requires `x-api-key` header |
| **Input** | `HoneypotRequest` JSON body |
| **Output** | `{ "status": "success", "reply": "..." }` |
| **Process** | Parses message → Analyzes intel → Launches 3 agents → Scores responses → Picks best → Merges intel from ALL agents → Logs → Callback |

### 2. `GET /analyze` — **Health Probe for /analyze**
Returns a simple "alive" message. Exists to prevent `405 Method Not Allowed` errors from uptime monitors that send GET requests.

### 3. `GET /health` — **Health Check** ❤️
```json
{ "status": "healthy", "timestamp": "2026-02-11T01:00:00" }
```

### 4. `GET|HEAD|POST /ping` — **Keep-Alive** 🏓
Lightweight endpoint for **UptimeRobot** monitoring. Returns plain text `"alive"`. Accepts GET, HEAD, and POST methods.

### 5. `GET /` — **Root Info**
Returns API metadata (name, version, description, available endpoints).

### 6. `POST /debug` — **Debug Endpoint** 🐛
Echoes back the raw request body and headers — useful during development.

---

## 🎭 Multi-Agent System — 3 Agents, 1 Winner

The system now runs **3 different AI agents in parallel** using `asyncio.gather()`. Each agent has the same "Ramesh Uncle" base persona but uses a **different tactical approach** to trap the scammer:

### Core Philosophy: **"Uski Baaton Me Uljhana"** 🪤
All agents follow the **golden rule** — never reveal suspicion, instead:
- **READ** the scammer's message and identify their CLAIMS
- **USE** their exact terminology and narrative back at them
- **PLAY INTO** their story to trick them into sharing details
- The scammer should feel like they're "winning" while they're actually giving away intel

### Agent 1: 🧓 **The Confused Uncle** (Temperature: 0.7)
| Aspect | Detail |
|---|---|
| **Strategy** | Mirrors the scammer's exact words back with genuine confusion |
| **Strength** | Forces scammer to repeat and clarify → they share MORE details |
| **Weapon** | Has multiple bank accounts (SBI, PNB, HDFC), always asks "which one?" |
| **Example** | Scammer: "Your account is blocked" → "Which account sir? SBI or PNB? Can you tell me the account number you see on your side?" |

### Agent 2: 🙋 **The Eager Victim** (Temperature: 0.85)
| Aspect | Detail |
|---|---|
| **Strategy** | Over-cooperates but his phone/app keeps asking for SCAMMER's details to proceed |
| **Strength** | Turns every scammer request BACK on them naturally |
| **Weapon** | Creates believable "technical issues" that require scammer's info as the solution |
| **Example** | Scammer: "Transfer ₹5000" → "Yes sir immediately! But app is asking sender's UPI ID to verify, what should I enter?" |

### Agent 3: 😰 **The Worried Citizen** (Temperature: 0.9)
| Aspect | Detail |
|---|---|
| **Strategy** | Genuinely scared, panics about losing money, demands scammer prove their identity |
| **Strength** | Fear-driven questions extract employee IDs, names, phone numbers |
| **Weapon** | Uses emotional language that makes scammers lower their guard |
| **Example** | Scammer: "I am from RBI" → "Oh my god sir! Please give me your employee ID and direct phone number, my son said I should always note it down!" |

### 🏆 Scoring System

After all 3 agents respond, a **scoring function** evaluates each response:

| Score Component | Weight | What It Measures |
|---|---|---|
| **New Intel Extracted** | 40% | Counts genuinely new items (phishing links = 15pts, bank accounts = 12pts, UPI = 10pts, etc.) |
| **Targets Missing Intel** | 30% | Bonus if the reply asks about fields we HAVEN'T captured yet |
| **Scam Confidence** | 15% | Higher confidence = higher score |
| **Reply Naturalness** | 15% | Sweet spot: 20-200 characters (too short = weak, too long = suspicious) |
| **Safety Penalty** | -20 each | Heavy penalty if reply contains danger words (scam, fraud, police, etc.) |

### 🔀 Intelligence Merging

Even though only **one agent's reply** is sent to the scammer, intelligence is **merged from ALL 3 agents**. This means:
- Agent 1 might detect a phone number that Agent 2 missed
- Agent 3 might extract a UPI ID that the others didn't catch
- The final intel profile combines the best of all three

### Scam Detection Criteria
All agents look for:
- **Urgency Tactics** — "Act NOW", "Account blocked"
- **Sensitive Info Requests** — OTP, PIN, CVV, bank details
- **Authority Claims** — Bank officials, police, tech support
- **Suspicious Links** — bit.ly, ngrok, unofficial domains

---

## 🔍 Intelligence Extraction Pipeline

Intelligence is extracted via a **two-pronged approach**:

### 1. Regex-Based Extraction (`analyze_known_intelligence()`)

Before the LLM even runs, the system scans all conversation text using regex patterns to find:

| Data Type | Pattern Examples |
|---|---|
| **Bank Accounts** | 16-digit numbers, formatted card numbers |
| **UPI IDs** | `*@upi`, `*@paytm`, `*@ybl`, `*@oksbi` etc. |
| **Phone Numbers** | `+91XXXXXXXXXX`, 10-digit starting with 6-9 |
| **Phishing Links** | `https://...`, `bit.ly/...` |
| **Email Addresses** | Standard email regex |
| **Scammer Names** | "My name is X", "I am X" |
| **Employee IDs** | "Employee ID: XXX" |
| **Case References** | "Case #XXX", "Ref: XXX" |

### 2. LLM-Based Extraction
The LLM also identifies and returns structured intelligence in its response, which gets merged with the regex-based findings.

### 3. Deduplication (`deduplicate_intelligence()`)
Prevents duplicate entries by:
- **Phone numbers:** Normalizing `+91XXXXXXXXXX` and `XXXXXXXXXX` to the same entry
- **UPI IDs:** Deduplicating by base ID
- **Email addresses:** Deduplicating by normalized base
- **Others:** Standard `set()` deduplication

### 4. Missing Intelligence Prompting (`get_missing_intelligence_prompt()`)
The system tracks what intelligence has **already** been captured and dynamically instructs the LLM to ask about **missing** fields. For example:
- If no bank account captured → "Ask them to confirm which account number they have on file"
- If no UPI ID captured → "Ask if they can share their UPI ID for verification"
- Focuses on the **top 3 missing priorities** each turn

---

## 🗂 Session Management & Callback System

### In-Memory Session Storage
Three dictionaries maintain session state:

```python
session_intelligence: Dict[str, Dict]   # Accumulated intel per session
session_timestamps: Dict[str, datetime]  # Last activity per session
session_callback_sent: Dict[str, bool]   # Whether callback was sent
```

### Callback Trigger
A callback is sent to GUVI's endpoint (`hackathon.guvi.in/api/updateHoneyPotFinalResult`) when **all** conditions are met:

| Condition | Value |
|---|---|
| Total messages exchanged | ≥ **18** |
| Scam detected | `true` |
| Confidence score | ≥ **0.7** |
| Callback not already sent | `true` |

### Callback Payload
```json
{
    "sessionId": "abc-123",
    "scamDetected": true,
    "totalMessagesExchanged": 20,
    "extractedIntelligence": {
        "bankAccounts": [...],
        "upiIds": [...],
        "phishingLinks": [...],
        "phoneNumbers": [...],
        "suspiciousKeywords": ["urgent", "verify now", "account blocked", "OTP", "immediately"]
    },
    "agentNotes": "Scammer impersonating SBI official..."
}
```

---

## 📝 Conversation Logging

Every interaction is logged to `conversation_log.txt` with a rich, human-readable format:

```
================================================================================
📅 TIMESTAMP: 2026-02-11 01:30:00
🆔 SESSION: abc-123
================================================================================

📨 SCAMMER MESSAGE:
----------------------------------------
Your account has been compromised! Share your OTP immediately.

📊 CONVERSATION TURN: 3

HONEYPOT RESPONSE:
----------------------------------------
Scam Detected: True
Confidence: 0.92
Scam Type: bank_fraud

VICTIM REPLY:
Wait... which account sir? I have SBI and PNB both...

EXTRACTED INTELLIGENCE:
  • Phone Numbers: +919876543210

AGENT NOTES:
Scammer using urgency tactics, impersonating bank official...

================================================================================
```

---

## 🚀 Deployment (Render)

The app is configured for deployment on **Render** via `render.yaml`:

```yaml
services:
  - type: web
    name: agentic-honeypot
    env: python
    buildCommand: pip install -r requirements.txt
    startCommand: uvicorn main:app --host 0.0.0.0 --port $PORT
    envVars:
      - key: PYTHON_VERSION
        value: 3.10.0
      - key: OLLAMA_API_KEY
        sync: false
      - key: HONEYPOT_API_KEY
        sync: false
    healthCheckPath: /health
```

- **Build:** Installs Python dependencies
- **Start:** Launches Uvicorn ASGI server
- **Health Check:** Uses `/health` endpoint
- **Keep-Alive:** `/ping` endpoint integrated with UptimeRobot to prevent cold starts

---

## 🔑 Environment Variables

| Variable | Purpose |
|---|---|
| `OLLAMA_API_KEY` | Authentication key for the Ollama LLM API |
| `HONEYPOT_API_KEY` | API key required in `x-api-key` header for `/analyze` endpoint |

---

## 🔄 How It Works (End-to-End)

```
Step 1  ─── Scammer sends a message (via the hackathon platform)
              │
Step 2  ─── POST /analyze receives the message + conversation history
              │
Step 3  ─── API key is verified via x-api-key header
              │
Step 4  ─── Request body is parsed into HoneypotRequest model
              │
Step 5  ─── Regex engine scans ALL text for known intelligence
              │
Step 6  ─── System determines what intelligence is MISSING
              │
Step 7  ─── 3 AGENTS LAUNCHED IN PARALLEL (asyncio.gather):
            ┌──────────────────────────────────────────────┐
            │ 🧓 Confused Uncle  (temp=0.7)  → LLM call 1 │
            │ 🙋 Eager Victim    (temp=0.85) → LLM call 2 │
            │ 😰 Worried Citizen (temp=0.9)  → LLM call 3 │
            └──────────────────────────────────────────────┘
              │
Step 8  ─── Each response is SCORED:
            • New intel extracted (40%)
            • Targets missing fields (30%)
            • Scam confidence (15%)
            • Reply naturalness (15%)
            • Safety penalty check
              │
Step 9  ─── 👑 BEST response selected as the reply to send
              │
Step 10 ─── Intelligence MERGED from ALL 3 agents (not just winner)
              │
Step 11 ─── Engagement metrics calculated (duration, message count)
              │
Step 12 ─── Session intelligence accumulated and deduplicated
              │
Step 13 ─── Conversation logged to conversation_log.txt
              │
Step 14 ─── If conditions met (≥18 msgs, scam detected, confidence ≥0.7):
            → Final report sent to GUVI callback endpoint
              │
Step 15 ─── Simplified response { status, reply } returned to caller
              │
Step 16 ─── The reply is sent back to the scammer as the "victim's" response
```

---

## 🛡 Fallback Handling

If all 3 LLM calls fail for any reason, the system returns a **hardcoded fallback response** that still:
- Marks `scamDetected: true`
- Sets a reasonable `confidenceScore: 0.75`
- Sends a generic but engaging victim reply asking for account details and employee ID
- Logs the error in `agentNotes`

If only 1 or 2 agents fail, the system still picks the best from the successful ones.

This ensures the conversation **never breaks** — the scammer always gets a response.

---

## 🏆 Key Features Summary

| Feature | Description |
|---|---|
| 🤖 **Multi-Agent Parallel System** | 3 AI agents with different strategies compete to find the best response |
| 🪤 **"Uski Baaton Me Uljhana"** | Traps scammers using their OWN words — they never suspect detection |
| 🧓🙋😰 **3 Tactical Personas** | Confused Uncle, Eager Victim, Worried Citizen — each excels at different scam types |
| � **AI Response Scoring** | Weighted scoring system picks the optimal reply based on intel potential |
| 🔀 **Intelligence Merging** | Combines intel from ALL agents even if only one reply is used |
| 🔍 **Multi-Layer Intel Extraction** | Regex + 3× LLM extraction pipeline |
| 📊 **Session Intelligence Accumulation** | Builds a complete intelligence profile across messages |
| 🌐 **Multi-Language Support** | Responds in the same language as the scammer (Hindi/English) |
| 📡 **Auto Callback** | Sends final report to GUVI when enough intel is gathered |
| 📝 **Rich Conversation Logging** | Human-readable logs with emojis and structured formatting |
| 🔄 **Smart Deduplication** | Normalizes phone numbers, UPIs, emails, and employee IDs |
| 🛡 **Graceful Fallback** | If all agents fail, hardcoded response still extracts intel |
| ⚡ **Zero Added Latency** | Parallel execution — 3 agents take same time as 1 |
| 🚀 **One-Click Deploy** | Ready-to-deploy on Render with `render.yaml` |

---

*Built for the GUVI Hackathon — Protecting innocent people by turning the tables on scammers. Uski baaton me uljhao. 🪤🎯*
