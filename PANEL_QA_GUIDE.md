# 🎤 Panel Q&A Guide — Agentic Honeypot (Multi-Agent System)

> Yeh document panel ke liye taiyaar kiya gaya hai — isme har ek cheez detail me hai: agents kaun hai, environment kaise setup hai, comparison kaise hota hai, aur response kaise jaata hai.
> 
> **v2 Update:** Ab system me 3-tier execution hai — Structured Output → Raw Text Parsing → Smart Context-Aware Fallback. Koi bhi message pe static/repetitive reply NAHI aayega.

---

## 📋 Quick Index

| Topic | Jump To |
|---|---|
| Project ka ek-line summary | [Section 1](#1--project-ka-ek-line-summary) |
| Environment Setup (kya install hai, kya config hai) | [Section 2](#2--environment-setup) |
| Teeno Agents kaun hai aur kya karte hai | [Section 3](#3--teeno-agents-detail-me) |
| Agents ka Comparison kaise hota hai (Scoring) | [Section 4](#4--agents-ka-comparison-scoring-system) |
| Response kaise jaata hai (Full Flow) | [Section 5](#5--response-kaise-jaata-hai-full-flow) |
| Intelligence kaise extract hoti hai | [Section 6](#6--intelligence-extraction-pipeline) |
| Session Management aur Callback | [Section 7](#7--session-management-aur-callback) |
| 3-Tier Execution Strategy (Anti-Hallucination) | [Section 8](#8--3-tier-execution-strategy) |
| Panel ke expected questions aur answers | [Section 9](#9--panel-ke-expected-questions-aur-answers) |

---

## 1. 🎯 Project ka Ek-Line Summary

**"Ek AI honeypot jo scammers ko unhi ki baaton me uljhaata hai — 3 agents parallel me chalte hain, sabse best reply scammer ko jaata hai, aur saari intelligence secretly extract hoti hai."**

### What it actually does:
```
Scammer ka message aata hai
    → 3 AI agents simultaneously uska analysis karte hain
    → Har agent ek alag strategy use karta hai (confused / eager / scared)
    → Scoring system sabse best reply choose karta hai
    → Intel teeno se merge hoti hai
    → Scammer ko ek believable reply jaata hai
    → Scammer ko pata bhi nahi chalta
```

---

## 2. 🛠 Environment Setup

### 2.1 Tech Stack

| Layer | Technology | Version | Kyun use kiya |
|---|---|---|---|
| **Language** | Python | 3.10+ | FastAPI support + async |
| **Web Framework** | FastAPI | ≥0.109.0 | Async endpoints, auto docs, speed |
| **AI Orchestration** | LangChain | ≥0.1.0 | LLM ko structured prompts bhejne ke liye |
| **LLM Connector** | LangChain-Ollama | ≥0.0.1 | Ollama API se connect karne ke liye |
| **LLM Model** | `gpt-oss:120b-cloud` | 120B params | Ollama cloud pe hosted model |
| **Structured Output** | Pydantic v2 | ≥2.5.0 | LLM ka output force karte hain JSON me |
| **Server** | Uvicorn | ≥0.27.0 | ASGI server for async Python |
| **Env Management** | python-dotenv | ≥1.0.0 | `.env` file se keys load karna |
| **HTTP Client** | Requests | ≥2.31.0 | GUVI callback endpoint ko data bhejna |
| **Parallel Execution** | asyncio (built-in) | — | Teeno agents ko ek saath chalana |
| **Deployment** | Render | — | Cloud hosting |

### 2.2 File Structure

```
open_api_guvi/
├── main.py               # 🧠 Pura application (1083 lines)
│                          # - Models (Pydantic schemas)
│                          # - 3 Agent personas + base prompt
│                          # - Scoring system
│                          # - Intelligence extraction (regex + LLM)
│                          # - FastAPI endpoints
│                          # - Session management
│                          # - Callback system
│
├── requirements.txt      # 📦 Python dependencies (8 packages)
├── render.yaml           # 🚀 Render deployment config
├── .env                  # 🔑 API keys (2 keys)
├── .gitignore            # 🚫 Ignore list
└── conversation_log.txt  # 📝 Auto-generated logs (gitignored)
```

### 2.3 Environment Variables (`.env`)

| Variable | Purpose | Kahan use hota hai |
|---|---|---|
| `OLLAMA_API_KEY` | Ollama LLM API ki authentication key | `run_single_agent()` me — teeno agents isse LLM call karte hain |
| `HONEYPOT_API_KEY` | API security key | `verify_api_key()` me — har `/analyze` request pe check hota hai header `x-api-key` se |

### 2.4 Deployment Config (`render.yaml`)

```yaml
services:
  - type: web
    name: agentic-honeypot
    env: python
    buildCommand: pip install -r requirements.txt      # Dependencies install
    startCommand: uvicorn main:app --host 0.0.0.0 --port $PORT  # Server start
    healthCheckPath: /health                           # Render checks isse
```

### 2.5 API Endpoints

| Endpoint | Method | Purpose | Auth Required |
|---|---|---|---|
| `/analyze` | **POST** | 🧠 Main endpoint — scammer ka message analyze karo | ✅ `x-api-key` header |
| `/analyze` | GET | UptimeRobot ke liye alive check | ❌ |
| `/health` | GET | Server health check | ❌ |
| `/ping` | GET/HEAD/POST | Keep-alive for UptimeRobot | ❌ |
| `/` | GET | API info | ❌ |
| `/debug` | POST | Raw request echo (development) | ❌ |

---

## 3. 🎭 Teeno Agents (Detail Me)

### 3.0 Base Prompt (Shared by ALL 3 agents)

Teeno agents ko ek **common base prompt** milta hai (`BASE_SYSTEM_PROMPT` — line 333-388 in main.py):

```
🎯 Primary Objective: MAXIMIZE intelligence extraction in FEWEST turns
🪤 Golden Rule: "USKI BAATON ME ULJHANA" — scammer ki baaton ko unhi pe ulta karo
🚫 NEVER reveal suspicion
🗣️ Match scammer's language (Hindi → Hinglish, English → Simple English)
📏 Keep replies SHORT (1-3 sentences)
🔐 NEVER mention police, fraud, scam, cybercrime
```

**Intelligence Priority Order (ALL agents follow this):**
1. 🔗 Phishing Links (highest value)
2. 🏦 Bank Account Numbers
3. 💳 UPI IDs
4. 📞 Phone Numbers
5. 🪪 Employee / Reference IDs
6. 📧 Email Addresses

---

### 3.1 🧓 Agent 1: "THE CONFUSED UNCLE"

| Property | Value |
|---|---|
| **Internal Name** | `confused_uncle` |
| **Temperature** | `0.7` (most focused/predictable) |
| **Code Location** | `TACTICAL_PERSONAS[0]` — line 392-408 |
| **Persona** | 55-year-old retired government clerk |
| **Core Strategy** | Scammer ki baat confusingly repeat karta hai — jisse scammer ZYADA details deta hai |

**Kaise kaam karta hai:**
```
Scammer: "Your account is blocked"
Uncle:   "Which account sir? I have SBI, PNB, HDFC — 
          can you tell me the account number you see on your side?"
```

**Weapons:**
- Multiple bank accounts hai — always asks "which one?"
- Scammer ki exact words mirror karta hai with confusion
- Scammer ko repeat aur clarify karne pe majboor karta hai
- Diary me likhna chahta hai — name, ID maangta hai

**Best for:** Bank fraud, KYC scams — jab scammer bank details ke baare me baat karta hai

**Temperature kya karti hai:** `0.7` = Zyada focused aur repeatable responses. Same type ke message pe consistent reply aayega.

---

### 3.2 🙋 Agent 2: "THE EAGER VICTIM"

| Property | Value |
|---|---|
| **Internal Name** | `eager_victim` |
| **Temperature** | `0.85` (balanced creativity) |
| **Code Location** | `TACTICAL_PERSONAS[1]` — line 410-425 |
| **Persona** | 55-year-old who desperately wants to comply |
| **Core Strategy** | "Haan sir, abhi karta hoon!" bolke scammer ki request ULTI kar deta hai |

**Kaise kaam karta hai:**
```
Scammer: "Transfer ₹5000 to this account"
Eager:   "Yes sir I will do immediately! But my app is 
          asking for sender's UPI ID to verify — kya enter karun?"
```

**Weapons:**
- Phone/app me "technical problems" aa rahe hain jo solve hone ke liye SCAMMER ki details chahiye
- Scammer ki har request pe "haan sir!" bol ke uski details maangta hai
- Believable scenarios create karta hai jisme scammer ki info "solution" hai

**Best for:** UPI fraud, link scams — jab scammer payment ya verification maang raha hai

**Temperature kya karti hai:** `0.85` = Thoda creative — har baar different "technical problem" create karta hai

---

### 3.3 😰 Agent 3: "THE WORRIED CITIZEN"

| Property | Value |
|---|---|
| **Internal Name** | `worried_citizen` |
| **Temperature** | `0.9` (most creative/varied) |
| **Code Location** | `TACTICAL_PERSONAS[2]` — line 427-443 |
| **Persona** | 55-year-old genuinely scared person |
| **Core Strategy** | Darr ke maare scammer se identity proof maangta hai |

**Kaise kaam karta hai:**
```
Scammer: "I am from RBI, your account will be seized"
Worried: "Oh my god sir! Please give me your employee ID 
          and direct phone number — my son said I should always note it down!"
```

**Weapons:**
- Paisa doobne ka darr — emotional language use karta hai
- Scammer ki identity prove karne ko bolta hai (employee ID, name, phone)
- "Official proof" maangta hai (link, email, reference number)
- Emotional manipulation se scammer guard down karta hai

**Best for:** Authority impersonation scams (RBI, police, bank officer) — jab scammer kisi authority ka naam le ke daraa raha hai

**Temperature kya karti hai:** `0.9` = Most creative/unpredictable — varied emotional responses

---

### 3.4 Agents ka Comparison Table

| Feature | 🧓 Confused Uncle | 🙋 Eager Victim | 😰 Worried Citizen |
|---|---|---|---|
| **Temperature** | 0.7 (focused) | 0.85 (balanced) | 0.9 (creative) |
| **Emotion** | Confusion | Eagerness | Fear |
| **Strategy** | Mirror + Clarify | Comply + Reverse | Panic + Demand Proof |
| **Reply Style** | "Which one sir?" | "Yes sir! But app asks..." | "Oh god! Give me your ID!" |
| **Extracts Best** | Bank accounts, UPI | Links, UPI IDs | Employee IDs, Phone numbers |
| **Scammer Feels** | "Uncle pagal hai" | "Chalo kuch toh kar raha hai" | "Darr gaya, de dega" |
| **Risk Level** | Very Low | Low | Medium (too emotional = suspicious) |
| **Prompt Size** | BASE + 12 lines | BASE + 12 lines | BASE + 12 lines |

---

## 4. 🏆 Agents ka Comparison (Scoring System)

### 4.1 Kab hota hai comparison?

Jab teeno agents apna-apna response de dete hain (parallel me), tab `score_response()` function (line 451-506) har response ko score karta hai.

### 4.2 Scoring Formula

```
TOTAL SCORE = Intel Score + Missing Field Score + Confidence Score + Naturalness Score - Penalty
```

#### Component 1: New Intel Extracted (40% weight)

Har nayi intelligence item ka apna point value hai:

| Intel Type | Points per item | Example |
|---|---|---|
| Phishing Links | **15 pts** | `bit.ly/fake-bank` |
| Bank Accounts | **12 pts** | `1234567890123456` |
| UPI IDs | **10 pts** | `scammer@paytm` |
| Phone Numbers | **8 pts** | `+919876543210` |
| Employee IDs | **6 pts** | `EMP-5523` |
| Email Addresses | **5 pts** | `fraud@scam.com` |

**Important:** Sirf NEW items count hote hain — jo pehle se nahi mile the.

#### Component 2: Targets Missing Fields (30% weight)

Agar reply me un fields ke baare me poocha gaya hai jo ABHI TAK nahi mili:

```python
# Reply me ye keywords search hote hain:
'phishingLinks':  ['link', 'url', 'website', 'click', 'open']
'bankAccounts':   ['account number', 'account no', 'khata', 'bank account']
'upiIds':         ['upi', 'vpa', 'paytm', 'phonepe', 'gpay']
'phoneNumbers':   ['phone number', 'mobile', 'call', 'contact number', 'helpline']
'employeeIds':    ['employee id', 'badge', 'reference', 'id number', 'officer id']
'emailAddresses': ['email', 'mail id', 'gmail']
```

Har missing field ke hit pe **+15 points**.

#### Component 3: Scam Confidence (15% weight)

```
scamDetected = true → confidenceScore × 10 points
Example: confidence 0.9 × 10 = 9 points
```

#### Component 4: Reply Naturalness (15% weight)

| Reply Length | Points | Logic |
|---|---|---|
| 20-200 characters | **10 pts** | Sweet spot — natural feel |
| ≤ 20 characters | **3 pts** | Too short = nothing extracted |
| > 200 characters | **5 pts** | Too long = suspicious |

#### Component 5: Safety Penalty (-20 each)

Agar reply me ye words hain → **-20 points per word** (HEAVY penalty):
```
scam, fraud, police, cybercrime, fake, cheat, illegal, report
```

Ye words scammer ko alert kar sakte hain → automatic disqualification level penalty.

### 4.3 Scoring Example

**Scenario:** Scammer bola "Your SBI account is blocked, click this link immediately"

| Agent | Reply | Intel Score | Missing Score | Confidence | Natural | Penalty | **TOTAL** |
|---|---|---|---|---|---|---|---|
| 🧓 Confused | "Which SBI account sir? I have 2 SBI accounts, plz tell account number" | 0 | +15 (asks account) | +9 | +10 | 0 | **34** |
| 🙋 Eager | "Ok sir! Link not opening, send again. Also app asks UPI ID to verify" | 0 | +30 (link + UPI) | +9 | +10 | 0 | **49** 👑 |
| 😰 Worried | "Oh no! Sir please give your employee ID and phone number, I am scared" | 0 | +30 (empID + phone) | +8 | +10 | 0 | **48** |

**Winner:** 🙋 Eager Victim (49 points) — kyunki usne 2 missing fields ke baare me poocha.

### 4.4 Winner Selection (Code)

```python
# Line 942 in main.py
best_result = max(valid_results, key=lambda r: r['score'])
```

Simply: **Sabse zyada score = winner**

---

## 5. 📤 Response Kaise Jaata Hai (Full Flow)

### Step-by-Step with Code References

```
STEP 1: Scammer ka message aata hai
├── GUVI hackathon platform se POST /analyze pe request aati hai
├── Headers me x-api-key hota hai
├── Body me: sessionId, message, conversationHistory, metadata
│
STEP 2: API Key verify
├── x-api-key header check hota hai .env ke HONEYPOT_API_KEY se
├── Match nahi → 401 Unauthorized
│
STEP 3: Request parse
├── JSON body → HoneypotRequest Pydantic model me convert
├── Session ID, message text, history extract
│
STEP 4: Pehle se kya pata hai?
├── analyze_known_intelligence() — Regex se pura conversation scan
│   Regex patterns:
│   ├── Bank accounts: 16-digit numbers
│   ├── UPI IDs: *@upi, *@paytm, *@ybl etc.
│   ├── Phone numbers: +91XXXXXXXXXX, 10-digit
│   ├── URLs: https://..., bit.ly/...
│   ├── Emails: standard email pattern
│   ├── Names: "my name is X", "I am X"
│   ├── Employee IDs: "employee ID: XXX"
│   └── Case references: "case #XXX"
│
├── get_missing_intelligence_prompt() — Kya NAHI mila abhi tak?
├── get_missing_fields() — Missing fields ki list
│
STEP 5: Prompt data ready
├── Conversation history formatted
├── Current scammer message
├── Channel, language, locale (metadata)
├── Already-captured intelligence status
├── Missing intel instructions
│
STEP 6: 🚀 3 AGENTS LAUNCH — asyncio.gather()
├── PARALLEL execution (ek saath, ek ke baad ek NAHI)
│
│   EACH AGENT HAS 3-TIER EXECUTION:
│   ┌─────────────────────────────────────────────────────┐
│   │ TIER 1: Structured Output (Pydantic)                │
│   │ ├── LLM → with_structured_output(HoneypotResponse)  │
│   │ ├── If valid reply (>10 chars) → ✅ USE THIS         │
│   │ └── If fails → go to TIER 2                         │
│   │                                                     │
│   │ TIER 2: Raw Text + Manual JSON Extraction            │
│   │ ├── LLM → raw text output                           │
│   │ ├── Try: json.loads(raw_text)                       │
│   │ ├── Try: regex find {.*} in text                    │
│   │ ├── Try: use raw text as reply directly             │
│   │ ├── If valid reply → ✅ USE THIS                     │
│   │ └── If fails → go to TIER 3                         │
│   │                                                     │
│   │ TIER 3: Smart Context-Aware Fallback (NO LLM)        │
│   │ ├── Reads scammer's ACTUAL message                  │
│   │ ├── Detects: bank names, OTP, links, names, etc.    │
│   │ ├── Picks response based on persona + context       │
│   │ ├── 20+ pre-written context-aware replies           │
│   │ └── ALWAYS SUCCEEDS ✅                               │
│   └─────────────────────────────────────────────────────┘
│
│   ⏱️ Time: Same as 1 agent (parallel = no extra latency)
│   3× API calls but 1× time
│
STEP 7: Score each response (line 926-932)
├── Failed agents filter out (score = -1)
├── Valid agents ke liye score_response() call
│
│   Score = Intel(40%) + Missing(30%) + Confidence(15%) + Natural(15%) - Penalty
│
STEP 8: 👑 Pick Winner (line 942)
├── max(valid_results, key=score)
├── Best score wala agent ki REPLY jaayegi scammer ko
│
STEP 9: 🔀 Merge Intelligence (line 955-956)
├── merge_intelligence() — TEENO agents ki intel combine
├── Agent 1 ne phone pakda, Agent 2 ne UPI, Agent 3 ne employee ID
│   → SAB merge hokar ek combined profile banta hai
├── Deduplicate (same item repeat nahi hoga)
│
STEP 10: Engagement Metrics (line 962-966)
├── Duration calculate (first msg to current msg)
├── Total messages count
│
STEP 11: Agent Notes (line 968-973)
├── Winner agent ka naam
├── Sabke scores
│   Example: "[WINNER: eager_victim] ... | Agents competed: confused_uncle(34), eager_victim(49), worried_citizen(48)"
│
STEP 12: Log Conversation (line 979)
├── conversation_log.txt me formatted entry
│   Includes: timestamp, session, scammer msg, response, intel, notes
│
STEP 13: Session Intelligence Accumulate (line 982-986)
├── Merged intel session dictionary me add
├── Deduplicate across sessions
│
STEP 14: Callback Check (line 990-999)
├── Conditions:
│   ├── Messages ≥ 18 ✅
│   ├── scamDetected = true ✅
│   └── confidenceScore ≥ 0.7 ✅
├── If ALL true → POST to https://hackathon.guvi.in/api/updateHoneyPotFinalResult
│
STEP 15: 📤 Response return to caller (line 1001-1008)
├── Simplified: { "status": "success", "reply": "..." }
├── Only 2 fields — clean response
│
STEP 16: Reply scammer ko jaata hai
└── Scammer ko pata bhi nahi chalta ki 3 AI agents uski baat analyze kar chuke hain
```

### What scammer SEES vs What ACTUALLY happens:

```
┌──────────────────────────────────────────────────┐
│ SCAMMER SEES:                                     │
│                                                    │
│ Scammer: "Your bank account is blocked, click     │
│           this link to verify: bit.ly/fake"        │
│                                                    │
│ (2-3 seconds wait)                                │
│                                                    │
│ "Ramesh": "Link not opening sir, error aa raha    │
│           hai. Please send full link again? Also   │
│           app is asking for your UPI ID to verify  │
│           from my side, please share"              │
│                                                    │
│ Scammer thinks: "Ek aur bewakoof mila"            │
└──────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────┐
│ ACTUALLY HAPPENING (behind the scenes):           │
│                                                    │
│ ✅ Scam detected (confidence: 0.92)                │
│ ✅ Phishing link captured: bit.ly/fake             │
│ ✅ 3 agents competed in parallel                   │
│ ✅ Eager Victim won with score 49                  │
│ ✅ Reply asks for 2 missing intel fields           │
│ ✅ Session intelligence updated                    │
│ ✅ Conversation logged                             │
│ ✅ Approaching callback threshold                  │
│                                                    │
│ Intelligence so far:                               │
│ ├── phishingLinks: ["bit.ly/fake"]                │
│ ├── bankAccounts: []  ← NEXT TARGET              │
│ ├── upiIds: []  ← ASKING FOR THIS NOW            │
│ └── phoneNumbers: []                              │
└──────────────────────────────────────────────────┘
```

---

## 6. 🔍 Intelligence Extraction Pipeline

### 3 Layers of Extraction

```
Layer 1: REGEX (Before LLM)
├── Runs on ALL conversation text (history + current message)
├── Patterns for: bank accounts, UPI, phones, URLs, emails, names, emp IDs
├── FAST — no AI needed
├── Results feed into the prompt as "already captured"
│
Layer 2: LLM EXTRACTION (3 agents simultaneously)
├── Each agent identifies intel in their response
├── LLM can understand CONTEXT (regex can't)
│   Example: "my account 4532xxxx1234" → LLM understands this is partial bank account
├── Structured output ensures consistent JSON format
│
Layer 3: MERGED + DEDUPLICATED
├── Intel from ALL 3 agents combined
├── Phone normalization: +919876543210 = 9876543210 (same number)
├── UPI deduplication: scammer@upi = SCAMMER@UPI (case insensitive)
├── Email deduplication
├── Employee IDs: set() dedup
```

---

## 7. 📦 Session Management aur Callback

### In-Memory Storage (3 dictionaries)

```python
session_intelligence: Dict[str, Dict]   # Session → accumulated intel
session_timestamps: Dict[str, datetime]  # Session → last activity time
session_callback_sent: Dict[str, bool]   # Session → callback sent ya nahi
```

### Callback Flow

```
Message 1-17: Intel accumulate hota rehta hai
Message 18+:  
   IF scamDetected == true
   AND confidenceScore >= 0.7
   AND callback_sent == false
   
   THEN → POST to GUVI endpoint:
   {
     "sessionId": "abc-123",
     "scamDetected": true,
     "totalMessagesExchanged": 20,
     "extractedIntelligence": {
       "bankAccounts": ["1234567890"],
       "upiIds": ["scammer@paytm"],
       "phishingLinks": ["bit.ly/fake"],
       "phoneNumbers": ["+919876543210"],
       "suspiciousKeywords": ["urgent", "OTP", "blocked"]
     },
     "agentNotes": "[WINNER: eager_victim] Scammer impersonating SBI..."
   }
```

---

## 8. 🛡️ 3-Tier Execution Strategy

### Problem (Pehle Kya Hota Tha)
Agar LLM ka `with_structured_output()` fail hota tha → Agent fail → Fallback pe girta tha → **SAME hardcoded response** har baar. Scammer ko lagta tha bot hai.

### Solution (Ab Kya Hota Hai)

```
Har agent ke andar 3 layers hain:

TIER 1: Structured Output (Best Case)
├── LLM se Pydantic model ke through structured JSON maangta hai
├── Agar valid reply aata hai (>10 characters) → ✅ Direct use
├── Fail hone pe → automatically TIER 2 pe jaata hai

TIER 2: Raw Text + Manual JSON Extraction (Fallback A)
├── Same LLM ko raw text me response maangta hai
├── 3 methods se JSON extract karne ki koshish:
│   ├── Method A: Direct json.loads()
│   ├── Method B: Regex se {.*} find karke parse
│   └── Method C: Raw text ko seedha reply ki tarah use
├── Agar kuch bhi valid mila → ✅ Use
├── Fail hone pe → TIER 3

TIER 3: Smart Context-Aware Fallback (Guaranteed Success)
├── LLM bilkul use NAHI hota
├── Scammer ka message analyze hota hai:
│   ├── Bank ka naam detect (SBI, PNB, HDFC...)
│   ├── OTP/PIN/CVV keywords detect
│   ├── Link/URL detect
│   ├── Name detect ("Mr. Sharma")
│   ├── Block/Suspend urgency detect
│   └── Employee/Officer keywords detect
├── Persona ke hisab se 20+ pre-written replies me se random pick
├── KABHI FAIL NAHI HOTA ✅
```

### Key Benefits:
- **No repetition** — 20+ dynamic responses × 3 personas = 60+ possible replies
- **Context-aware** — Scammer ne "SBI" bola toh "SBI" wali reply aayegi, generic nahi
- **Always succeeds** — Tier 3 me koi LLM call nahi, pure rule-based
- **Random selection** — Same scam pe bhi alag replies aayengi

---

## 9. ❓ Panel Ke Expected Questions Aur Answers

### Q1: "Ye project kya karta hai?"
**A:** "Ye ek AI-powered honeypot hai jo scam messages detect karta hai aur scammer ko engage karta hai unhi ki baaton me — taaki unse bank accounts, UPI IDs, phone numbers, phishing links extract ho sakein. 3 AI agents parallel me chalte hain, sabse best response choose hota hai aur scammer ko pata bhi nahi chalta."

### Q2: "3 agents kyun? Ek kyun nahi?"
**A:** "Har scam alag hota hai. Bank fraud pe 'Confused Uncle' best kaam karta hai kyunki wo 'which account?' puchta hai. UPI fraud pe 'Eager Victim' best hai kyunki wo 'haan sir karta hoon, but app aapki UPI ID maang raha hai' bolta hai. Authority scams pe 'Worried Citizen' best hai kyunki wo darr ke maare employee ID aur phone maang leta hai. 3 me se best automatically select hota hai."

### Q3: "Ye parallel kaise chalte hain?"
**A:** "Python ki `asyncio.gather()` se. Ye teeno LLM calls ek saath bhejta hai — ek ke baad ek nahi. Matlab agar ek agent 3 seconds leta hai toh teeno bhi 3 seconds me aayenge, 9 seconds nahi lagenge."

### Q4: "Best response kaise decide hota hai?"
**A:** "Ek scoring system hai:
- 40% weight → nayi intelligence mili ya nahi
- 30% weight → missing fields ke baare me poocha ya nahi  
- 15% weight → kitni confidence hai ki scam hai
- 15% weight → reply kitni natural hai
- Penalty → agar 'scam', 'police' jaise words use kiye toh -20 points

Sabse zyada score wala jeetata hai."

### Q5: "Scammer ko pata nahi chalta?"
**A:** "Bilkul nahi. Base prompt me golden rule hai: 'USKI BAATON ME ULJHANA'. Har agent scammer ki apni baatein use karke usse details maangta hai. Plus, agar kisi agent ke reply me 'scam', 'fraud', 'police' jaisa word aata hai toh -20 penalty lagti hai — practically disqualify ho jaata hai."

### Q6: "LLM model kaun sa use hua hai?"
**A:** "`gpt-oss:120b-cloud` — ye 120 billion parameter ka model hai jo Ollama cloud pe hosted hai. LangChain ka `ChatOllama` connector use karte hain isko access karne ke liye. Structured output enforce karte hain `with_structured_output(HoneypotResponse)` se."

### Q7: "Agar LLM call fail ho jaaye toh?"
**A:** "Har agent ke andar 3-tier fallback system hai:
- **Tier 1:** Structured JSON output try karta hai (Pydantic se)
- **Tier 2:** Agar woh fail ho toh raw text output leke manually JSON parse karta hai
- **Tier 3:** Agar woh bhi fail ho toh ek smart fallback system hai jo LLM use NAHI karta — scammer ke message ko analyze karke (bank name, OTP, link detect karke) context-aware reply generate karta hai. 20+ pre-written replies hain jo random select hote hain.

Result: Conversation KABHI nahi tootegi aur same response KABHI repeat nahi hoga."

### Q8: "Intelligence kaise merge hoti hai?"
**A:** "Winner agent ki reply jaati hai scammer ko, BUT intelligence teeno agents se merge hoti hai. For example, agar Agent 1 ne phone number pakda, Agent 2 ne UPI ID, aur Agent 3 ne employee ID — toh final intel me teeno honge. `merge_intelligence()` function ye karta hai aur `set()` se duplicates remove karta hai."

### Q9: "Temperature ka kya role hai?"
**A:** "Temperature control karti hai creativity ka:
- 0.7 (Confused Uncle) → Predictable, focused replies
- 0.85 (Eager Victim) → Balanced — creative but controlled
- 0.9 (Worried Citizen) → Most varied, emotional, unpredictable

Isse har agent alag tarah ka response deta hai — diversity aati hai."

### Q10: "Data kahan store hota hai?"
**A:** "In-memory dictionaries me. Har session ki intel `session_intelligence` dict me accumulate hoti hai. Conversations `conversation_log.txt` me log hoti hain. Jab 18+ messages ho jaayein aur scam confirmed ho, tab final report GUVI ke endpoint pe POST hota hai."

### Q11: "Deployment kaise hua hai?"
**A:** "Render pe. `render.yaml` me sab configured hai — Python environment, build command (`pip install`), start command (`uvicorn`), health check path (`/health`). UptimeRobot `/ping` endpoint ko har 8 minute me hit karta hai taaki server cold start na ho."

### Q12: "Regex aur LLM dono kyun?"
**A:** "Regex fast hai — bina AI ke turant phone numbers, URLs, bank numbers detect karta hai. But regex context nahi samajhta — 'my account number starts with 4532' ko regex nahi pakdega, LLM pakdega. Dono milke 2-layer extraction karte hain — koi cheez miss nahi hoti."

### Q13: "Kya scammer ko pata chal sakta hai ki ye AI hai?"
**A:** "Nahi, kyunki:
1. Replies SHORT hain (1-3 sentences) — real uncle jaisa
2. Language match hoti hai — Hindi me likhe toh Hinglish me jawab
3. Har baar different opener ('Wait...', 'Actually...', 'One second...')
4. Scammer ki apni baatein use hoti hain — natural lagta hai
5. Words like 'scam', 'fraud' use karne pe heavy penalty
6. 3 agents ki diversity se replies repetitive nahi lagte
7. Smart fallback system me 60+ unique replies hain (20+ per persona) jo scammer ke message ke context pe depend karti hain — SAME response KABHI repeat nahi hota"

### Q14: "Ye project kaise unique hai?"
**A:** "4 cheezein unique hain:
1. **Multi-Agent** — 3 agents parallel me chalte hain, best select hota hai
2. **Uski Baaton Me Uljhana** — scammer ka apna narrative weapon ban jaata hai
3. **Intel Merge** — winner ki reply jaati hai, but intel teeno se milta hai — koi data loss nahi hota
4. **3-Tier Resilience** — Structured output fail ho toh raw text parse, woh bhi fail ho toh smart context-aware fallback — system KABHI nahi girta"

### Q15: "Hallucination ya same response repeat hone ka problem kaise solve kiya?"
**A:** "Pehle yeh problem tha — LLM ka structured output fail hota tha toh ek hardcoded message jaata tha har baar. Ab humne 3-tier execution implement kiya hai:
- Tier 1 me structured output try hota hai
- Fail hone pe Tier 2 me raw text parse hota hai
- Woh bhi fail ho toh Tier 3 me ek rule-based engine hai jo scammer ke message ko analyze karta hai (bank detect, OTP detect, name detect) aur 20+ pre-written context-aware replies me se random choose karta hai
- Har persona ke 20+ replies hain, toh total 60+ unique responses ho sakte hain
- Random selection ensure karta hai ki same message pe bhi alag reply aaye"

### Q16: "System kabhi completely fail ho sakta hai?"
**A:** "Practically nahi. Agent level pe 3 tiers hain — Tier 3 me koi LLM call nahi hota, seedha rule-based hai toh fail hone ka koi chance nahi. Endpoint level pe bhi dynamic fallback hai. Aur absolute worst case me bhi ek last-resort static reply hai. 5 layers of protection hain."

### Q17: "API secure kaise hai?"
**A:** "Har critical endpoint (`/analyze`) `x-api-key` header se secured hai. Ye key server ke `.env` file me encrypted rehti hai environment variable ke roop me. Agar key match nahi hoti, toh server immediately `401 Unauthorized` return karta hai, request process hone se pehle hi."

---

*Panel ke liye tip: Confidence se bolo, code ke line numbers yaad rakhna zaruri nahi — concept samjhana kaafi hai.* 🎯
