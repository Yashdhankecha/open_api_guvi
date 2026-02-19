# Honeypot API

## Description

An AI-powered honeypot system that engages scammers in realistic conversations while silently extracting intelligence. The system uses a **dual-agent parallel architecture** — a Reply Agent generates convincing victim responses while an Intel Agent simultaneously extracts structured data (phone numbers, bank accounts, UPI IDs, phishing links, emails). Regex-based extraction runs alongside for maximum coverage.

### Architecture

```
Scammer Message ──► /analyze endpoint
                        │
                   ┌────┴────┐
                   │  Regex  │  (fast keyword/pattern extraction)
                   └────┬────┘
                        │
              ┌─────────┼─────────┐
              ▼                   ▼
        Reply Agent         Intel Agent
      (conversational)    (structured extraction)
        (plain LLM)       (structured output)
              │                   │
              └─────────┬─────────┘
                        │
                  Union & Merge
                  (deduplicate)
                        │
              ┌─────────┼─────────┐
              ▼                   ▼
         Reply to             Callback
         Scammer           (to evaluator)
```

**Strategy:**
- **Scam Detection** — Keyword-based + LLM classification across 13 scam types (bank_fraud, upi_fraud, phishing, kyc_fraud, job_scam, lottery_scam, etc.)
- **Intelligence Extraction** — Dual-layer: regex patterns + LLM structured output, merged and deduplicated. Distinguishes UPI IDs from emails by TLD presence.
- **Engagement** — Dynamic persona (Ramesh Kumar, 58yo retired govt employee) with turn-phase strategy: Initial Engagement → Intelligence Gathering → Deep Extraction → Final Extraction. Smart pacing ensures >60s session duration.

## Tech Stack

- **Language/Framework:** Python 3.10+ / FastAPI + Uvicorn
- **Key Libraries:** LangChain, Pydantic v2, httpx (async), pydantic-settings
- **LLM/AI Models:** Groq (`openai/gpt-oss-120b`) — swappable to OpenAI, Anthropic, or Ollama via `llm_client.py`

## Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/Yashdhankecha/open_api_guvi.git
   cd open_api_guvi
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys:
   # GROQ_API_KEY=gsk_...
   # API_KEY=your-secret-key
   ```

4. **Run the application**
   ```bash
   cd src
   python main.py
   ```
   Server starts at `http://localhost:8000`

## API Endpoint

- **URL:** `https://your-deployed-url.com/analyze`
- **Method:** POST
- **Authentication:** `x-api-key` header

**Request:**
```json
{
  "sessionId": "abc-123",
  "message": {
    "sender": "scammer",
    "text": "Your bank account is blocked! Send OTP immediately."
  },
  "conversationHistory": [],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "Sir, I am very worried! Which OTP are you talking about? Can you please tell me your direct number so I can call you back?"
}
```
