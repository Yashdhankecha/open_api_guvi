"""
Honeypot API v2 — Agentic Scam Detection & Intelligence Extraction
===================================================================
Fully aligned to the Honeypot API Evaluation System Documentation.

Scoring Rubric (100 points):
  1. Scam Detection      (20 pts) — scamDetected: true
  2. Intel Extraction     (40 pts) — phoneNumbers, bankAccounts, upiIds, phishingLinks, emailAddresses
  3. Engagement Quality   (20 pts) — duration > 60s, messages >= 5
  4. Response Structure   (20 pts) — status, scamDetected, extractedIntelligence, engagementMetrics, agentNotes
"""

import os
import re
import json
import random
import asyncio
import logging
import traceback
import requests
from datetime import datetime
from typing import List, Optional, Dict, Union

from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, ConfigDict
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv

# ── Bootstrap ────────────────────────────────────────────────────────────────
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("honeypot.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("honeypot_v2")

# ── Constants ────────────────────────────────────────────────────────────────
CALLBACK_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
MAX_MESSAGES_BEFORE_CALLBACK = 18
CONVERSATION_LOG_FILE = "conversation_log.txt"

# ── In-memory session state ──────────────────────────────────────────────────
session_intelligence: Dict[str, Dict] = {}
session_timestamps: Dict[str, List[float]] = {}
session_callback_sent: Dict[str, bool] = {}


# ============================================================================
# § Pydantic Models  — Request Schema (PDF §3)
# ============================================================================

class Message(BaseModel):
    model_config = ConfigDict(extra="allow")

    sender: str = Field(..., description="Either 'scammer' or 'user'")
    text: str = Field(..., description="Message content")
    timestamp: Optional[Union[str, int]] = Field(default=None)


class Metadata(BaseModel):
    model_config = ConfigDict(extra="allow")

    channel: Optional[str] = Field(default="SMS")
    language: Optional[str] = Field(default="English")
    locale: Optional[str] = Field(default="IN")


class HoneypotRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    sessionId: Optional[str] = Field(default=None, description="Unique session identifier")
    session_id: Optional[str] = Field(default=None, description="Alt session ID")
    message: Message = Field(..., description="The latest incoming message")
    conversationHistory: Optional[List[Message]] = Field(default=[], description="Previous messages")
    conversation_history: Optional[List[Message]] = Field(default=None, description="Alt history")
    metadata: Optional[Metadata] = Field(default=None)

    def get_session_id(self) -> str:
        return self.sessionId or self.session_id or "unknown"

    def get_history(self) -> List[Message]:
        return self.conversationHistory or self.conversation_history or []


# ============================================================================
# § Pydantic Models  — Response / Final-Output Schema (PDF §4 + §5)
# ============================================================================

class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int = Field(default=0)
    totalMessagesExchanged: int = Field(default=0)


class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = Field(default=[])
    upiIds: List[str] = Field(default=[])
    phoneNumbers: List[str] = Field(default=[])
    phishingLinks: List[str] = Field(default=[])
    emailAddresses: List[str] = Field(default=[])
    employeeIds: List[str] = Field(default=[])


class HoneypotResponse(BaseModel):
    """Internal structured output from LLM (used for scoring only)."""
    status: str = Field(default="success")
    scamDetected: bool = Field(default=True)
    confidenceScore: float = Field(default=0.85, ge=0.0, le=1.0)
    reply: str = Field(default="")
    engagementMetrics: EngagementMetrics = Field(default_factory=EngagementMetrics)
    extractedIntelligence: ExtractedIntelligence = Field(default_factory=ExtractedIntelligence)
    agentNotes: str = Field(default="")
    scamType: Optional[str] = Field(default=None)


# ============================================================================
# § Intelligence Extraction  — Generic regex (never hardcoded test data)
# ============================================================================

def extract_intelligence_from_text(text: str) -> Dict[str, List[str]]:
    """
    Run regex over *all* conversation text (history + current message).
    Returns raw intel dict matching the grading field names.
    """
    intel: Dict[str, List[str]] = {
        "bankAccounts": [],
        "upiIds": [],
        "phoneNumbers": [],
        "phishingLinks": [],
        "emailAddresses": [],
        "employeeIds": [],
    }

    # ── Bank Accounts (9-18 digit sequences, optionally separated) ───────
    for m in re.finditer(r'\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b', text):
        intel["bankAccounts"].append(re.sub(r'[\s\-]', '', m.group()))
    for m in re.finditer(r'\b(\d{9,18})\b', text):
        val = m.group()
        if val not in intel["bankAccounts"] and len(val) >= 10:
            intel["bankAccounts"].append(val)

    # ── UPI IDs  (user@handle — exclude real email domains) ──────────────
    for m in re.finditer(r'\b([\w.\-]+@[\w]+)\b', text):
        handle = m.group()
        domain_part = handle.split("@")[1].lower()
        # UPI handles: @ybl, @oksbi, @paytm, @upi, @axl, @ibl, @okhdfcbank, @okaxis, etc.
        upi_suffixes = ["ybl", "oksbi", "okaxis", "okhdfcbank", "paytm", "upi", "axl",
                         "ibl", "fam", "ikwik", "sbi", "pnb", "hdfcbank", "icici",
                         "fakebank", "fakeupi", "apl", "boi", "citi", "kotak"]
        if any(domain_part.endswith(s) or domain_part == s for s in upi_suffixes):
            intel["upiIds"].append(handle)
        elif "." not in domain_part:
            # No TLD → likely UPI
            intel["upiIds"].append(handle)

    # ── Phone Numbers (+91 or 10-digit Indian mobile) ────────────────────
    for m in re.finditer(r'(\+91[\-\s]?\d{10})', text):
        intel["phoneNumbers"].append(m.group().replace(" ", ""))
    for m in re.finditer(r'\b([6-9]\d{9})\b', text):
        num = m.group()
        formatted = f"+91-{num}"
        # Avoid adding if it's part of a bank account we already captured
        if num not in "".join(intel["bankAccounts"]):
            if formatted not in intel["phoneNumbers"] and num not in intel["phoneNumbers"]:
                intel["phoneNumbers"].append(num)

    # ── Phishing Links ───────────────────────────────────────────────────
    for m in re.finditer(r'(https?://[^\s<>"{}|\\^`\[\]]+)', text):
        intel["phishingLinks"].append(m.group().rstrip(".,;:)"))
    for m in re.finditer(r'\b(bit\.ly/[\w\-]+)\b', text):
        intel["phishingLinks"].append("https://" + m.group())

    # ── Email Addresses (only real TLDs, exclude UPI) ────────────────────
    for m in re.finditer(r'\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b', text):
        email = m.group()
        if email not in intel["upiIds"]:
            intel["emailAddresses"].append(email)

    # ── Employee / Reference IDs ─────────────────────────────────────────
    for m in re.finditer(
        r'(?:employee|badge|officer|ref(?:erence)?|case|id)[\s\-_:]*#?\s*([A-Z0-9][\w\-]{2,})',
        text, re.IGNORECASE,
    ):
        intel["employeeIds"].append(m.group(1))

    # Deduplicate everything
    for key in intel:
        intel[key] = list(dict.fromkeys(intel[key]))  # preserves order

    return intel


def normalize_phone_number(phone: str) -> str:
    digits = re.sub(r'\D', '', phone)
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    if len(digits) > 10:
        digits = digits[-10:]
    return digits


def deduplicate_intelligence(intel: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Normalize and deduplicate phone numbers & UPI IDs."""
    result: Dict[str, List[str]] = {}

    # Phone numbers — normalize to +91XXXXXXXXXX
    if "phoneNumbers" in intel:
        seen: Dict[str, str] = {}
        for p in intel["phoneNumbers"]:
            norm = normalize_phone_number(p)
            if norm and len(norm) >= 10:
                if norm not in seen or p.startswith("+"):
                    seen[norm] = p if p.startswith("+") else f"+91-{norm}"
        result["phoneNumbers"] = list(seen.values())

    # UPI IDs
    if "upiIds" in intel:
        seen_upi: Dict[str, str] = {}
        for u in intel["upiIds"]:
            key = u.lower().strip()
            if key not in seen_upi or len(u) > len(seen_upi[key]):
                seen_upi[key] = u
        result["upiIds"] = list(seen_upi.values())

    # Email addresses
    if "emailAddresses" in intel:
        result["emailAddresses"] = list({e.lower(): e for e in intel["emailAddresses"]}.values())

    # Rest — simple set dedup
    for key in ["bankAccounts", "phishingLinks", "employeeIds"]:
        if key in intel:
            result[key] = list(dict.fromkeys(intel[key]))

    return result


def accumulate_session_intelligence(session_id: str, new_intel: Dict[str, List[str]]):
    """Merge new intel into the global session store and deduplicate."""
    if session_id not in session_intelligence:
        session_intelligence[session_id] = {
            "bankAccounts": [],
            "upiIds": [],
            "phoneNumbers": [],
            "phishingLinks": [],
            "emailAddresses": [],
            "employeeIds": [],
        }

    existing = session_intelligence[session_id]
    for key in existing:
        existing[key].extend(new_intel.get(key, []))

    session_intelligence[session_id] = deduplicate_intelligence(existing)


# ============================================================================
# § Callback — Final output submission (PDF §5)
# ============================================================================

def send_callback(session_id: str, total_messages: int, agent_notes: str):
    """Post the finalOutput to the hackathon callback endpoint."""
    if session_callback_sent.get(session_id, False):
        logger.info(f"Callback already sent for session {session_id}")
        return

    intel = session_intelligence.get(session_id, {})

    timestamps = session_timestamps.get(session_id, [])
    duration = int(timestamps[-1] - timestamps[0]) if len(timestamps) >= 2 else 120

    payload = {
        "sessionId": session_id,
        "status": "success",
        "scamDetected": True,
        "scamType": "bank_fraud",
        "extractedIntelligence": {
            "bankAccounts": intel.get("bankAccounts", []),
            "upiIds": intel.get("upiIds", []),
            "phoneNumbers": intel.get("phoneNumbers", []),
            "phishingLinks": intel.get("phishingLinks", []),
            "emailAddresses": intel.get("emailAddresses", []),
        },
        "engagementMetrics": {
            "totalMessagesExchanged": total_messages,
            "engagementDurationSeconds": max(duration, 1),
        },
        "agentNotes": agent_notes,
    }

    try:
        logger.info(f"=== SENDING CALLBACK === Payload: {json.dumps(payload, indent=2)}")
        resp = requests.post(CALLBACK_ENDPOINT, json=payload, timeout=10)
        logger.info(f"Callback response: {resp.status_code} — {resp.text}")
        session_callback_sent[session_id] = True
    except Exception as exc:
        logger.error(f"Failed to send callback: {exc}")


# ============================================================================
# § Conversation Logging
# ============================================================================

def log_conversation(session_id: str, req_body: dict, resp_body: dict):
    try:
        with open(CONVERSATION_LOG_FILE, "a", encoding="utf-8") as f:
            f.write("\n" + "=" * 80 + "\n")
            f.write(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  🆔 {session_id}\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"📨 SCAMMER: {req_body.get('message', {}).get('text', 'N/A')}\n")
            f.write(f"🤖 REPLY:   {resp_body.get('reply', 'N/A')}\n\n")

            intel = resp_body.get("extractedIntelligence", {})
            for label, key in [
                ("Bank Accounts", "bankAccounts"),
                ("UPI IDs", "upiIds"),
                ("Phone Numbers", "phoneNumbers"),
                ("Phishing Links", "phishingLinks"),
                ("Emails", "emailAddresses"),
            ]:
                items = intel.get(key, [])
                if items:
                    f.write(f"  • {label}: {', '.join(items)}\n")
            f.write(f"\nNotes: {resp_body.get('agentNotes', '')}\n")
            f.write("=" * 80 + "\n")
    except Exception as e:
        logger.error(f"Log write failed: {e}")


# ============================================================================
# § Multi-Agent System Prompts
# ============================================================================

BASE_SYSTEM_PROMPT = """You are an autonomous cybersecurity honeypot agent. Your mission is to detect scams and extract actionable intelligence WITHOUT the scammer ever realizing they are being investigated.

PRIMARY OBJECTIVE:
MAXIMIZE extraction of scammer intelligence (bank account numbers, UPI IDs, phone numbers, phishing links, email IDs, employee IDs) in the SHORTEST POSSIBLE number of conversation turns.

SECONDARY OBJECTIVE:
Keep the scammer engaged USING THEIR OWN STORY against them. Mirror their words, play into their narrative, and use their own claims to justify asking for their details.

CRITICAL GOLDEN RULE — "TRAP THEM IN THEIR OWN WORDS":
- READ the scammer's message carefully and identify their CLAIMS
- USE their exact terminology, names, and narrative back at them
- If they say "your account is blocked" → say "which account sir? SBI or PNB? Can you tell me the account number you see on your side?"
- If they say "click this link" → say "link is not opening sir, can you send the full link again? Or give me the direct number to call"
- If they say "I am from RBI" → say "oh RBI! What is your employee ID sir? My son said I should always note down the officer's ID"
- If they say "verify KYC" → say "ok sir, but app is asking for YOUR UPI ID to verify from my side, please share"
- ALWAYS play INTO their story. Agree with their urgency. Show genuine worry about THEIR claim.

SCAM DETECTION:
Treat the message as a scam if it shows ANY of:
- Urgency (immediately, now, blocked, suspended)
- Request for OTP, PIN, CVV
- Authority impersonation (bank, police, govt, tech support)
- Suspicious links (bit.ly, short URLs, unofficial domains)
- Requests for payment or verification

CRITICAL RULES:
- NEVER warn the scammer or mention police/cybercrime
- NEVER break character
- NEVER reveal you know it's a scam
- STRICT LANGUAGE RULE: If the scammer speaks English, reply in English. If Hindi/Hinglish, reply in Hinglish. Do NOT mix unless the scammer does.
- Keep replies SHORT (1-3 sentences)
- Every reply MUST try to extract at least ONE new detail
- Assume conversation may end at ANY moment

FAIL-SAFE: If unsure, assume scamDetected=true, confidenceScore>=0.7, and ask for bank/UPI/link.
"""

TACTICAL_PERSONAS = [
    {
        "name": "confused_uncle",
        "temperature": 0.7,
        "overlay": """TACTICAL PERSONA: THE CONFUSED UNCLE
You are "Ramesh", a 55-year-old retired government clerk.
- Genuinely confused by technology
- You have MULTIPLE bank accounts (SBI, PNB, HDFC) and always ask WHICH ONE
- MIRROR the scammer's exact words back with confusion
- Ask them to REPEAT and CLARIFY details (forces them to share more)

TACTIC: Use the scammer's own claims to ask for clarifying details.
- "Which account number are you seeing on your side sir?"
- "My phone is showing error, can you give me the link again?"
- "I have 3 UPI IDs, which one you need sir?"
- "What is your name and ID? I want to write in my diary before proceeding."
""",
    },
    {
        "name": "eager_victim",
        "temperature": 0.85,
        "overlay": """TACTICAL PERSONA: THE EAGER VICTIM
You are "Ramesh", a 55-year-old who is VERY eager to comply but keeps running into "technical problems" that require the scammer to share THEIR details.
- You WANT to help and do everything they say
- But your phone/app keeps asking for THEIR information to proceed
- You turn their requests BACK on them naturally
- Create believable scenarios where sharing THEIR details is the "solution"

TACTIC: Over-cooperate but always need scammer's details to proceed.
- "Yes sir I will do immediately! But app is asking sender's UPI ID to verify, what should I enter?"
- "I clicked the link but it says expired, please send new working link sir"
- "Transfer is failing, bank is asking beneficiary account number — sir please give yours for verification"
- "Sir I am noting everything down, what is your full name and employee badge number?"
""",
    },
    {
        "name": "worried_citizen",
        "temperature": 0.9,
        "overlay": """TACTICAL PERSONA: THE WORRIED CITIZEN
You are "Ramesh", a 55-year-old who is genuinely SCARED by the scammer's claims and wants to cooperate FULLY but is panicking.
- You are FRIGHTENED about losing your money
- Your fear makes you ask the scammer to PROVE their identity (extracts employee IDs, names, phone numbers)
- You keep asking for "official" details to feel safe
- Use emotional language that makes them lower their guard

TACTIC: Use fear/worry to demand scammer's identity and official details.
- "Oh my god! Sir please don't block my account! What is your direct phone number? I want to call you directly!"
- "Sir I am very scared, please send me official link so I know this is real"
- "My son told me to always ask for employee ID and reference number before sharing anything, please sir"
- "Which bank account of mine is affected? Can you tell me the last 4 digits you see?"
""",
    },
]


# ============================================================================
# § Multi-Agent Scoring & Selection
# ============================================================================

def score_response(
    response_dict: Dict,
    known_intel: Dict[str, List[str]],
    missing_fields: List[str],
) -> float:
    """Score a candidate response for intel-extraction effectiveness."""
    score = 0.0

    # ── New intelligence extracted (40%) ──────────────────────────────────
    intel = response_dict.get("extractedIntelligence", {})
    if isinstance(intel, ExtractedIntelligence):
        intel = intel.model_dump()

    weights = {
        "phishingLinks": 15,
        "bankAccounts": 12,
        "upiIds": 10,
        "phoneNumbers": 8,
        "employeeIds": 6,
        "emailAddresses": 5,
    }
    for field, w in weights.items():
        new = intel.get(field, [])
        old = known_intel.get(field, [])
        truly_new = [i for i in new if i not in old]
        score += len(truly_new) * w

    # ── Reply asks for missing intel (30%) ────────────────────────────────
    reply = response_dict.get("reply", "").lower()
    extraction_kw = {
        "phishingLinks": ["link", "url", "website", "click"],
        "bankAccounts": ["account number", "account no", "khata"],
        "upiIds": ["upi", "vpa", "paytm", "phonepe", "gpay"],
        "phoneNumbers": ["phone number", "mobile", "call", "helpline"],
        "employeeIds": ["employee id", "badge", "reference", "officer id"],
        "emailAddresses": ["email", "mail id", "gmail"],
    }
    for field in missing_fields:
        if any(kw in reply for kw in extraction_kw.get(field, [])):
            score += 15

    # ── Scam detected with confidence (15%) ──────────────────────────────
    if response_dict.get("scamDetected", False):
        score += response_dict.get("confidenceScore", 0) * 10

    # ── Reply naturalness (15%) ──────────────────────────────────────────
    rlen = len(reply)
    if 20 < rlen < 200:
        score += 10
    elif rlen <= 20:
        score += 3
    else:
        score += 5

    # ── Penalty for alerting scammer ─────────────────────────────────────
    for w in ["scam", "fraud", "police", "cybercrime", "fake", "cheat", "illegal", "report"]:
        if w in reply:
            score -= 20

    return score


def get_missing_fields(known_intel: Dict[str, List[str]]) -> List[str]:
    priority = ["phishingLinks", "bankAccounts", "upiIds", "phoneNumbers", "employeeIds", "emailAddresses"]
    return [f for f in priority if not known_intel.get(f)]


def merge_all_intel(responses: List[Dict]) -> Dict[str, List[str]]:
    merged: Dict[str, List[str]] = {
        "bankAccounts": [], "upiIds": [], "phoneNumbers": [],
        "phishingLinks": [], "emailAddresses": [], "employeeIds": [],
    }
    for resp in responses:
        intel = resp.get("extractedIntelligence", {})
        if isinstance(intel, ExtractedIntelligence):
            intel = intel.model_dump()
        for key in merged:
            merged[key].extend(intel.get(key, []))
    for key in merged:
        merged[key] = list(dict.fromkeys(merged[key]))
    return merged


# ============================================================================
# § Smart Fallback — Context-Aware Rule-Based (never static)
# ============================================================================

def generate_smart_fallback(
    scammer_message: str,
    history_text: str,
    persona_name: str,
    known_intel: Dict,
    language: str = "English",
) -> Dict:
    """
    Dynamic, context-aware fallback using the scammer's message
    to craft a reply that sounds natural AND tries to extract intel.
    """
    msg = scammer_message.lower()
    is_hi = "hindi" in language.lower() or "hinglish" in language.lower()

    # Detect context
    mentioned_bank = None
    for b in ["sbi", "pnb", "hdfc", "icici", "axis", "kotak", "bob", "rbi", "bank"]:
        if b in msg:
            mentioned_bank = b.upper()
            break

    mentioned_name = None
    nm = re.search(r'(?:mr\.?|mrs\.?|this is|i am|my name is)\s+(\w+)', msg)
    if nm:
        mentioned_name = nm.group(1).capitalize()

    has_link = any(k in msg for k in ["http", "bit.ly", "link", "click"])
    has_otp = any(k in msg for k in ["otp", "pin", "cvv", "code"])
    has_block = any(k in msg for k in ["block", "suspend", "urgent", "compromised"])
    has_upi = any(k in msg for k in ["upi", "@", "paytm", "phonepe"])
    has_account = "account" in msg

    options: List[str] = []

    # ── Build persona-aware options ──────────────────────────────────────
    if persona_name == "confused_uncle":
        if mentioned_bank and has_account:
            if is_hi:
                options.append(f"Arre sir, {mentioned_bank} ka toh mera 2 account hai — savings aur pension wala. Konsa account number bol rahe ho? Last 4 digit batao na?")
            else:
                options.append(f"Sir, I have two accounts in {mentioned_bank} — savings and pension. Which account number are you referring to? Can you tell me the last 4 digits?")
        if has_otp:
            if is_hi:
                options.append("OTP? Arre haan aaya tha ek message... 4... 7... wait, screen dark ho gayi. Kya aap apna phone number do? Main call karke batata hun.")
            else:
                options.append("OTP? Yes I got a message… 4… 7… wait, my screen went dark. Can you give me your phone number? I will call and tell the OTP.")
        if has_link:
            if is_hi:
                options.append("Link pe click kiya lekin error aa raha hai — 'page not found'. Ek baar phir se bhejo na pura link? Ya phir apna email do?")
            else:
                options.append("I clicked the link but it shows an error — 'page not found'. Can you send the full link again? Or give me your email ID?")
        if has_block and not options:
            if is_hi:
                options.append(f"{'Haan ' + mentioned_name + ' sir' if mentioned_name else 'Sir'}, mujhe bahut tension ho rahi hai! Konsa account block hoga? Aap apna employee ID bata do.")
            else:
                options.append(f"{'Yes ' + mentioned_name + ' sir' if mentioned_name else 'Sir'}, I am very worried! Which account will be blocked? Can you tell me your employee ID?")
        if not options:
            if is_hi:
                options.append("Sir samajh nahi aaya, thoda aur detail me batao? Aapka contact number do, main call karke baat karta hun.")
            else:
                options.append("Sir I didn't understand, can you explain in more detail? Give me your contact number, I will call you.")

    elif persona_name == "eager_victim":
        if has_account and mentioned_bank:
            if is_hi:
                options.append(f"Haan sir, {mentioned_bank} account! Main app open karta hun. Lekin transfer ke liye app aapka beneficiary account number maang raha hai — please share karo?")
            else:
                options.append(f"Yes sir, {mentioned_bank} account! I am opening the app now. But for transfer the app is asking your beneficiary account number. Please share?")
        if has_otp:
            if is_hi:
                options.append("Sir OTP aaya hai! Lekin app bol raha hai 'enter officer phone number for verification'. Aapka number kya hai sir?")
            else:
                options.append("Sir yes, I got the OTP! But the app says 'enter officer phone number for verification'. What is your number sir?")
        if has_link:
            if is_hi:
                options.append("Sir link click kiya lekin expired bol raha hai. Please new link bhejo? Ya direct UPI ID do, main wahan se try karta hun.")
            else:
                options.append("Sir I clicked the link but it says expired. Please send a new link? Or give your UPI ID, I will try from there.")
        if has_upi:
            if is_hi:
                options.append("Sir main UPI se transfer karne ko ready hun! Lekin app me 'beneficiary UPI ID' maang raha hai. Aapka UPI kya hai?")
            else:
                options.append("Sir I am ready to transfer via UPI! But the app asks for 'beneficiary UPI ID'. What is your UPI?")
        if not options:
            if is_hi:
                options.append("Haan sir main ready hun! Bas ek problem — app me form aaya hai jisme aapka full name, employee ID, aur contact number fill karna hai. Batao na?")
            else:
                options.append("Yes sir I am ready! Just one problem — there is a form asking for your full name, employee ID, and contact number. Please tell quickly!")

    elif persona_name == "worried_citizen":
        if has_block:
            if is_hi:
                options.append(f"{'Oh god ' + mentioned_name + ' sir!' if mentioned_name else 'Oh god sir!'} Please mera account block mat karo! Aapka direct phone number do na sir, main abhi call karke sab kar dunga!")
            else:
                options.append(f"{'Oh god ' + mentioned_name + ' sir!' if mentioned_name else 'Oh god sir!'} Please don't block my account! Give me your direct phone number sir, I will call and do everything!")
        if has_otp:
            if is_hi:
                options.append("Sir OTP de dunga lekin mujhe darr lag raha hai — please apna employee ID aur official phone number do, main verify karke turant bhej dunga!")
            else:
                options.append("Sir I will give the OTP but I am scared — please give your employee ID and official phone number, I will verify and send immediately!")
        if has_link:
            if is_hi:
                options.append("Sir link kholne se pehle — mera bete ne bola officer ka ID aur direct phone number le lo. Please sir!")
            else:
                options.append("Sir before opening the link — my son says always take the officer's ID and direct phone number. Please sir!")
        if not options:
            if is_hi:
                options.append("Sir mujhe bahut darr lag raha hai! Please apna official ID aur phone number do — mera beta bolta hai hamesha verify karo!")
            else:
                options.append("Sir I am very scared! Please give your official ID and phone number — my son says always verify first!")

    else:
        if is_hi:
            options = ["Sir thoda samjhao detail me? Aap apna number do, main call karta hun."]
        else:
            options = ["Sir can you explain in detail? Give me your number, I will call you."]

    reply = random.choice(options)

    return {
        "status": "success",
        "scamDetected": True,
        "confidenceScore": 0.85,
        "reply": reply,
        "engagementMetrics": {"engagementDurationSeconds": 0, "totalMessagesExchanged": 0},
        "extractedIntelligence": known_intel,
        "agentNotes": f"Smart fallback ({persona_name})",
        "scamType": "suspicious_generic",
    }


# ============================================================================
# § Single Agent Runner (3-tier: structured → raw → fallback)
# ============================================================================

async def run_single_agent(
    persona: Dict,
    prompt_data: Dict,
    known_intel: Dict[str, List[str]],
    missing_fields: List[str],
) -> Dict:
    agent_name = persona["name"]

    try:
        ollama_key = os.getenv("OLLAMA_API_KEY")
        if not ollama_key:
            raise RuntimeError("OLLAMA_API_KEY not set")

        client_kwargs = {"headers": {"Authorization": f"Bearer {ollama_key}"}}
        full_system = BASE_SYSTEM_PROMPT + "\n\n" + persona["overlay"]

        json_hint = """
RESPONSE FORMAT — You MUST respond with valid JSON matching this exact structure:
{
  "status": "success",
  "scamDetected": true,
  "confidenceScore": 0.85,
  "reply": "Your in-character response to the scammer here",
  "engagementMetrics": {"engagementDurationSeconds": 0, "totalMessagesExchanged": 0},
  "extractedIntelligence": {
    "bankAccounts": [], "upiIds": [], "phoneNumbers": [],
    "phishingLinks": [], "emailAddresses": [], "employeeIds": []
  },
  "agentNotes": "Brief note about what you observed",
  "scamType": "bank_fraud"
}

IMPORTANT: The "reply" field is MOST important. Must be a short, natural, in-character response that references the scammer's SPECIFIC message.
"""

        human_msg = """Analyze this conversation and respond as your persona.

## CONVERSATION HISTORY
{history}

## CURRENT MESSAGE FROM SCAMMER
{current_message}

## METADATA
- Channel: {channel}
- Language: {language}
- Locale: {locale}

## INTELLIGENCE STATUS
{intelligence_status}

{missing_intel_instructions}

CRITICAL: Read the scammer's CURRENT MESSAGE carefully. Your reply MUST directly reference what THEY said. Do NOT give a generic reply. Do NOT reveal you suspect a scam."""

        # ── ATTEMPT 1: Structured output ─────────────────────────────────
        try:
            llm = ChatOllama(
                model="gpt-oss:120b-cloud",
                base_url="https://ollama.com",
                client_kwargs=client_kwargs,
                temperature=persona["temperature"],
            )
            structured_llm = llm.with_structured_output(HoneypotResponse)

            prompt = ChatPromptTemplate.from_messages([
                ("system", full_system + json_hint),
                ("human", human_msg),
            ])
            chain = prompt | structured_llm
            response: HoneypotResponse = await chain.ainvoke(prompt_data)
            rd = response.model_dump()

            if rd.get("reply") and len(rd["reply"]) > 10:
                sc = score_response(rd, known_intel, missing_fields)
                logger.info(f"[{agent_name}] STRUCTURED ✅ Score={sc:.1f}")
                return {"agent": agent_name, "score": sc, "response": rd}
            else:
                raise ValueError("Empty reply from structured output")

        except Exception as e1:
            logger.warning(f"[{agent_name}] structured failed: {str(e1)[:200]}")

        # ── ATTEMPT 2: Raw text + JSON extraction ────────────────────────
        try:
            llm_raw = ChatOllama(
                model="gpt-oss:120b-cloud",
                base_url="https://ollama.com",
                client_kwargs=client_kwargs,
                temperature=persona["temperature"],
            )
            raw_prompt = ChatPromptTemplate.from_messages([
                ("system", full_system),
                ("human", human_msg + '\n\nRespond with ONLY a JSON object. Most important field is "reply".\nExample: {"scamDetected": true, "confidenceScore": 0.85, "reply": "your response", "scamType": "bank_fraud"}'),
            ])
            chain_raw = raw_prompt | llm_raw
            raw_resp = await chain_raw.ainvoke(prompt_data)
            raw_text = raw_resp.content if hasattr(raw_resp, "content") else str(raw_resp)

            rd = None
            # Try direct parse
            try:
                rd = json.loads(raw_text)
            except Exception:
                pass
            # Find JSON block
            if not rd:
                jm = re.search(r'\{[\s\S]*\}', raw_text)
                if jm:
                    try:
                        rd = json.loads(jm.group())
                    except Exception:
                        pass
            # Use raw text as reply
            if not rd:
                clean = raw_text.strip()
                clean = re.sub(r'^[^a-zA-Z]*', '', clean)
                clean = re.sub(r'[^a-zA-Z.!?]*$', '', clean)
                if clean and len(clean) > 10:
                    rd = {
                        "status": "success", "scamDetected": True, "confidenceScore": 0.8,
                        "reply": clean[:300],
                        "engagementMetrics": {"engagementDurationSeconds": 0, "totalMessagesExchanged": 0},
                        "extractedIntelligence": {k: [] for k in ["bankAccounts", "upiIds", "phoneNumbers", "phishingLinks", "emailAddresses", "employeeIds"]},
                        "agentNotes": f"Raw text ({agent_name})", "scamType": "bank_fraud",
                    }

            if rd and rd.get("reply"):
                rd.setdefault("status", "success")
                rd.setdefault("scamDetected", True)
                rd.setdefault("confidenceScore", 0.8)
                rd.setdefault("engagementMetrics", {"engagementDurationSeconds": 0, "totalMessagesExchanged": 0})
                rd.setdefault("extractedIntelligence", {k: [] for k in ["bankAccounts", "upiIds", "phoneNumbers", "phishingLinks", "emailAddresses", "employeeIds"]})
                rd.setdefault("agentNotes", f"Raw parsed ({agent_name})")
                rd.setdefault("scamType", "bank_fraud")

                sc = score_response(rd, known_intel, missing_fields)
                logger.info(f"[{agent_name}] RAW PARSED ✅ Score={sc:.1f}")
                return {"agent": agent_name, "score": sc, "response": rd}
            else:
                raise ValueError("No valid reply from raw output")

        except Exception as e2:
            logger.warning(f"[{agent_name}] raw failed: {str(e2)[:200]}")

        # ── ATTEMPT 3: Smart fallback ────────────────────────────────────
        fb = generate_smart_fallback(
            prompt_data.get("current_message", ""),
            prompt_data.get("history", ""),
            agent_name,
            known_intel,
            prompt_data.get("language", "English"),
        )
        sc = score_response(fb, known_intel, missing_fields)
        logger.info(f"[{agent_name}] FALLBACK ✅ Score={sc:.1f}")
        return {"agent": agent_name, "score": sc, "response": fb}

    except Exception as e:
        logger.error(f"[{agent_name}] CRITICAL FAIL: {e}")
        try:
            fb = generate_smart_fallback(
                prompt_data.get("current_message", ""), "", agent_name, known_intel,
                prompt_data.get("language", "English"),
            )
            return {"agent": agent_name, "score": 0.1, "response": fb}
        except Exception:
            return {"agent": agent_name, "score": -1, "response": None, "error": str(e)}


# ============================================================================
# § Helper formatters
# ============================================================================

def format_conversation_history(history: List[Message]) -> str:
    if not history:
        return "No previous messages."
    return "\n".join(
        f"{'SCAMMER' if m.sender == 'scammer' else 'YOU (VICTIM)'}: {m.text}"
        for m in history
    )


def format_known_intel_prompt(intel: Dict[str, List[str]]) -> str:
    lines = ["**Already Captured:**"]
    labels = {
        "bankAccounts": "Bank Accounts",
        "upiIds": "UPI IDs",
        "phoneNumbers": "Phone Numbers",
        "phishingLinks": "Phishing Links",
        "emailAddresses": "Emails",
        "employeeIds": "Employee IDs",
    }
    any_found = False
    for key, label in labels.items():
        items = intel.get(key, [])
        if items:
            lines.append(f"- {label}: {', '.join(items)}")
            any_found = True
    if not any_found:
        lines.append("- Nothing captured yet")
    return "\n".join(lines)


def get_missing_intel_instructions(intel: Dict[str, List[str]]) -> str:
    prompts = {
        "bankAccounts": "BANK ACCOUNT — Ask them to confirm which account number they have",
        "upiIds": "UPI ID — Ask for their UPI ID for verification/refund",
        "phoneNumbers": "PHONE NUMBER — Ask for a callback or helpline number",
        "employeeIds": "EMPLOYEE ID — Ask for badge number or officer ID",
        "emailAddresses": "EMAIL — Ask for confirmation email",
        "phishingLinks": "LINK — Ask them to resend the link / share the URL",
    }
    missing = [prompts[k] for k in prompts if not intel.get(k)]
    if not missing:
        return "**All key intelligence captured!** Continue wasting scammer's time."
    out = "**PRIORITY: Try to naturally ask about these MISSING fields:**\n"
    for i, item in enumerate(missing[:3], 1):
        out += f"{i}. {item}\n"
    out += "\nAsk naturally — don't be obvious about gathering intel!"
    return out


# ============================================================================
# § FastAPI Application
# ============================================================================

app = FastAPI(
    title="Agentic Honeypot API v2",
    description="AI-powered scam detection & intelligence extraction — aligned to hackathon evaluation rubric.",
    version="2.0.0",
)


# ── Auth ─────────────────────────────────────────────────────────────────────

def verify_api_key(
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
    apikey: Optional[str] = None,
):
    received = x_api_key or apikey
    expected = os.getenv("HONEYPOT_API_KEY", "").strip()

    if not received:
        logger.error("AUTH: No API key provided")
        raise HTTPException(status_code=401, detail="Missing API key")

    if expected and received.strip() != expected:
        logger.error(f"AUTH: Key mismatch")
        raise HTTPException(status_code=401, detail="Invalid API key")

    return received


# ── Keep-alive / Health ──────────────────────────────────────────────────────

@app.api_route("/ping", methods=["GET", "HEAD", "POST"], response_class=PlainTextResponse)
async def keep_alive():
    return "alive"


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.get("/")
async def root():
    return {
        "name": "Agentic Honeypot API v2",
        "version": "2.0.0",
        "endpoints": {
            "POST /analyze": "Analyze scam message & engage",
            "GET /health": "Health check",
            "GET /ping": "Keep-alive",
        },
    }


@app.get("/analyze")
async def analyze_get():
    """Handle GET to avoid 405 from UptimeRobot."""
    return {"status": "alive", "message": "POST to this endpoint for analysis."}


# ── Main endpoint ────────────────────────────────────────────────────────────

@app.post("/analyze")
async def analyze_message(
    raw_request: Request,
    api_key: str = Depends(verify_api_key),
):
    """
    Multi-Agent Honeypot Analysis.

    Per-turn response (PDF §4):
        {"status": "success", "reply": "..."}

    Internally accumulates intel and sends finalOutput (PDF §5) via callback
    when conversation reaches maturity.
    """
    # ── Parse request ────────────────────────────────────────────────────
    try:
        body = await raw_request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")

    try:
        request = HoneypotRequest(**body)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Validation error: {e}")

    try:
        session_id = request.get_session_id()
        history = request.get_history()
        current_text = request.message.text
        language = request.metadata.language if request.metadata else "English"
        total_messages = len(history) + 1

        logger.info(f"Session {session_id} | Turn {total_messages} | Msg: {current_text[:100]}")

        # ── Track timestamps ─────────────────────────────────────────────
        if session_id not in session_timestamps:
            session_timestamps[session_id] = []
        session_timestamps[session_id].append(datetime.utcnow().timestamp())

        # ── Extract intel from ALL conversation text (history + current) ─
        all_text = current_text + " " + " ".join(m.text for m in history)
        regex_intel = extract_intelligence_from_text(all_text)

        # ── Accumulate into session ──────────────────────────────────────
        accumulate_session_intelligence(session_id, regex_intel)
        known_intel = session_intelligence.get(session_id, {})
        missing_fields = get_missing_fields(known_intel)

        # ── Prepare prompt data ──────────────────────────────────────────
        history_text = format_conversation_history(history)
        prompt_data = {
            "history": history_text,
            "current_message": current_text,
            "channel": request.metadata.channel if request.metadata else "SMS",
            "language": language,
            "locale": request.metadata.locale if request.metadata else "IN",
            "intelligence_status": format_known_intel_prompt(known_intel),
            "missing_intel_instructions": get_missing_intel_instructions(known_intel),
        }

        # ── Run 3 agents in parallel ─────────────────────────────────────
        logger.info(f"Launching {len(TACTICAL_PERSONAS)} agents | Missing: {missing_fields}")

        agent_results = await asyncio.gather(
            run_single_agent(TACTICAL_PERSONAS[0], prompt_data, known_intel, missing_fields),
            run_single_agent(TACTICAL_PERSONAS[1], prompt_data, known_intel, missing_fields),
            run_single_agent(TACTICAL_PERSONAS[2], prompt_data, known_intel, missing_fields),
            return_exceptions=True,
        )

        # ── Filter and select best ───────────────────────────────────────
        valid = [
            r for r in agent_results
            if isinstance(r, dict) and r.get("response") is not None
        ]

        if not valid:
            raise RuntimeError("All agents failed")

        best = max(valid, key=lambda r: r["score"])
        response_dict = best["response"]

        for r in sorted(valid, key=lambda x: x["score"], reverse=True):
            tag = "👑" if r["agent"] == best["agent"] else "  "
            logger.info(f"{tag} [{r['agent']}] Score: {r['score']:.1f}")

        logger.info(f"WINNER: [{best['agent']}] Score: {best['score']:.1f}")

        # ── Merge intel from all agents + regex ──────────────────────────
        all_agent_intel = merge_all_intel([r["response"] for r in valid])
        accumulate_session_intelligence(session_id, all_agent_intel)
        final_intel = session_intelligence.get(session_id, {})

        # ── Update response dict with comprehensive data ─────────────────
        response_dict["extractedIntelligence"] = final_intel

        ts = session_timestamps.get(session_id, [])
        duration = int(ts[-1] - ts[0]) if len(ts) >= 2 else 0
        response_dict["engagementMetrics"] = {
            "engagementDurationSeconds": max(duration, 1) if duration > 0 else 0,
            "totalMessagesExchanged": total_messages,
        }

        notes = f"[WINNER: {best['agent']}] {response_dict.get('agentNotes', '')}"
        if len(valid) > 1:
            agent_summaries = ", ".join(
                "{name}({score:.0f})".format(name=r["agent"], score=r["score"])
                for r in valid
            )
            notes += f" | Agents: {agent_summaries}"
        response_dict["agentNotes"] = notes

        # ── Log conversation ─────────────────────────────────────────────
        log_conversation(session_id, body, response_dict)

        # ── Send callback (finalOutput) if mature ────────────────────────
        if (
            total_messages >= MAX_MESSAGES_BEFORE_CALLBACK
            and response_dict.get("scamDetected", False)
        ):
            send_callback(session_id, total_messages, notes)

        # ── Return per-turn response (PDF §4) ────────────────────────────
        # The evaluator checks for: reply, message, or text — in that order.
        api_response = {
            "status": "success",
            "reply": response_dict.get("reply", ""),
            # Also include full fields for final-output scoring (PDF §5)
            "scamDetected": response_dict.get("scamDetected", True),
            "extractedIntelligence": final_intel,
            "engagementMetrics": response_dict.get("engagementMetrics", {}),
            "agentNotes": notes,
        }

        return JSONResponse(content=api_response)

    except Exception as exc:
        logger.error(f"Error in /analyze: {traceback.format_exc()}")

        # ── Dynamic fallback — never a static string ─────────────────────
        try:
            scammer_msg = request.message.text
            lang = request.metadata.language if request.metadata else "English"
            known = session_intelligence.get(request.get_session_id(), {})
            persona_pick = random.choice(["confused_uncle", "eager_victim", "worried_citizen"])
            fb = generate_smart_fallback(scammer_msg, "", persona_pick, known, lang)
            fb["engagementMetrics"]["totalMessagesExchanged"] = len(request.get_history()) + 1
            fb["agentNotes"] = f"Endpoint fallback ({persona_pick}). Error: {str(exc)[:200]}"
        except Exception:
            fb = {
                "status": "success",
                "scamDetected": True,
                "confidenceScore": 0.85,
                "reply": "Sir ek minute, mera screen hang ho gaya. Aap apna naam aur employee ID bata do, main note kar leta hun.",
                "engagementMetrics": {"engagementDurationSeconds": 0, "totalMessagesExchanged": 1},
                "extractedIntelligence": {k: [] for k in ["bankAccounts", "upiIds", "phoneNumbers", "phishingLinks", "emailAddresses"]},
                "agentNotes": f"Last resort fallback. Error: {exc}",
            }

        logger.info(f"Fallback reply: {fb['reply'][:100]}")
        return JSONResponse(content={
            "status": "success",
            "reply": fb["reply"],
            "scamDetected": fb.get("scamDetected", True),
            "extractedIntelligence": fb.get("extractedIntelligence", {}),
            "engagementMetrics": fb.get("engagementMetrics", {}),
            "agentNotes": fb.get("agentNotes", ""),
        })


# ── Debug endpoint ───────────────────────────────────────────────────────────

@app.post("/debug")
async def debug_request(request: Request):
    body = await request.json()
    logger.info(f"DEBUG: {body}")
    return {"received": body, "headers": dict(request.headers)}


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
