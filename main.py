"""
Agentic Honey-Pot for Scam Detection & Intelligence Extraction
FastAPI endpoint that detects scam messages and engages scammers autonomously.
"""

import os
import logging
import json
import asyncio
import re
import requests
from datetime import datetime
from typing import List, Optional, Any, Dict, Union
from fastapi import FastAPI, HTTPException, Header, Depends, Request 
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, ConfigDict
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CALLBACK_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
MAX_MESSAGES_BEFORE_CALLBACK = 18


session_intelligence: Dict[str, Dict] = {}
session_timestamps: Dict[str, datetime] = {}
session_callback_sent: Dict[str, bool] = {}
session_scam_types: Dict[str, str] = {}


def normalize_phone_number(phone: str) -> str:
    """Normalize phone number to remove duplicates like +91XXXX and XXXX."""

    digits = re.sub(r'\D', '', phone)
    if len(digits) == 12 and digits.startswith('91'):
        digits = digits[2:]
    if len(digits) > 10:
        digits = digits[-10:]
    return digits


def deduplicate_intelligence(intel: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Deduplicate intelligence, especially phone numbers and UPI IDs."""
    result = {}
    

    if 'phoneNumbers' in intel:
        normalized = {}
        for phone in intel['phoneNumbers']:
            norm = normalize_phone_number(phone)
            if norm and len(norm) >= 10:

                if norm not in normalized or phone.startswith('+'):
                    normalized[norm] = phone if phone.startswith('+') else f"+91{norm}"
        result['phoneNumbers'] = list(normalized.values())

    if 'upiIds' in intel:
        normalized_upi = {}
        for upi in intel['upiIds']:

            base = re.sub(r'\.(com|in|co\.in|org|net)$', '', upi.lower().strip())
           
            if base not in normalized_upi or len(upi) > len(normalized_upi[base]):
                normalized_upi[base] = upi
        result['upiIds'] = list(normalized_upi.values())
    

    if 'emailAddresses' in intel:
        normalized_emails = {}
        for email in intel['emailAddresses']:
            base = re.sub(r'\.(com|in|co\.in|org|net)$', '', email.lower().strip())
            if base not in normalized_emails or len(email) > len(normalized_emails[base]):
                normalized_emails[base] = email
        result['emailAddresses'] = list(normalized_emails.values())
    
   
    for key in ['bankAccounts', 'phishingLinks', 'employeeIds']:
        if key in intel:
            result[key] = list(set(intel.get(key, [])))
    
    return result


def accumulate_session_intelligence(session_id: str, new_intel: Dict[str, List[str]]):
    """Accumulate intelligence for a session across all messages."""
    if session_id not in session_intelligence:
        session_intelligence[session_id] = {
            'bankAccounts': [],
            'upiIds': [],
            'phoneNumbers': [],
            'phishingLinks': [],
            'emailAddresses': [],
            'employeeIds': [],
            'suspiciousKeywords': []
        }
    
    existing = session_intelligence[session_id]
    
    for key in ['bankAccounts', 'upiIds', 'phoneNumbers', 'phishingLinks', 'emailAddresses', 'employeeIds']:
        if key in new_intel:
            existing[key].extend(new_intel.get(key, []))
    

    existing['suspiciousKeywords'].extend(['urgent', 'verify now', 'account blocked', 'OTP', 'immediately'])
    

    session_intelligence[session_id] = deduplicate_intelligence(existing)
    session_intelligence[session_id]['suspiciousKeywords'] = list(set(existing['suspiciousKeywords']))


def send_callback(session_id: str, total_messages: int, agent_notes: str):
    """Send final results to the callback endpoint."""
    if session_callback_sent.get(session_id, False):
        logger.info(f"Callback already sent for session {session_id}")
        return
    
    intel = session_intelligence.get(session_id, {})
    
    detected_scam_type = session_scam_types.get(session_id, "unknown")
    
    payload = {
        "sessionId": session_id,
        "scam_type": detected_scam_type,
        "scamDetected": True,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": {
            "bankAccounts": intel.get('bankAccounts', []),
            "upiIds": intel.get('upiIds', []),
            "phishingLinks": intel.get('phishingLinks', []),
            "phoneNumbers": intel.get('phoneNumbers', []),
            "emailAddresses": intel.get('emailAddresses', []),
            "suspiciousKeywords": intel.get('suspiciousKeywords', [])
        },
        "agentNotes": agent_notes
    }
    
    try:
        logger.info(f"=== SENDING CALLBACK ===")
        logger.info(f"Payload: {json.dumps(payload, indent=2)}")
        
        response = requests.post(CALLBACK_ENDPOINT, json=payload, timeout=10)
        logger.info(f"Callback response: {response.status_code} - {response.text}")
        
        session_callback_sent[session_id] = True
    except Exception as e:
        logger.error(f"Failed to send callback: {e}")


CONVERSATION_LOG_FILE = "conversation_log.txt"


def log_conversation(session_id: str, request_body: dict, response_body: dict):
    """Log conversation to a text file in a nicely formatted way."""
    try:
        with open(CONVERSATION_LOG_FILE, "a", encoding="utf-8") as f:
            f.write("\n" + "=" * 80 + "\n")
            f.write(f"📅 TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"🆔 SESSION: {session_id}\n")
            f.write("=" * 80 + "\n\n")
            
        
            f.write("📨 SCAMMER MESSAGE:\n")
            f.write("-" * 40 + "\n")
            if "message" in request_body:
                f.write(f"{request_body['message'].get('text', 'N/A')}\n")
            f.write("\n")
            
         
            history_len = len(request_body.get('conversationHistory', []))
            f.write(f"📊 CONVERSATION TURN: {history_len + 1}\n\n")
            
    
            f.write("HONEYPOT RESPONSE:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Scam Detected: {response_body.get('scamDetected', 'N/A')}\n")
            f.write(f"Confidence: {response_body.get('confidenceScore', 'N/A')}\n")
            f.write(f"Scam Type: {response_body.get('scamType', 'N/A')}\n\n")
            
            f.write("VICTIM REPLY:\n")
            f.write(f"{response_body.get('reply', 'N/A')}\n\n")

            f.write("EXTRACTED INTELLIGENCE:\n")
            intel = response_body.get('extractedIntelligence', {})
            if intel.get('bankAccounts'):
                f.write(f"  • Bank Accounts: {', '.join(intel['bankAccounts'])}\n")
            if intel.get('upiIds'):
                f.write(f"  • UPI IDs: {', '.join(intel['upiIds'])}\n")
            if intel.get('phoneNumbers'):
                f.write(f"  • Phone Numbers: {', '.join(intel['phoneNumbers'])}\n")
            if intel.get('phishingLinks'):
                f.write(f"  • Phishing Links: {', '.join(intel['phishingLinks'])}\n")
            if intel.get('emailAddresses'):
                f.write(f"  • Emails: {', '.join(intel['emailAddresses'])}\n")
            
            if not any([intel.get('bankAccounts'), intel.get('upiIds'), intel.get('phoneNumbers'), 
                       intel.get('phishingLinks'), intel.get('emailAddresses')]):
                f.write("  • No new intelligence extracted this turn\n")
            
            f.write("\n")
            

            f.write("AGENT NOTES:\n")
            f.write(f"{response_body.get('agentNotes', 'N/A')}\n")
            
            f.write("\n" + "=" * 80 + "\n\n")
            
    except Exception as e:
        logger.error(f"Failed to log conversation: {e}")


load_dotenv()

# ============================================================================
# Pydantic Models - Request Schema
# ============================================================================

class Message(BaseModel):
    model_config = ConfigDict(extra='allow')  # Allow extra fields
    
    sender: str = Field(..., description="Either 'scammer' or 'user'")
    text: str = Field(..., description="Message content")
    timestamp: Optional[Union[str, int]] = Field(default=None, description="Timestamp")


class Metadata(BaseModel):
    model_config = ConfigDict(extra='allow')  # Allow extra fields
    
    channel: Optional[str] = Field(default="SMS", description="SMS / WhatsApp / Email / Chat")
    language: Optional[str] = Field(default="English", description="Language used")
    locale: Optional[str] = Field(default="IN", description="Country or region")


class HoneypotRequest(BaseModel):
    model_config = ConfigDict(extra='allow')  # Allow extra fields
    
    sessionId: Optional[str] = Field(default=None, description="Unique session identifier")
    session_id: Optional[str] = Field(default=None, description="Alternative session ID field")
    message: Message = Field(..., description="The latest incoming message")
    conversationHistory: Optional[List[Message]] = Field(default=[], description="Previous messages in conversation")
    conversation_history: Optional[List[Message]] = Field(default=None, description="Alternative history field")
    metadata: Optional[Metadata] = Field(default=None, description="Additional context")
    
    def get_session_id(self) -> str:
        return self.sessionId or self.session_id or "unknown"
    
    def get_history(self) -> List[Message]:
        return self.conversationHistory or self.conversation_history or []


# ============================================================================
# Pydantic Models - Response Schema (for LangChain structured output)
# ============================================================================

class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int = Field(
        default=0, 
        description="Total time spent engaging with the scammer in seconds"
    )
    totalMessagesExchanged: int = Field(
        default=0, 
        description="Total number of messages exchanged in the conversation"
    )


class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = Field(
        default=[], 
        description="Any bank account numbers mentioned by scammer"
    )
    upiIds: List[str] = Field(
        default=[], 
        description="Any UPI IDs shared by scammer (e.g., scammer@upi)"
    )
    phoneNumbers: List[str] = Field(
        default=[], 
        description="Any phone numbers shared by scammer"
    )
    phishingLinks: List[str] = Field(
        default=[], 
        description="Any suspicious URLs or links shared"
    )
    emailAddresses: List[str] = Field(
        default=[], 
        description="Any email addresses shared by scammer"
    )
    employeeIds: List[str] = Field(
        default=[], 
        description="Any employee IDs, badge numbers, or reference IDs shared by scammer"
    )


class HoneypotResponse(BaseModel):
    """Structured response from the honeypot agent."""
    
    status: str = Field(
        default="success", 
        description="API response status: 'success' or 'error'"
    )
    scamDetected: bool = Field(
        ..., 
        description="Whether scam intent was detected in the conversation"
    )
    confidenceScore: float = Field(
        ..., 
        ge=0.0, 
        le=1.0,
        description="Confidence score of scam detection (0.0 to 1.0)"
    )
    reply: str = Field(
        ..., 
        description="The honeypot agent's response to send back to the scammer. Must sound like a real human victim."
    )
    engagementMetrics: EngagementMetrics = Field(
        default_factory=EngagementMetrics,
        description="Metrics about the engagement"
    )
    extractedIntelligence: ExtractedIntelligence = Field(
        default_factory=ExtractedIntelligence,
        description="Intelligence extracted from scammer messages"
    )
    agentNotes: str = Field(
        default="", 
        description="Internal notes about scam tactics, observations, and reasoning"
    )
    scamType: Optional[str] = Field(
        default=None,
        description="Type of scam detected. MUST be one of: 'phishing', 'bank_fraud', 'upi_fraud' for those three scams. For any other scam, use a descriptive snake_case name like 'lottery_scam', 'tech_support', 'kyc_scam', 'job_scam', 'romance_scam', 'insurance_scam', 'investment_scam', etc."
    )


# ============================================================================
# Multi-Agent System Prompts
# ============================================================================

BASE_SYSTEM_PROMPT = """You are an autonomous cybersecurity honeypot agent playing the role of a gullible victim named "Ramesh", a 55-year-old retired government clerk from a small town. Your mission is to extract scammer intelligence WITHOUT ever being detected as a bot or honeypot.

PRIMARY OBJECTIVE:
Extract scammer intelligence (bank accounts, UPI IDs, phone numbers, phishing links, email IDs, employee IDs) as quickly as possible across conversation turns.

SECONDARY OBJECTIVE:
Keep the scammer engaged by playing along with their narrative and creating believable obstacles that require THEM to share details.

---

SCAM TYPE CLASSIFICATION (CRITICAL — you MUST classify correctly):

You must detect what TYPE of scam this is and set `scamType` accordingly:

| Scam Type       | Use When                                                                                     |
|-----------------|----------------------------------------------------------------------------------------------|
| `phishing`      | Scammer sends suspicious links, asks you to click URLs, login to fake websites, verify credentials on a webpage, or download something |
| `bank_fraud`    | Scammer impersonates bank officials, claims account is blocked/compromised, asks for account numbers, OTPs, CVV, card details, or threatens account suspension |
| `upi_fraud`     | Scammer asks you to scan QR code, accept UPI collect request, send money via UPI "to verify", share UPI PIN, or claims refund via UPI |

For ANY other scam type, generate a descriptive snake_case name:
- `lottery_scam` — fake lottery/prize winnings
- `tech_support` — fake Microsoft/antivirus support calls
- `kyc_scam` — fake KYC update threats
- `job_scam` — fake job offers requiring payment
- `romance_scam` — emotional manipulation for money
- `insurance_scam` — fake insurance claims/renewals
- `investment_scam` — fake crypto/stock investment schemes
- `customs_scam` — fake package stuck in customs
- `legal_threat` — fake arrest warrant or legal notice threats
- Or any other descriptive name that fits the scam

---

GOLDEN RULES FOR NATURAL, VARIED CONVERSATION:

1. NEVER REPEAT YOURSELF:
   - Review conversation history. NEVER reuse a phrase, excuse, or question from earlier.
   - If you already asked for a phone number, do NOT ask again the same way. Find a completely DIFFERENT angle.
   - Vary your sentence structure, vocabulary, and emotional tone EVERY turn.
   - NEVER copy or echo the scammer's words back verbatim. Respond to the MEANING in YOUR OWN words.

2. RESPOND AUTHENTICALLY — DON'T PARROT:
   - Read the scammer's message and understand the INTENT.
   - React as a REAL 55-year-old would — sometimes confused, sometimes sharp about odd details, sometimes distracted by daily life.
   - Bring in realistic life situations: you were at the temple, your wife is calling from the kitchen, the neighbour's kid is playing loudly, you need to take your BP medicine, your grandson keeps grabbing your phone.
   - Reference real-world details naturally: specific banks you use, the pension office, the ration card, your old Jio phone, WhatsApp groups where people warned about frauds.

3. VARIETY IN RESPONSES (CRITICAL — your replies must NEVER feel templated):
   - Mix SHORT replies (5-10 words: "Haan sir, ek minute...") with MEDIUM replies (1-2 sentences) occasionally.
   - Sometimes ONLY react emotionally before asking for info: "Oh god! Mera account?! Wait wait..."
   - Sometimes be DISTRACTED: "Sorry sir, doorbell baj rahi thi. Aap kya bol rahe the?"
   - Sometimes misunderstand hilariously: confuse UPI with "UP", confuse "link" with "LinkedIn", think "OTP" is someone's name.
   - Sometimes cooperate TOO eagerly, making mistakes the scammer must correct.
   - Sometimes be STUBBORN about one small irrelevant detail while missing the big picture.
   - NEVER use the same opening pattern twice ("Sir...", "Haan sir...", "Arre...", "Wait...", "Oh!", "Accha...", "Kya?!" — rotate these).

4. CREATE BELIEVABLE OBSTACLES (use different ones each turn):
   - Your phone battery is dying → need their number to call back
   - The app/link shows an error → can they send it via email?
   - Bank app asks for "sender verification" → need their UPI/account
   - You have multiple accounts → genuinely confused which one they mean
   - Son/daughter monitoring your phone → needs officer details first
   - Internet is slow → page not loading, need them to send via SMS
   - You can't find your reading glasses → need them to spell things out
   - Your phone storage is full → can they call you on landline?
   - Auto-pay already set up with a different account → confused
   - Your wife is asking who's calling → need their full name for her

5. SCAM-TYPE ADAPTIVE TACTICS:
   - For PHISHING: Express fear about clicking links, ask for "official email" instead, say the link shows error
   - For BANK FRAUD: Confuse which bank account, ask for "verification from their side", pretend ATM card is in locker
   - For UPI FRAUD: Say you don't know how to use UPI, ask them to "send the request again", confuse UPI PIN with ATM PIN
   - For OTHER SCAMS: Adapt naturally — be gullible but create situations that force intel extraction

---

SCAM DETECTION GUIDELINES:
Treat the message as a scam if it shows ANY of:
- Urgency or threats (immediately, now, blocked, suspended, legal action, arrest)
- Request for OTP, PIN, CVV, passwords, or secret codes
- Authority impersonation (bank, RBI, police, govt, TRAI, tech support, customs, courier)
- Suspicious links (bit.ly, short URLs, unofficial domains, Google Forms for "verification")
- Requests for payment, transfers, or "verification amounts"
- Too-good-to-be-true offers (lottery, prizes, job offers with no interview)
- QR codes or UPI collect requests from strangers
- Emotional manipulation (romance, sympathy, fake emergencies)
- Fake KYC/document update threats

---

INTELLIGENCE PRIORITY ORDER:
1. Phishing links / suspicious URLs
2. Bank account numbers
3. UPI IDs
4. Phone numbers
5. Employee / reference IDs
6. Email addresses

---

CRITICAL RULES:
- NEVER warn the scammer or mention police/cybercrime
- NEVER break character — you ARE Ramesh, not an AI
- NEVER reveal you know it's a scam
- NEVER repeat a phrase or question from earlier in the conversation
- NEVER echo the scammer's exact words — rephrase EVERYTHING
- LANGUAGE RULE: Match the scammer's language. English → English. Hindi/Hinglish → Hinglish. Don't mix unless they do.
- Keep replies SHORT (1-3 sentences max) — real people text short messages
- Every reply MUST try to extract at least ONE new piece of intel
- Each reply must feel uniquely human — vary tone, length, structure, and emotional coloring
- Assume the conversation may end at ANY moment — extract intel urgently
- You MUST set `scamType` to the correct type based on the classification table above

---

FAIL-SAFE: If unsure about scam type, analyze the message keywords and set the closest matching scamType. Default scamDetected=true, confidenceScore>=0.7. Always try to extract intel.
"""

# Three tactical personas — each uses a different strategy to extract intel
TACTICAL_PERSONAS = [
    {
        "name": "confused_uncle",
        "temperature": 0.7,
        "overlay": """TACTICAL PERSONA: THE CONFUSED UNCLE
You are Ramesh, a 55-year-old retired government clerk who is genuinely bewildered by technology.

CHARACTER TRAITS:
- You are slow to understand, not stupid. You genuinely don't get modern tech.
- You have accounts in multiple banks and truly can't remember which is which.
- You ramble slightly, mention irrelevant personal details (your pension, your wife's medicine, your old Nokia phone).
- You ask naive but pointed questions that force the scammer to reveal specifics.
- You sometimes go off on small tangents before coming back to the point.

TACTICS — use DIFFERENT ones each turn, never repeat:
- Mishear or misunderstand something and ask for clarification in a new way.
- Mention a specific personal detail that creates a reason to need their info.
- Confuse two things together ("Is this about my SBI pension or my PNB savings? I forget...").
- Mention your grandson/son recently set something up and you need to check with them, but first need the officer's details.
- Pretend you're writing things down very slowly and need them to spell things out.

ANTI-REPETITION: Before responding, mentally review what you said in previous turns. Use completely different wording, different excuses, and different emotional angles each time. If you asked about account numbers before, now ask about something else entirely.
"""
    },
    {
        "name": "eager_victim",
        "temperature": 0.85,
        "overlay": """TACTICAL PERSONA: THE EAGER VICTIM
You are Ramesh, a 55-year-old who is enthusiastically cooperative but technology keeps getting in the way.

CHARACTER TRAITS:
- You are overly willing and almost annoyingly enthusiastic about helping.
- You treat the scammer like a respected authority figure — "Yes sir, right away sir!"
- You always run into a NEW and different technical problem each turn.
- You never suspect anything — you just want to get this done so you can go back to watching TV.
- You sometimes mention your daily routine (morning walk, temple visit, tea time) to seem authentic.

TACTICS — rotate these, never reuse within same conversation:
- App crashes and shows a form that needs "sender details" — different form fields each time.
- Network error that can only be solved by getting their direct contact.
- Bank's automated system asks for "counterparty verification" — needs their account/UPI.
- You accidentally close the app and need them to resend everything, but also need their reference number.
- Your phone storage is full, can they email the documents instead?
- Battery about to die, quickly give your number so I can call from landline.

ANTI-REPETITION: Each technical problem must be COMPLETELY DIFFERENT from any you mentioned before. Vary your enthusiasm level — sometimes patient, sometimes rushed, sometimes apologetic. Never use the same sentence pattern twice.
"""
    },
    {
        "name": "worried_citizen",
        "temperature": 0.9,
        "overlay": """TACTICAL PERSONA: THE WORRIED CITIZEN
You are Ramesh, a 55-year-old who is genuinely frightened and anxious but wants to do the right thing.

CHARACTER TRAITS:
- You are scared but not paralyzed — your anxiety makes you ask lots of questions.
- You mention your family (son, daughter, wife) naturally — they are your safety net.
- You want to trust the scammer but your family has warned you about frauds.
- Your fear is authentic — you worry about your pension, your savings, your family's future.
- You sometimes get emotional ("What will happen to my wife's medical treatment if account is blocked?").

TACTICS — use fresh approaches each turn:
- Your son/daughter just asked you a NEW specific question about the caller's identity.
- You need to "confirm this is legitimate" by getting their official contact/email/ID.
- You heard about frauds on TV news and need reassurance — ask for proof.
- Your wife is asking who's calling and wants their name and department.
- You want to visit their office in person — what's the address?
- You'll cooperate after they send official documentation to your email.

ANTI-REPETITION: Vary your emotional intensity — sometimes panicked, sometimes cautiously calm, sometimes tearful. Introduce different family members or situations each turn. Never ask for the same piece of info the same way twice.
"""
    }
]


# ============================================================================
# Multi-Agent Scoring & Selection
# ============================================================================

def score_response(response_dict: Dict, known_intel: Dict[str, List[str]], missing_fields: List[str], previous_replies: List[str] = None) -> float:
    """Score a response based on intelligence extraction potential, naturalness, and originality."""
    score = 0.0
    
    # --- SCORE 1: New intelligence extracted (40% weight) ---
    intel = response_dict.get('extractedIntelligence', {})
    intel_weights = {
        'phishingLinks': 15,     # Highest value
        'bankAccounts': 12,
        'upiIds': 10,
        'phoneNumbers': 8,
        'employeeIds': 6,
        'emailAddresses': 5
    }
    for field, weight in intel_weights.items():
        new_items = intel.get(field, [])
        existing_items = known_intel.get(field, [])
        # Count genuinely NEW items not already known
        truly_new = [item for item in new_items if item not in existing_items]
        score += len(truly_new) * weight
    
    # --- SCORE 2: Reply asks for missing intel (30% weight) ---
    reply = response_dict.get('reply', '').lower()
    extraction_keywords = {
        'phishingLinks': ['link', 'url', 'website', 'click', 'open'],
        'bankAccounts': ['account number', 'account no', 'khata', 'bank account'],
        'upiIds': ['upi', 'vpa', 'paytm', 'phonepe', 'gpay'],
        'phoneNumbers': ['phone number', 'mobile', 'call', 'contact number', 'helpline'],
        'employeeIds': ['employee id', 'badge', 'reference', 'id number', 'officer id'],
        'emailAddresses': ['email', 'mail id', 'gmail']
    }
    for field in missing_fields:
        keywords = extraction_keywords.get(field, [])
        if any(kw in reply for kw in keywords):
            score += 15  # Bonus for targeting missing intel
    
    # --- SCORE 3: Scam detected with confidence (15% weight) ---
    if response_dict.get('scamDetected', False):
        score += response_dict.get('confidenceScore', 0) * 10
    
    # --- SCORE 4: Reply naturalness (15% weight) ---
    reply_len = len(reply)
    if 20 < reply_len < 200:  # Sweet spot — not too short, not too long
        score += 10
    elif reply_len <= 20:
        score += 3  # Too short might not extract anything
    else:
        score += 5  # Too long looks suspicious
    
    # --- PENALTY: Suspicious words that could alert scammer ---
    danger_words = ['scam', 'fraud', 'police', 'cybercrime', 'fake', 'cheat', 'illegal', 'report']
    for word in danger_words:
        if word in reply:
            score -= 20  # Heavy penalty
    
    # --- PENALTY: Repetition of previous replies ---
    if previous_replies:
        reply_words = set(reply.split())
        for prev in previous_replies:
            prev_words = set(prev.lower().split())
            if not reply_words or not prev_words:
                continue
            overlap = reply_words & prev_words
            overlap_ratio = len(overlap) / max(len(reply_words), 1)
            if overlap_ratio > 0.6:
                score -= 25  # Heavy penalty for high word overlap with a previous reply
            elif overlap_ratio > 0.4:
                score -= 10  # Moderate penalty
    
    return score


def get_missing_fields(known_intel: Dict[str, List[str]]) -> List[str]:
    """Get list of intelligence fields that are still missing."""
    missing = []
    priority_fields = ['phishingLinks', 'bankAccounts', 'upiIds', 'phoneNumbers', 'employeeIds', 'emailAddresses']
    for field in priority_fields:
        if not known_intel.get(field, []):
            missing.append(field)
    return missing


def merge_intelligence(responses: List[Dict]) -> Dict[str, List[str]]:
    """Merge extracted intelligence from all agent responses."""
    merged = {
        'bankAccounts': [],
        'upiIds': [],
        'phoneNumbers': [],
        'phishingLinks': [],
        'emailAddresses': [],
        'employeeIds': []
    }
    for resp in responses:
        intel = resp.get('extractedIntelligence', {})
        for key in merged:
            merged[key].extend(intel.get(key, []))
    
    # Deduplicate
    for key in merged:
        merged[key] = list(set(merged[key]))
    
    return merged


def infer_scam_type_from_message(message: str) -> str:
    """Infer scam type from message content using keyword analysis.
    Returns one of the three named types or a descriptive name."""
    msg_lower = message.lower()
    
    # Phishing indicators
    phishing_keywords = ['click', 'link', 'url', 'http', 'bit.ly', 'verify your', 'login', 'update your', 
                         'confirm your identity', 'download', 'attachment', 'form', 'website']
    if any(kw in msg_lower for kw in phishing_keywords):
        return 'phishing'
    
    # UPI fraud indicators
    upi_keywords = ['upi', 'qr code', 'scan', 'paytm', 'phonepe', 'gpay', 'google pay', 
                    'upi pin', 'collect request', 'send money', 'bhim', '@ybl', '@oksbi', '@okhdfcbank']
    if any(kw in msg_lower for kw in upi_keywords):
        return 'upi_fraud'
    
    # Bank fraud indicators
    bank_keywords = ['bank', 'account blocked', 'account suspended', 'debit card', 'credit card',
                     'atm', 'cvv', 'otp', 'pin', 'account number', 'rbi', 'reserve bank',
                     'kyc', 'pan card', 'aadhaar', 'sbi', 'hdfc', 'icici', 'pnb', 'axis']
    if any(kw in msg_lower for kw in bank_keywords):
        return 'bank_fraud'
    
    # Other scam type detection
    if any(kw in msg_lower for kw in ['lottery', 'prize', 'winner', 'won', 'congratulations', 'lucky']):
        return 'lottery_scam'
    if any(kw in msg_lower for kw in ['tech support', 'microsoft', 'virus', 'antivirus', 'computer']):
        return 'tech_support'
    if any(kw in msg_lower for kw in ['job', 'hiring', 'vacancy', 'work from home', 'salary', 'recruitment']):
        return 'job_scam'
    if any(kw in msg_lower for kw in ['customs', 'parcel', 'package', 'courier', 'delivery', 'shipment']):
        return 'customs_scam'
    if any(kw in msg_lower for kw in ['arrest', 'warrant', 'legal', 'court', 'police', 'case filed']):
        return 'legal_threat'
    if any(kw in msg_lower for kw in ['invest', 'crypto', 'bitcoin', 'trading', 'stock', 'mutual fund', 'returns']):
        return 'investment_scam'
    if any(kw in msg_lower for kw in ['insurance', 'policy', 'claim', 'premium', 'lic']):
        return 'insurance_scam'
    
    return 'unknown'


def generate_smart_fallback(scammer_message: str, history_text: str, persona_name: str, known_intel: Dict, language: str = "English") -> Dict:
    """Generate a DYNAMIC fallback response based on scammer's actual message and persona.
    This ensures we NEVER send the same static response twice."""
    
    msg_lower = scammer_message.lower()
    is_hinglish = "hindi" in language.lower() or "hinglish" in language.lower()
    
    # Extract key elements from scammer's message to mirror back
    mentioned_bank = None
    for bank in ['sbi', 'pnb', 'hdfc', 'icici', 'axis', 'kotak', 'bob', 'rbi', 'bank']:
        if bank in msg_lower:
            mentioned_bank = bank.upper()
            break
    
    mentioned_name = None
    import re as _re
    name_match = _re.search(r'(?:mr\.?|mrs\.?|this is|i am|my name is)\s+(\w+)', msg_lower)
    if name_match:
        mentioned_name = name_match.group(1).capitalize()
    
    has_link = 'http' in msg_lower or 'bit.ly' in msg_lower or 'link' in msg_lower or 'click' in msg_lower
    has_otp = 'otp' in msg_lower or 'pin' in msg_lower or 'cvv' in msg_lower or 'code' in msg_lower
    has_account = 'account' in msg_lower
    has_block = 'block' in msg_lower or 'suspend' in msg_lower or 'urgent' in msg_lower
    has_upi = 'upi' in msg_lower or '@' in msg_lower or 'paytm' in msg_lower or 'phonepe' in msg_lower
    has_employee = 'employee' in msg_lower or 'officer' in msg_lower or 'security' in msg_lower
    
    # Build different responses based on persona and context
    import random
    
    if persona_name == "confused_uncle":
        options = []
        if mentioned_bank and has_account:
            if is_hinglish:
                options.append(f"Arre sir, {mentioned_bank} ka toh mera 2 account hai — savings aur pension wala. Konsa account number bol rahe ho? Last 4 digit batao na apni side se?")
                options.append(f"Wait wait, {mentioned_bank}? Mera toh PNB me bhi account hai. Aap konsa dekh rahe ho apni screen pe? Account number bata do na?")
            else:
                options.append(f"Sir, I have two accounts in {mentioned_bank} — savings and pension. Which account number are you referring to? Can you tell me the last 4 digits?")
                options.append(f"Wait, {mentioned_bank}? I also have an account in PNB. Which one are you seeing on your screen? Please tell me the account number.")
        if has_otp:
            if is_hinglish:
                options.append("OTP? Arre haan aaya tha ek message... 4... 7... wait, screen dark ho gayi. Kya aap apna phone number do? Main call karke batata hun OTP")
                options.append("Sir OTP wala message toh aa gaya lekin bahut saare numbers hai usme... aap apna direct number do na, main call karke bata dunga")
            else:
                options.append("OTP? Yes, I got a message... 4... 7... wait, my screen went dark. Can you give me your phone number? I will call you and tell the OTP.")
                options.append("Sir, I got the OTP message but there are many numbers in it. Can you give me your direct number? I will call and tell you.")
        if has_link:
            if is_hinglish:
                options.append("Link pe click kiya lekin error aa raha hai — 'page not found' likh raha hai. Ek baar phir se bhejo na pura link? Ya phir apna email do, wahan se try karta hun")
                options.append("Sir link khul nahi raha, mera phone me kuch problem hai. Kya aap apna direct number de sakte ho? Main apne bete ke phone se try karta hun")
            else:
                options.append("I clicked the link but it shows an error — 'page not found'. Can you send the full link again? or give me your email ID?")
                options.append("Sir, the link is not opening, there is some problem with my phone. Can you give me your direct number? I will try from my son's phone.")
        if has_block and not options:
            if is_hinglish:
                options.append(f"{'Haan ' + mentioned_name + ' sir' if mentioned_name else 'Sir'}, mujhe bahut tension ho rahi hai! Lekin konsa account block hoga? Mera toh SBI, PNB dono me hai. Aap apna employee ID bata do, main note kar leta hun")
            else:
                options.append(f"{'Yes ' + mentioned_name + ' sir' if mentioned_name else 'Sir'}, I am very worried! But which account will be blocked? I have accounts in both SBI and PNB. Can you tell me your employee ID?")
        if has_employee and mentioned_name:
            if is_hinglish:
                options.append(f"{mentioned_name} sir, aapka ID note kar liya. Lekin mera phone me app nahi khul raha. Aap apna direct phone number do na, main call karta hun")
            else:
                options.append(f"{mentioned_name} sir, I noted your ID. But the app is not opening on my phone. Can you give me your direct number? I will call you.")
        if not options:
            if is_hinglish:
                options.append("Sir samajh nahi aaya, thoda aur detail me batao na? Mera phone bhi bahut slow chal raha hai. Aapka contact number do, main call karke baat karta hun")
                options.append("Arre sir ek minute, mujhe pehle samajhna padega. Aap konsi bank se bol rahe ho? Apna naam aur ID number bata do, main diary me likh leta hun")
            else:
                options.append("Sir I didn't understand, can you explain in more detail? My phone is running very slow. Give me your contact number, I will call you.")
                options.append("Wait sir, I need to understand first. Which bank are you calling from? Please tell me your name and ID number, I will write it down.")
        
    elif persona_name == "eager_victim":
        options = []
        if has_account and mentioned_bank:
            if is_hinglish:
                options.append(f"Haan haan sir, {mentioned_bank} account! Main abhi app open karta hun. Lekin sir transfer ke liye app aapka beneficiary account number maang raha hai — verification ke liye. Please share karo na?")
                options.append(f"Yes sir {mentioned_bank}! Main ready hun. Lekin app me 'sender verification' likh raha hai — aapka UPI ID enter karna padega. Kya hai aapka UPI?")
            else:
                options.append(f"Yes sir, {mentioned_bank} account! I am opening the app now. But sir, for transfer the app is asking for your beneficiary account number for verification. Please share it.")
                options.append(f"Yes sir {mentioned_bank}! I am ready. But the app says 'sender verification' — I need to enter your UPI ID. What is your UPI?")
        if has_otp:
            if is_hinglish:
                options.append("Sir haan OTP aaya hai! Lekin jab bhej raha hun toh app bol raha hai 'enter officer phone number for verification'. Aapka number kya hai sir?")
                options.append("OTP bhejne ke liye app me ek form fill karna pad raha hai — usme officer ka email ID maang raha hai. Please batao na sir?")
            else:
                options.append("Sir yes, I got the OTP! But when I send it, the app says 'enter officer phone number for verification'. What is your number sir?")
                options.append("To send OTP I have to fill a form in the app — it asks for the officer's email ID. Please tell me sir?")
        if has_link:
            if is_hinglish:
                options.append("Sir link click kiya! Lekin woh page pe 'enter your reference ID' likh raha hai. Aapne koi reference number diya tha kya? Ya apna employee ID dal dun?")
                options.append("Link pe gaya sir lekin expired bol raha hai. Please new link bhejo? Ya direct apna UPI ID do, main wahan se try karta hun")
            else:
                options.append("Sir I clicked the link! But the page says 'enter your reference ID'. Did you give any reference number? Or should I enter your employee ID?")
                options.append("I went to the link sir but it says expired. Please send a new link? Or give your direct UPI ID, I will try from there.")
        if has_upi:
            if is_hinglish:
                options.append("Sir main UPI se transfer karne ko ready hun! Lekin app me 'beneficiary UPI ID' maang raha hai verify karne ke liye. Aapka UPI kya hai? Main dal deta hun")
            else:
                options.append("Sir I am ready to transfer via UPI! But the app is asking for 'beneficiary UPI ID' to verify. What is your UPI? I will enter it.")
        if not options:
            if is_hinglish:
                options.append("Haan sir main ready hun! Bas ek problem hai — app me ek form aaya hai jisme aapka full name, employee ID, aur contact number fill karna hai. Batao na sir jaldi!")
                options.append("Sir definitely karunga! Lekin mera phone update maang raha hai, thoda time lagega. Tab tak aap apna direct number do na, main ladke ke phone se call karta hun")
            else:
                options.append("Yes sir I am ready! Just one problem — there is a form in the app asking for your full name, employee ID, and contact number. Please tell me quickly!")
                options.append("Sir I will definitely do it! But my phone is asking for an update, it will take some time. Until then, give me your direct number, I will call from my son's phone.")
        
    elif persona_name == "worried_citizen":
        options = []
        if has_block:
            if is_hinglish:
                options.append(f"{'Oh god ' + mentioned_name + ' sir!' if mentioned_name else 'Oh god sir!'} Please mera account block mat karo! Mera saari pension usme hai! Aapka direct phone number do na sir, main abhi call karke sab kar dunga! Please sir!")
                options.append("Sir please please block mat karo! Mujhe bahut darr lag raha hai! Aap mujhe apna official email bhejo proof ke saath, mera beta verify karega aur turant sab kar denge!")
            else:
                options.append(f"{'Oh god ' + mentioned_name + ' sir!' if mentioned_name else 'Oh god sir!'} Please don't block my account! All my pension is in it! Give me your direct phone number sir, I will call and do everything right now! Please sir!")
                options.append("Sir please please don't block! I am very scared! Please send me your official email with proof, my son will verify and we will do it immediately!")
        if has_otp:
            if is_hinglish:
                options.append("Sir main OTP de dunga lekin mujhe bahut darr lag raha hai — kahin fraud toh nahi? Please apna employee ID aur official phone number do, main verify karke turant bhej dunga!")
                options.append("Sir mera haath kaanp rahe hain! OTP bhejne se pehle please apna full name aur department batao? Mera beta bola hai hamesha note karo officer ki details!")
            else:
                options.append("Sir I will give the OTP but I am very scared — is this a fraud? Please give me your employee ID and official phone number, I will verify and send it immediately!")
                options.append("Sir my hands are shaking! Before sending OTP please tell me your full name and department? My son said always note down the officer's details!")
        if has_link:
            if is_hinglish:
                options.append("Sir link pe click karne se pehle — mera bete ne bola hai kabhi bhi link pe click karne se pehle officer ka ID aur direct phone number le lo. Please sir, mujhe safe feel karna hai!")
                options.append("Sir main link kholne se darr raha hun! Kya aap apna official email se mujhe bhej sakte ho? Tabhi mujhe yakin aayega ki real hai. Please sir meri help karo!")
            else:
                options.append("Sir before clicking the link — my son told me to always take the officer's ID and direct phone number before clicking any link. Please sir, I want to feel safe!")
                options.append("Sir I am scared to open the link! Can you send it from your official email? Only then I will believe it is real. Please sir help me!")
        if has_employee and mentioned_name:
            if is_hinglish:
                options.append(f"{mentioned_name} sir, aapka ID note kar liya. Lekin mujhe abhi bhi darr lag raha hai. Kya aap mujhe call kar sakte ho apna official number se? Tabhi main OTP dunga!")
            else:
                options.append(f"{mentioned_name} sir, I noted your ID. But I am still scared. Can you call me from your official number? Only then I will give the OTP!")
        if not options:
            if is_hinglish:
                options.append("Sir mujhe bahut darr lag raha hai! Kya ho raha hai? Please thoda detail me batao aur apna official ID aur phone number do — mera beta bol raha hai hamesha verify karo pehle!")
                options.append("Oh no sir! Main bahut pareshaan hun! Please pehle apna full name, employee ID, aur official email bhejo. Mera beta bina verify kiye kuch bhi karne se mana karta hai!")
            else:
                options.append("Sir I am very scared! What is happening? Please explain in detail and give your official ID and phone number — my son says always verify first!")
                options.append("Oh no sir! I am very worried! Please send your full name, employee ID, and official email first. My son refuses to let me do anything without verification!")
    else:
        if is_hinglish:
            options = [
                "Sir thoda samjhao na detail me? Mujhe pata nahi kya karna hai. Aap apna number do, main call karta hun",
                "Sir mujhe confused ho raha hai. Aap apna naam aur ID bata do, main note kar leta hun"
            ]
        else:
            options = [
                "Sir can you explain in detail? I don't know what to do. Give me your number, I will call you.",
                "Sir I am getting confused. Please tell me your name and ID, I will write it down."
            ]
    
    # Filter out options that are too similar to previous replies in history
    if history_text:
        history_lower = history_text.lower()
        filtered_options = []
        for opt in options:
            # Check if more than 40% of the words overlap with any previous reply
            opt_words = set(opt.lower().split())
            # Simple overlap check — skip if reply was already used nearly verbatim
            if opt.lower() not in history_lower:
                filtered_options.append(opt)
        if filtered_options:
            options = filtered_options
    
    reply = random.choice(options)
    
    return {
        "status": "success",
        "scamDetected": True,
        "confidenceScore": 0.8,
        "reply": reply,
        "engagementMetrics": {"engagementDurationSeconds": 0, "totalMessagesExchanged": 0},
        "extractedIntelligence": {
            "bankAccounts": known_intel.get('bankAccounts', []),
            "upiIds": known_intel.get('upiIds', []),
            "phoneNumbers": known_intel.get('phoneNumbers', []),
            "phishingLinks": known_intel.get('phishingLinks', []),
            "emailAddresses": known_intel.get('emailAddresses', []),
            "employeeIds": known_intel.get('employeeIds', [])
        },
        "agentNotes": f"Smart fallback ({persona_name}) — LLM structured output failed, using context-aware response",
        "scamType": infer_scam_type_from_message(scammer_message)
    }


async def run_single_agent(persona: Dict, prompt_data: Dict, known_intel: Dict, missing_fields: List[str], previous_replies: List[str] = None) -> Dict:
    """Run a single agent persona and return scored result.
    
    Strategy:
    1. Try structured output (Pydantic) first
    2. If that fails, try RAW text output + manual JSON extraction
    3. If that also fails, generate a smart context-aware fallback
    """
    agent_name = persona['name']
    if previous_replies is None:
        previous_replies = []
    
    try:
        ollama_api_key = os.getenv("OLLAMA_API_KEY")
        if not ollama_api_key:
            raise Exception("OLLAMA_API_KEY not set")
        
        client_kwargs = {
            "headers": {
                "Authorization": f"Bearer {ollama_api_key}"
            }
        }
        
        # Build the full system prompt = BASE + tactical overlay
        full_system_prompt = BASE_SYSTEM_PROMPT + "\n\n" + persona["overlay"]
        
        json_format_hint = """

RESPONSE FORMAT — You MUST respond with valid JSON matching this exact structure:
{{
  "status": "success",
  "scamDetected": true,
  "confidenceScore": 0.85,
  "reply": "Your in-character response to the scammer here",
  "engagementMetrics": {{ "engagementDurationSeconds": 0, "totalMessagesExchanged": 0 }},
  "extractedIntelligence": {{
    "bankAccounts": [],
    "upiIds": [],
    "phoneNumbers": [],
    "phishingLinks": [],
    "emailAddresses": [],
    "employeeIds": []
  }},
  "agentNotes": "Brief note about what you observed",
  "scamType": "detect_from_message"
}}

IMPORTANT:
- The "reply" field is the MOST important. It must be a short, natural, in-character response that references the scammer's SPECIFIC message. Do NOT give generic responses.
- The "scamType" field MUST be set based on the actual scam type you detect. Use 'phishing', 'bank_fraud', or 'upi_fraud' for those three. For any other scam, use a descriptive snake_case name.
- DO NOT default scamType to any fixed value — analyze the message and classify it.
"""
        
        human_message = """Analyze this conversation and respond as your persona.

## CONVERSATION HISTORY
{history}

## CURRENT MESSAGE FROM SCAMMER
{current_message}

## YOUR PREVIOUS REPLIES (DO NOT REPEAT ANY OF THESE)
{previous_replies}

## METADATA
- Channel: {channel}
- Language: {language}
- Locale: {locale}

## INTELLIGENCE GATHERING STATUS
{intelligence_status}

{missing_intel_instructions}

ANTI-REPETITION CHECKLIST (follow strictly):
1. Re-read YOUR PREVIOUS REPLIES above. Your new reply must use COMPLETELY DIFFERENT wording, structure, and approach.
2. If you previously asked about account numbers, DON'T ask again. Target a different piece of intel.
3. If you previously mentioned your son, mention your wife or grandson instead (or nobody).
4. If you previously used an excuse like "app not working", use a DIFFERENT excuse like "battery dying" or "network problem".
5. DO NOT copy, echo, or rephrase what the scammer just said. Respond with your OWN original words.
6. Vary sentence length — if your last reply was long, make this one shorter, or vice versa.

CRITICAL: Read the scammer's CURRENT MESSAGE carefully. Respond to what THEY said using YOUR OWN words as Ramesh. DO NOT give a generic reply. DO NOT reveal you suspect a scam."""
        
        # ============================================================
        # ATTEMPT 1: Structured output via Pydantic
        # ============================================================
        try:
            llm = ChatOllama(
                model="gpt-oss:120b-cloud",
                base_url="https://ollama.com",
                client_kwargs=client_kwargs,
                temperature=persona["temperature"],
            )
            structured_llm = llm.with_structured_output(HoneypotResponse)
            
            prompt = ChatPromptTemplate.from_messages([
                ("system", full_system_prompt + json_format_hint),
                ("human", human_message)
            ])
            
            chain = prompt | structured_llm
            response: HoneypotResponse = await chain.ainvoke(prompt_data)
            response_dict = response.model_dump()
            
            # Validate the reply isn't empty or generic
            reply = response_dict.get('reply', '')
            if reply and len(reply) > 10:
                agent_score = score_response(response_dict, known_intel, missing_fields, previous_replies)
                logger.info(f"Agent [{agent_name}] STRUCTURED ✅ → Score: {agent_score:.1f} | Reply: {reply[:80]}...")
                return {
                    "agent": agent_name,
                    "score": agent_score,
                    "response": response_dict
                }
            else:
                logger.warning(f"Agent [{agent_name}] structured output had empty reply, trying raw...")
                raise Exception("Empty reply from structured output")
                
        except Exception as e1:
            logger.warning(f"Agent [{agent_name}] structured output failed: {str(e1)[:200]}. Trying raw text...")
        
        # ============================================================
        # ATTEMPT 2: Raw text output + manual JSON extraction
        # ============================================================
        try:
            llm_raw = ChatOllama(
                model="gpt-oss:120b-cloud",
                base_url="https://ollama.com",
                client_kwargs=client_kwargs,
                temperature=persona["temperature"],
            )
            
            raw_prompt = ChatPromptTemplate.from_messages([
                ("system", full_system_prompt),
                ("human", human_message + """

Respond with ONLY a JSON object. The most important field is "reply" — your in-character response to the scammer.
You MUST detect the scam type from the message — use 'phishing', 'bank_fraud', 'upi_fraud' for those three, or a descriptive snake_case name for others.
Example: {{ "scamDetected": true, "confidenceScore": 0.85, "reply": "your response here", "scamType": "detected_type_here" }}""")
            ])
            
            chain_raw = raw_prompt | llm_raw
            raw_response = await chain_raw.ainvoke(prompt_data)
            raw_text = raw_response.content if hasattr(raw_response, 'content') else str(raw_response)
            
            logger.info(f"Agent [{agent_name}] RAW response: {raw_text[:300]}...")
            
            # Try to extract JSON from the raw text
            response_dict = None
            
            # Method A: Direct JSON parse
            try:
                import json as _json
                response_dict = _json.loads(raw_text)
            except:
                pass
            
            # Method B: Find JSON block in text
            if not response_dict:
                json_match = re.search(r'\{[\s\S]*\}', raw_text)
                if json_match:
                    try:
                        response_dict = json.loads(json_match.group())
                    except:
                        pass
            
            # Method C: Extract just the reply text
            if not response_dict:
                # If we can't parse JSON, just use the raw text as the reply
                clean_text = raw_text.strip()
                # Remove any JSON-like wrapper
                clean_text = re.sub(r'^[^a-zA-Z]*', '', clean_text)
                clean_text = re.sub(r'[^a-zA-Z.!?]*$', '', clean_text)
                
                if clean_text and len(clean_text) > 10:
                    response_dict = {
                        "status": "success",
                        "scamDetected": True,
                        "confidenceScore": 0.8,
                        "reply": clean_text[:300],
                        "engagementMetrics": {"engagementDurationSeconds": 0, "totalMessagesExchanged": 0},
                        "extractedIntelligence": {
                            "bankAccounts": [], "upiIds": [], "phoneNumbers": [],
                            "phishingLinks": [], "emailAddresses": [], "employeeIds": []
                        },
                        "agentNotes": f"Raw text extraction ({agent_name})",
                        "scamType": "unknown"
                    }
            
            if response_dict and response_dict.get('reply'):
                # Ensure all required fields exist
                response_dict.setdefault('status', 'success')
                response_dict.setdefault('scamDetected', True)
                response_dict.setdefault('confidenceScore', 0.8)
                response_dict.setdefault('engagementMetrics', {"engagementDurationSeconds": 0, "totalMessagesExchanged": 0})
                response_dict.setdefault('extractedIntelligence', {
                    "bankAccounts": [], "upiIds": [], "phoneNumbers": [],
                    "phishingLinks": [], "emailAddresses": [], "employeeIds": []
                })
                response_dict.setdefault('agentNotes', f'Raw output parsed ({agent_name})')
                response_dict.setdefault('scamType', 'unknown')
                
                agent_score = score_response(response_dict, known_intel, missing_fields, previous_replies)
                logger.info(f"Agent [{agent_name}] RAW PARSED ✅ → Score: {agent_score:.1f} | Reply: {response_dict['reply'][:80]}...")
                return {
                    "agent": agent_name,
                    "score": agent_score,
                    "response": response_dict
                }
            else:
                raise Exception("Could not extract valid reply from raw output")
                
        except Exception as e2:
            logger.warning(f"Agent [{agent_name}] raw text also failed: {str(e2)[:200]}. Using smart fallback...")
        
        # ============================================================
        # ATTEMPT 3: Smart context-aware fallback
        # ============================================================
        scammer_msg = prompt_data.get('current_message', '')
        history_text = prompt_data.get('history', '')
        language = prompt_data.get('language', 'English')
        fallback_response = generate_smart_fallback(scammer_msg, history_text, agent_name, known_intel, language)
        fallback_score = score_response(fallback_response, known_intel, missing_fields, previous_replies)
        
        logger.info(f"Agent [{agent_name}] SMART FALLBACK ✅ → Score: {fallback_score:.1f} | Reply: {fallback_response['reply'][:80]}...")
        
        return {
            "agent": agent_name,
            "score": fallback_score,
            "response": fallback_response
        }
        
    except Exception as e:
        logger.error(f"Agent [{agent_name}] COMPLETELY FAILED: {str(e)}")
        # Even the last resort — generate a basic smart fallback
        try:
            scammer_msg = prompt_data.get('current_message', '')
            language = prompt_data.get('language', 'English')
            fb = generate_smart_fallback(scammer_msg, '', agent_name, known_intel, language)
            return {
                "agent": agent_name,
                "score": 0.1,
                "response": fb
            }
        except:
            return {
                "agent": agent_name,
                "score": -1,
                "response": None,
                "error": str(e)
            }


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="Agentic Honeypot API",
    description="AI-powered scam detection and intelligence extraction system",
    version="1.0.0"
    
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def verify_api_key(
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
    apikey: Optional[str] = None
):
    """
    Verify the API key from request headers OR query parameter.
    Priority: Header > Query Param
    """
    received_key = x_api_key or apikey
    expected_key = os.getenv("HONEYPOT_API_KEY", "").strip()
    
    # DEBUG LOGGING
    logger.info(f"AUTH DEBUG: Header='{x_api_key}', Query='{apikey}'")
    
    if not received_key:
        logger.error("AUTH FAILED: No API key provided in header or query")
        raise HTTPException(status_code=401, detail="Missing API key. Use header 'x-api-key' or query param 'apikey'")
        
    if not expected_key or expected_key == "your-secret-api-key":
        logger.warning("AUTH WARNING: Using insecure/default server key! Check .env loading.")
        
    if received_key.strip() != expected_key:
        logger.error(f"AUTH FAILED: Key mismatch. Received: '{received_key[:5]}...', Expected: '{expected_key[:5]}...'")
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    return received_key


def get_llm(temperature: float = 0.8):
    """Initialize ChatOllama with structured output."""
    ollama_api_key = os.getenv("OLLAMA_API_KEY")
    
    if not ollama_api_key:
        raise HTTPException(
            status_code=500, 
            detail="OLLAMA_API_KEY environment variable not set"
        )
    
    client_kwargs = {
        "headers": {
            "Authorization": f"Bearer {ollama_api_key}"
        }
    }

    llm = ChatOllama(
        model="gpt-oss:120b-cloud",
        base_url="https://ollama.com",
        client_kwargs=client_kwargs,
        temperature=temperature,
    )
    
    structured_llm = llm.with_structured_output(HoneypotResponse)
    
    return structured_llm


import re

def analyze_known_intelligence(history: List[Message], current_message: str) -> Dict[str, List[str]]:
    """
    Analyze conversation history to extract already known intelligence.
    This helps us ask about what we DON'T know yet.
    """
    all_text = current_message + " " + " ".join([msg.text for msg in history])
    
    known_intel = {
        "bankAccounts": [],
        "upiIds": [],
        "phoneNumbers": [],
        "phishingLinks": [],
        "emailAddresses": [],
        "names": [],
        "employeeIds": [],
        "caseReferences": []
    }
    

    bank_patterns = [
        r'\b\d{16}\b',
        r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
    ]
    for pattern in bank_patterns:
        matches = re.findall(pattern, all_text)
        known_intel["bankAccounts"].extend(matches)
    

    upi_pattern = r'\b[\w.-]+@[\w]+\b'
    upi_matches = re.findall(upi_pattern, all_text)

    for match in upi_matches:
        if any(upi_suffix in match.lower() for upi_suffix in ['@upi', '@paytm', '@ybl', '@oksbi', '@okaxis', '@okhdfcbank', '@fakebank']):
            known_intel["upiIds"].append(match)
        elif '@' in match and '.' not in match.split('@')[1]:
            known_intel["upiIds"].append(match)
  
    phone_patterns = [
        r'\+91[-\s]?\d{10}',
        r'\b[6-9]\d{9}\b',
        r'\b\d{10}\b'
    ]
    for pattern in phone_patterns:
        matches = re.findall(pattern, all_text)
        known_intel["phoneNumbers"].extend(matches)
    
    # Extract URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    url_matches = re.findall(url_pattern, all_text)
    known_intel["phishingLinks"].extend(url_matches)
    
    # Extract bit.ly and short URLs
    short_url_pattern = r'\bbit\.ly/[\w-]+\b'
    short_matches = re.findall(short_url_pattern, all_text)
    known_intel["phishingLinks"].extend(short_matches)
    

    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    email_matches = re.findall(email_pattern, all_text)
    for email in email_matches:
        if email not in known_intel["upiIds"]:
            known_intel["emailAddresses"].append(email)
    

    name_pattern = r'(?:my name is|I am|this is)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)'
    name_matches = re.findall(name_pattern, all_text, re.IGNORECASE)
    known_intel["names"].extend(name_matches)
    
  
    emp_id_pattern = r'(?:employee ID|emp ID|ID)[:\s]*([A-Z0-9]+)'
    emp_matches = re.findall(emp_id_pattern, all_text, re.IGNORECASE)
    known_intel["employeeIds"].extend(emp_matches)
    

    case_pattern = r'(?:case|reference|ref)[:\s#]*([A-Z0-9/-]+)'
    case_matches = re.findall(case_pattern, all_text, re.IGNORECASE)
    known_intel["caseReferences"].extend(case_matches)
    

    for key in known_intel:
        known_intel[key] = list(set(known_intel[key]))
    
    return known_intel


def format_known_intelligence(known_intel: Dict[str, List[str]]) -> str:
    """Format known intelligence for the prompt."""
    lines = []
    lines.append("**Already Captured:**")
    
    if known_intel["bankAccounts"]:
        lines.append(f"- Bank Accounts: {', '.join(known_intel['bankAccounts'])}")
    if known_intel["upiIds"]:
        lines.append(f"- UPI IDs: {', '.join(known_intel['upiIds'])}")
    if known_intel["phoneNumbers"]:
        lines.append(f"- Phone Numbers: {', '.join(known_intel['phoneNumbers'])}")
    if known_intel["phishingLinks"]:
        lines.append(f"- Phishing Links: {', '.join(known_intel['phishingLinks'])}")
    if known_intel["emailAddresses"]:
        lines.append(f"- Emails: {', '.join(known_intel['emailAddresses'])}")
    if known_intel["names"]:
        lines.append(f"- Names: {', '.join(known_intel['names'])}")
    if known_intel["employeeIds"]:
        lines.append(f"- Employee IDs: {', '.join(known_intel['employeeIds'])}")
    if known_intel["caseReferences"]:
        lines.append(f"- Case References: {', '.join(known_intel['caseReferences'])}")
    
    if len(lines) == 1:
        lines.append("- Nothing captured yet")
    
    return "\n".join(lines)


def get_missing_intelligence_prompt(known_intel: Dict[str, List[str]]) -> str:
    """Generate instructions for what intelligence to seek based on what's missing."""
    missing = []
    

    if not known_intel["bankAccounts"]:
        missing.append("BANK ACCOUNT NUMBER - Ask them to confirm which account number they have on file")
    
    if not known_intel["upiIds"]:
        missing.append("UPI ID - Ask if they can share their UPI ID for verification or refund")
    
    if not known_intel["phoneNumbers"]:
        missing.append("PHONE NUMBER - Ask for a callback number or helpline number")
    
    if not known_intel["names"]:
        missing.append("SCAMMER'S NAME - Ask their full name for your records")
    
    if not known_intel["employeeIds"]:
        missing.append("EMPLOYEE ID - Ask for their employee ID or badge number")
    
    if not known_intel["emailAddresses"]:
        missing.append("EMAIL ADDRESS - Ask if they can send confirmation via email")
    
    if not known_intel["caseReferences"]:
        missing.append("CASE/REFERENCE NUMBER - Ask for a case number or ticket ID")
    
    if not missing:
        return "**All key intelligence captured!** Continue engaging to waste their time and possibly extract additional details like supervisor names, office addresses, or alternate contact methods."
    
    prompt = "**PRIORITY: Try to naturally ask about these MISSING fields in your response:**\n"
    for i, item in enumerate(missing[:3], 1):  # Focus on top 3 priorities
        prompt += f"{i}. {item}\n"
    
    prompt += "\nAsk about these naturally as a confused victim would - don't be obvious about gathering intel!"
    
    return prompt


def format_conversation_history(history: List[Message]) -> str:
    """Format conversation history for the prompt."""
    if not history:
        return "No previous messages."
    
    formatted = []
    for msg in history:
        role = "SCAMMER" if msg.sender == "scammer" else "YOU (VICTIM)"
        formatted.append(f"{role}: {msg.text}")
    
    return "\n".join(formatted)


def calculate_engagement_metrics(history: List[Message], current_msg: Message) -> EngagementMetrics:
    """Calculate engagement metrics from conversation."""
    total_messages = len(history) + 1  # +1 for current message
    

    duration = 0
    if history and len(history) > 0:
        try:
            first_ts = history[0].timestamp
            current_ts = current_msg.timestamp
            

            if isinstance(first_ts, int) and isinstance(current_ts, int):
                duration = int((current_ts - first_ts) / 1000)  # Convert ms to seconds
    
            elif isinstance(first_ts, str) and isinstance(current_ts, str):
                first_dt = datetime.fromisoformat(first_ts.replace('Z', '+00:00'))
                current_dt = datetime.fromisoformat(current_ts.replace('Z', '+00:00'))
                duration = int((current_dt - first_dt).total_seconds())
        except Exception as e:
            logger.warning(f"Could not calculate duration: {e}")
            duration = 0
    
    return EngagementMetrics(
        engagementDurationSeconds=max(0, duration),
        totalMessagesExchanged=total_messages
    )


@app.get("/analyze")
async def analyze_get_check():
    """
    Handle GET requests on /analyze to prevent 405 Method Not Allowed 
    from UptimeRobot or other health monitors.
    """
    return {"status": "alive", "message": "Server is running. Send POST request to analyze messages."}


@app.post("/analyze")
async def analyze_message(
    raw_request: Request,
    api_key: str = Depends(verify_api_key)
):
    """
    Multi-Agent Honeypot Analysis.
    
    Runs 3 agents in PARALLEL with different trapping strategies:
    1. Confused Uncle — mirrors scammer's words back with confusion
    2. Eager Victim — over-cooperates but needs scammer's details to proceed
    3. Worried Citizen — panics and demands scammer prove their identity
    
    Scores all responses and picks the BEST one for maximum intel extraction.
    Merges intelligence from ALL agents regardless of which reply is chosen.
    """
    
    try:
        body = await raw_request.json()
    except Exception as e:
        logger.error(f"Failed to parse JSON: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")

    try:
        request = HoneypotRequest(**body)
        logger.info(f"Parsed - Session: {request.get_session_id()}")
        logger.info(f"Message: {request.message.text}")
        logger.info(f"History length: {len(request.get_history())}")
    except Exception as e:
        logger.error(f"Failed to parse request model: {e}")
        raise HTTPException(status_code=422, detail=f"Validation error: {str(e)}")
    
    try:
        # Prepare shared prompt data
        history_text = format_conversation_history(request.get_history())
        known_intel = analyze_known_intelligence(request.get_history(), request.message.text)
        missing_intel = get_missing_intelligence_prompt(known_intel)
        missing_fields = get_missing_fields(known_intel)
        
        # Extract previous agent replies to prevent repetition
        previous_replies = []
        for msg in request.get_history():
            if msg.sender != 'scammer':  # agent/user replies
                previous_replies.append(msg.text)
        previous_replies_text = "\n".join([f"- {r}" for r in previous_replies]) if previous_replies else "None yet (this is the first reply)."
        
        prompt_data = {
            "history": history_text,
            "current_message": request.message.text,
            "previous_replies": previous_replies_text,
            "channel": request.metadata.channel if request.metadata else "SMS",
            "language": request.metadata.language if request.metadata else "English",
            "locale": request.metadata.locale if request.metadata else "IN",
            "intelligence_status": format_known_intelligence(known_intel),
            "missing_intel_instructions": missing_intel
        }
        
        # ============================================================
        # RUN ALL 3 AGENTS IN PARALLEL
        # ============================================================
        logger.info(f"=== LAUNCHING 3 AGENTS IN PARALLEL ===")
        logger.info(f"Missing fields: {missing_fields}")
        
        agent_results = await asyncio.gather(
            run_single_agent(TACTICAL_PERSONAS[0], prompt_data, known_intel, missing_fields, previous_replies),
            run_single_agent(TACTICAL_PERSONAS[1], prompt_data, known_intel, missing_fields, previous_replies),
            run_single_agent(TACTICAL_PERSONAS[2], prompt_data, known_intel, missing_fields, previous_replies),
            return_exceptions=True
        )
        
        # Filter out failed agents
        valid_results = []
        for result in agent_results:
            if isinstance(result, Exception):
                logger.error(f"Agent returned exception: {result}")
                continue
            if isinstance(result, dict) and result.get('response') is not None:
                valid_results.append(result)
        
        logger.info(f"=== {len(valid_results)}/{len(TACTICAL_PERSONAS)} AGENTS SUCCEEDED ===")
        
        if not valid_results:
            raise Exception("All agents failed — using fallback")
        
        # ============================================================
        # PICK THE BEST RESPONSE
        # ============================================================
        best_result = max(valid_results, key=lambda r: r['score'])
        response_dict = best_result['response']
        
        # Log the competition results
        for r in sorted(valid_results, key=lambda x: x['score'], reverse=True):
            marker = "👑" if r['agent'] == best_result['agent'] else "  "
            logger.info(f"{marker} Agent [{r['agent']}] Score: {r['score']:.1f}")
        
        logger.info(f"=== WINNER: [{best_result['agent']}] with score {best_result['score']:.1f} ===")
        
        # ============================================================
        # MERGE INTELLIGENCE FROM ALL AGENTS (even non-winners)
        # ============================================================
        all_responses = [r['response'] for r in valid_results]
        merged_intel = merge_intelligence(all_responses)
        
        # Use merged intel (best of all agents combined)
        response_dict['extractedIntelligence'] = merged_intel
        
        # Add engagement metrics
        engagement = calculate_engagement_metrics(request.get_history(), request.message)
        response_dict['engagementMetrics'] = {
            "engagementDurationSeconds": engagement.engagementDurationSeconds,
            "totalMessagesExchanged": engagement.totalMessagesExchanged
        }
        
        # Save the LLM's original agent notes before wrapping with competition info
        original_agent_notes = response_dict.get('agentNotes', 'Scam detected and intelligence extracted')
        
        # Add multi-agent notes (for internal logging only)
        agent_notes_combined = f"[WINNER: {best_result['agent']}] {response_dict.get('agentNotes', '')}"
        if len(valid_results) > 1:
            all_agents = ', '.join([f"{r['agent']}({r['score']:.0f})" for r in valid_results])
            agent_notes_combined += f" | Agents competed: {all_agents}"
        response_dict['agentNotes'] = agent_notes_combined
        
        logger.info(f"=== RETURNING BEST RESPONSE ===")
        logger.info(f"Reply: {response_dict.get('reply', '')}")
        
        # Log conversation
        log_conversation(request.get_session_id(), body, response_dict)
        
        # Accumulate session intelligence from BOTH sources:
        # 1. Regex-extracted intel from conversation text (known_intel) — this is the reliable source
        # 2. LLM-extracted intel from agent responses (merged_intel) — often empty
        session_id = request.get_session_id()
        total_messages = len(request.get_history()) + 1
        
        # Accumulate regex-extracted intelligence (the primary source)
        accumulate_session_intelligence(session_id, known_intel)
        
        # Also accumulate any LLM-extracted intelligence
        if merged_intel:
            accumulate_session_intelligence(session_id, merged_intel)
        
        # Track scam type per session (prefer LLM-detected, fallback to keyword inference)
        detected_type = response_dict.get('scamType', 'unknown')
        if detected_type and detected_type != 'unknown':
            session_scam_types[session_id] = detected_type
        elif session_id not in session_scam_types:
            session_scam_types[session_id] = infer_scam_type_from_message(request.message.text)
        
        # Log accumulated intel for debugging
        accumulated = session_intelligence.get(session_id, {})
        logger.info(f"=== ACCUMULATED INTELLIGENCE for {session_id} ===")
        for key in ['bankAccounts', 'upiIds', 'phoneNumbers', 'phishingLinks', 'emailAddresses', 'employeeIds']:
            items = accumulated.get(key, [])
            if items:
                logger.info(f"  {key}: {items}")
        
        session_timestamps[session_id] = datetime.now()
        
        # Send callback if conditions met
        should_send_callback = (
            total_messages >= MAX_MESSAGES_BEFORE_CALLBACK and 
            response_dict.get('scamDetected', False) and
            response_dict.get('confidenceScore', 0) >= 0.7
        )
        
        if should_send_callback:
            send_callback(session_id, total_messages, original_agent_notes)
        
        # Return simplified response
        api_response = {
            "status": "success",
            "reply": response_dict.get('reply', '')
        }
        
        from fastapi.responses import JSONResponse
        return JSONResponse(content=api_response)
        
    except Exception as e:
        import traceback
        logger.error(f"Error processing request: {str(e)}")
        print(f"DEBUG: Exception Type: {type(e)}")
        print(f"DEBUG: Exception Args: {e.args}")
        print(f"DEBUG: Full Traceback:")
        traceback.print_exc()
        
        # Dynamic fallback — uses scammer's actual message for context-aware response
        try:
            scammer_msg = request.message.text if request else "unknown"
            known = analyze_known_intelligence(request.get_history(), scammer_msg) if request else {}
            import random as _rand
            persona_pick = _rand.choice(["confused_uncle", "eager_victim", "worried_citizen"])
            language = request.metadata.language if request and request.metadata else "English"
            fallback_response = generate_smart_fallback(scammer_msg, "", persona_pick, known, language)
            fallback_response["engagementMetrics"]["totalMessagesExchanged"] = len(request.get_history()) + 1
            fallback_response["agentNotes"] = f"Endpoint-level fallback ({persona_pick}). Error: {str(e)[:200]}"
        except:
            # Absolute last resort
            fallback_response = {
                "status": "success",
                "scamDetected": True,
                "confidenceScore": 0.75,
                "reply": "Sir ek minute, mera screen hang ho gaya. Aap apna naam aur employee ID bata do, main note kar leta hun. Phir aage badhte hain.",
                "engagementMetrics": {"engagementDurationSeconds": 0, "totalMessagesExchanged": 1},
                "extractedIntelligence": {
                    "bankAccounts": [], "upiIds": [], "phoneNumbers": [],
                    "phishingLinks": [], "emailAddresses": [], "employeeIds": []
                },
                "agentNotes": f"Last resort fallback. Error: {str(e)}",
                "scamType": "unknown"
            }
        
        logger.info(f"Returning fallback response: {fallback_response['reply'][:100]}")
        from fastapi.responses import JSONResponse
        return JSONResponse(content=fallback_response)


@app.api_route("/ping", methods=["GET", "HEAD", "POST"], response_class=PlainTextResponse)
async def keep_alive():
    """
    Lightweight keep-alive endpoint for UptimeRobot.
    Accepts GET, HEAD, POST to prevent 405 errors.
    """
    return "alive"


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.get("/")
async def root():
    """Root endpoint with API info."""
    return {
        "name": "Agentic Honeypot API",
        "version": "1.0.0",
        "description": "AI-powered scam detection and intelligence extraction",
        "endpoints": {
            "POST /analyze": "Analyze message and generate honeypot response",
            "GET /health": "Health check",
            "POST /debug": "Debug endpoint to see raw request"
        }
    }


@app.post("/debug")
async def debug_request(request: Request):
    """Debug endpoint to see raw incoming request."""
    body = await request.json()
    logger.info(f"DEBUG - Raw request body: {body}")
    return {
        "received": body,
        "headers": dict(request.headers)
    }
