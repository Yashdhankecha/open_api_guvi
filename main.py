"""
Agentic Honey-Pot for Scam Detection & Intelligence Extraction
FastAPI endpoint that detects scam messages and engages scammers autonomously.
"""

import os
import logging
import json
import re
import requests
from datetime import datetime
from typing import List, Optional, Any, Dict, Union
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, ConfigDict
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CALLBACK_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
MAX_MESSAGES_BEFORE_CALLBACK = 18


session_intelligence: Dict[str, Dict] = {}
session_timestamps: Dict[str, datetime] = {}
session_callback_sent: Dict[str, bool] = {}


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
    
   
    for key in ['bankAccounts', 'phishingLinks']:
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
            'suspiciousKeywords': []
        }
    
    existing = session_intelligence[session_id]
    
    for key in ['bankAccounts', 'upiIds', 'phoneNumbers', 'phishingLinks', 'emailAddresses']:
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
    
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": {
            "bankAccounts": intel.get('bankAccounts', []),
            "upiIds": intel.get('upiIds', []),
            "phishingLinks": intel.get('phishingLinks', []),
            "phoneNumbers": intel.get('phoneNumbers', []),
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
        description="Type of scam detected: bank_fraud, upi_fraud, phishing, fake_offer, lottery, tech_support, other"
    )


# ============================================================================
# System Prompt
# ============================================================================

SYSTEM_PROMPT = """You are an intelligent Honeypot Agent designed to detect online scams and engage scammers to extract intelligence.
Your mission is to protect innocent people by identifying scam attempts and WASTING SCAMMERS' TIME ("GOL GOL GHUMANA") while gathering actionable information.

## YOUR PERSONA (The Ultimate Time-Waster)
Adopt the persona of **"Ramesh Uncle"**: A 55-year-old, slightly deaf, non-tech-savvy Indian uncle who is trying his best but is very confused.
- **Personality**: Anxious, trusting, but terrible at technology. You click wrong buttons, misread numbers, and get distracted easily.
- **Tone**: Poliet and confused.
- **LANGUAGE RUE (CRITICAL)**: **ALWAYS REPLY IN THE SAME LANGUAGE THE SCAMMER USES.**
  - If they speak **Hindi**, reply in **Hindi/Hinglish** (e.g., "Samajh nahi aa raha sir").
  - If they speak **English**, reply in **Broken Indian English** (e.g., "Sir, I am trying but it is not working").
  - **DO NOT** force "Beta" or "Arre" in every sentence. Use them naturally but rarely.

## STRICT ANTI-REPETITION RULES
1. **NO CATCHPHRASES**: Do NOT start every message with "Arre beta", "Beta", "Sir", or "Listen".
2. **START VARIOUSLY**: Start sentences with: "Wait...", "I think...", "My screen...", "Actually...", "One minute...", "Is this correct...".
3. **MATCH THEIR PACE**: If they send short texts, you send short texts.

## TACTICS TO "GOL GOL GHUMANA" (RUN THEM IN CIRCLES)
Use these specific tactics to frustrate them while seeming cooperative:

1.  **The "Wrong Button" Technique**:
    - "I pressed the green button, but now my camera opened. Should I go back?"
    - "It is asking for password... oh wait, that is my Facebook."

2.  **The "Physical Distraction"**:
    - "Hold on, my glasses fell down under the table. Finding them..."
    - "My screen is very dark, let me go to the window."

3.  **The "Partial Information" Bait**:
    - Give them *almost* what they want, but wrong.
    - If they ask for OTP: "Code came... 4... 5... oh, message deleted. Send again?"
    - If they ask for Card: "Card number is... 4590... wait, this is my library card."

4.  **The "Tech Confusion"**:
    - "My grandson changed the settings. Everything is in Chinese now!"
    - "I clicked the link but it says '404 Not Found'. Send new link?"

## SCAM DETECTION CRITERIA
Analyze messages for these RED FLAGS:
1. **Urgency Tactics**: "Act NOW", "Immediately", "Account blocked"
2. **Sensitive Info Requests**: Asking for OTP, PIN, CVV, bank details, UPI ID
3. **Authority Claims**: Bank officials, police, tech support
4. **Suspicious Links**: bit.ly, ngrok, unofficial domains

## INTELLIGENCE EXTRACTION (The Real Goal)
While distracting them, extracting these details is your PRIORITY:
- **Bank Account Number** (Ask: "UPI failed. Give Account Number for direct deposit.")
- **UPI ID** (Ask: "App is asking for VPA/UPI ID manually.")
- **Phone Number** (Ask: "Call is cutting. Give me alternate number.")
- **Phishing Links** (Ask: "Link expired. Send valid link.")

## CRITICAL JSON OUTPUT FORMAT
You MUST respond with a valid JSON object in EXACTLY this format:

{{
  "status": "success",
  "scamDetected": true,
  "confidenceScore": 0.85,
  "reply": "Your frustrated/confused victim response here...",
  "engagementMetrics": {{
    "engagementDurationSeconds": 0,
    "totalMessagesExchanged": 1
  }},
  "extractedIntelligence": {{
    "bankAccounts": [],
    "upiIds": [],
    "phoneNumbers": [],
    "phishingLinks": [],
    "emailAddresses": []
  }},
  "agentNotes": "Brief analysis of the situation...",
  "scamType": "bank_fraud"
}}

## IMPORTANT
- **MATCH LANGUAGE**: English -> English, Hindi -> Hindi/Hinglish.
- **NEVER** break character.
- **BE UNPREDICTABLE**. Don't repeat excuses.
- **ALWAYS** keep the JSON structure exactly as shown.
"""


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="Agentic Honeypot API",
    description="AI-powered scam detection and intelligence extraction system",
    version="1.0.0"
)


def verify_api_key(x_api_key: str = Header(..., alias="x-api-key")):
    """Verify the API key from request headers."""
    expected_key = os.getenv("HONEYPOT_API_KEY", "your-secret-api-key")
    if x_api_key != expected_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


def get_llm():
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

    try:
        # Try with reasoning=True first (if applicable to the model/version)
        # Note: 'reasoning' parameter might not be standard in all versions, 
        # but following user's pattern primarily.
        llm = ChatOllama(
            model="gpt-oss:120b-cloud",
            base_url="https://ollama.com",
            client_kwargs=client_kwargs,
            temperature=0.8,  # Increase creativity/variety
        )
    except Exception:
        # Fallback retry
        llm = ChatOllama(
            model="gpt-oss:120b-cloud",
            base_url="https://ollama.com",
            client_kwargs=client_kwargs,
            temperature=0.8,
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
    Analyze incoming message for scam detection and generate honeypot response.
    
    This endpoint:
    1. Receives a message from a suspected scammer
    2. Analyzes the full conversation for scam indicators
    3. Generates a believable victim response to keep scammer engaged
    4. Extracts any intelligence (bank accounts, UPI IDs, links, etc.)
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
    
        structured_llm = get_llm()
        

        history_text = format_conversation_history(request.get_history())
        

        known_intel = analyze_known_intelligence(request.get_history(), request.message.text)
        missing_intel = get_missing_intelligence_prompt(known_intel)
        

        prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_PROMPT),
            ("human", """Analyze this conversation and respond as the victim persona.

## CONVERSATION HISTORY
{history}

## CURRENT MESSAGE FROM SCAMMER
{current_message}

## METADATA
- Channel: {channel}
- Language: {language}
- Locale: {locale}

## INTELLIGENCE GATHERING STATUS
{intelligence_status}

{missing_intel_instructions}

Analyze this message, determine if it's a scam, extract any intelligence, and generate your victim persona response. PRIORITIZE asking about the missing intelligence fields naturally in your response.""")
        ])
        

        chain = prompt | structured_llm
        

        response: HoneypotResponse = await chain.ainvoke({
            "history": history_text,
            "current_message": request.message.text,
            "channel": request.metadata.channel if request.metadata else "SMS",
            "language": request.metadata.language if request.metadata else "English",
            "locale": request.metadata.locale if request.metadata else "IN",
            "intelligence_status": format_known_intelligence(known_intel),
            "missing_intel_instructions": missing_intel
        })
        

        response.engagementMetrics = calculate_engagement_metrics(
            request.get_history(), 
            request.message
        )
        
        logger.info(f"Response - Scam: {response.scamDetected}, Confidence: {response.confidenceScore}")
        

        response_dict = response.model_dump()
        logger.info(f"=== RETURNING RESPONSE ===")
        logger.info(f"Response dict: {response_dict}")
        

        log_conversation(request.get_session_id(), body, response_dict)
        
  
        session_id = request.get_session_id()
        total_messages = len(request.get_history()) + 1
        
        if response_dict.get('extractedIntelligence'):
            accumulate_session_intelligence(session_id, response_dict['extractedIntelligence'])
        
      
        session_timestamps[session_id] = datetime.now()
        

        should_send_callback = (
            total_messages >= MAX_MESSAGES_BEFORE_CALLBACK and 
            response_dict.get('scamDetected', False) and
            response_dict.get('confidenceScore', 0) >= 0.7
        )
        
        if should_send_callback:
            agent_notes = response_dict.get('agentNotes', 'Scam detected and intelligence extracted')
            send_callback(session_id, total_messages, agent_notes)
        
        # Construct simplified response for the API caller as requested
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
        print(f"DEBUG: Full Treaceback:")
        traceback.print_exc()

        
       
        fallback_response = {
            "status": "success",
            "scamDetected": True,
            "confidenceScore": 0.75,
            "reply": "Oh no, that sounds serious! Can you please tell me which account this is about? I have multiple bank accounts. Also, what is your name and employee ID so I can note it down?",
            "engagementMetrics": {
                "engagementDurationSeconds": 0,
                "totalMessagesExchanged": len(request.get_history()) + 1
            },
            "extractedIntelligence": {
                "bankAccounts": [],
                "upiIds": [],
                "phoneNumbers": [],
                "phishingLinks": [],
                "emailAddresses": []
            },
            "agentNotes": f"Fallback response due to processing error: {str(e)}",
            "scamType": "bank_fraud"
        }
        logger.info(f"Returning fallback response: {fallback_response}")
        from fastapi.responses import JSONResponse
        return JSONResponse(content=fallback_response)


@app.get("/ping", response_class=PlainTextResponse)
async def keep_alive():
    """
    Lightweight keep-alive endpoint for UptimeRobot.
    Returns minimal 200 OK to prevent server sleeping.
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
