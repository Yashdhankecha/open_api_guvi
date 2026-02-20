"""
FastAPI routes.
POST /analyze — main honeypot endpoint
GET  /session/{session_id} — debug: view session state
POST /session/{session_id}/callback — manually trigger callback
"""

import logging
from fastapi import APIRouter, HTTPException, Header, BackgroundTasks
from typing import Optional

from config import settings
from models import AnalyzeRequest, AnalyzeResponse
from agent import run_agent
from session_store import session_store
from callback import send_callback, build_final_payload

logger = logging.getLogger(__name__)
router = APIRouter()


def _verify_api_key(x_api_key: Optional[str]):
    """Validate API key if one is configured."""
    if settings.API_KEY and x_api_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    request: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(default=None),
):
    """
    Main honeypot endpoint.
    Receives scammer message, returns honeypot reply.
    """
    _verify_api_key(x_api_key)

    logger.info(
        f"[{request.sessionId}] Turn received | "
        f"sender={request.message.sender} | "
        f"history_len={len(request.conversationHistory or [])}"
    )

    # Convert conversation history to list of dicts
    history = []
    if request.conversationHistory:
        for msg in request.conversationHistory:
            history.append({"sender": msg.sender, "text": msg.text})

    try:
        reply = await run_agent(
            session_id=request.sessionId,
            scammer_message=request.message.text,
            conversation_history=history,
        )
    except Exception as exc:
        logger.error(f"[{request.sessionId}] Agent error: {exc}", exc_info=True)
        # Graceful fallback — never return 500 to evaluator
        reply = "I'm sorry, I am very confused. Can you please call me back? I need to verify with my bank first."

    logger.info(f"[{request.sessionId}] Reply: {reply[:80]}...")
    return AnalyzeResponse(status="success", reply=reply)


@router.get("/session/{session_id}")
async def get_session(
    session_id: str,
    x_api_key: Optional[str] = Header(default=None),
):
    """Debug endpoint: view session state and extracted intel."""
    _verify_api_key(x_api_key)
    session = await session_store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    payload = build_final_payload(session)
    return {
        "session_id": session_id,
        "turn_count": session.turn_count,
        "scam_type": session.scam_type,
        "callback_sent": session.callback_sent,
        "elapsed_seconds": round(session.elapsed_seconds(), 1),
        "final_payload": payload.model_dump(),
    }


@router.post("/session/{session_id}/callback")
async def trigger_callback(
    session_id: str,
    x_api_key: Optional[str] = Header(default=None),
):
    """Manually trigger callback for a session (admin use)."""
    _verify_api_key(x_api_key)
    session = await session_store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    success = await send_callback(session)
    return {"success": success, "callback_sent": session.callback_sent}


@router.get("/test-score/{session_id}")
async def test_score(
    session_id: str,
    x_api_key: Optional[str] = Header(default=None),
):
    """
    Score a session's final output using the GUVI evaluation rubric.
    Returns detailed breakdown:
      Detection (20) + Intel (30, dynamic) + ConvQuality (30) + Engage (10) + Structure (10) = 100.
    """
    _verify_api_key(x_api_key)
    session = await session_store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    payload = build_final_payload(session)
    output = payload.model_dump()

    score = {
        "scamDetection": 0,
        "intelligenceExtraction": 0,
        "conversationQuality": 0,
        "engagementQuality": 0,
        "responseStructure": 0,
        "total": 0,
    }

    # ── 1. Scam Detection (20 pts) ──────────────────────────────────
    if output.get("scamDetected"):
        score["scamDetection"] = 20

    # ── 2. Intelligence Extraction (30 pts, dynamic per-item) ───────
    extracted = output.get("extractedIntelligence", {})
    intel_fields = [
        "phoneNumbers", "bankAccounts", "upiIds",
        "phishingLinks", "emailAddresses",
        "caseIds", "policyNumbers", "orderNumbers",
    ]
    total_fake_fields = sum(1 for f in intel_fields if extracted.get(f))
    if total_fake_fields > 0:
        per_item = 30.0 / total_fake_fields
        score["intelligenceExtraction"] = round(
            sum(per_item for f in intel_fields if extracted.get(f)), 1
        )
    score["intelligenceExtraction"] = min(score["intelligenceExtraction"], 30)

    # ── 3. Conversation Quality (30 pts) ────────────────────────────
    notes = output.get("agentNotes", "")
    history_len = len(session.history) if session else 0
    # Simple heuristics: award up to 30 based on conversation depth
    if history_len >= 2:
        score["conversationQuality"] += 5   # Had a conversation
    if history_len >= 6:
        score["conversationQuality"] += 5   # Sustained multi-turn
    if history_len >= 10:
        score["conversationQuality"] += 5   # Extended engagement
    if notes and len(notes) > 20:
        score["conversationQuality"] += 5   # Produced meaningful notes
    if "?" in " ".join(m.get("content", "") for m in (session.history or []) if m.get("role") == "assistant"):
        score["conversationQuality"] += 5   # Asked investigative questions
    if output.get("scamDetected") and total_fake_fields >= 2:
        score["conversationQuality"] += 5   # Effective elicitation
    score["conversationQuality"] = min(score["conversationQuality"], 30)

    # ── 4. Engagement Quality (10 pts) ──────────────────────────────
    metrics = output.get("engagementMetrics", {})
    duration = metrics.get("engagementDurationSeconds", 0)
    messages = metrics.get("totalMessagesExchanged", 0)
    if duration >= 30:
        score["engagementQuality"] += 3
    if duration >= 120:
        score["engagementQuality"] += 2
    if messages >= 3:
        score["engagementQuality"] += 3
    if messages >= 8:
        score["engagementQuality"] += 2
    score["engagementQuality"] = min(score["engagementQuality"], 10)

    # ── 5. Response Structure (10 pts) ──────────────────────────────
    for field in ["status", "scamDetected", "extractedIntelligence", "engagementMetrics"]:
        if field in output:
            score["responseStructure"] += 2
    if output.get("agentNotes"):
        score["responseStructure"] += 2
    score["responseStructure"] = min(score["responseStructure"], 10)

    score["total"] = round(
        score["scamDetection"]
        + score["intelligenceExtraction"]
        + score["conversationQuality"]
        + score["engagementQuality"]
        + score["responseStructure"],
        1,
    )

    return {
        "session_id": session_id,
        "score": score,
        "max_possible": 100,
        "final_output": output,
    }
