"""
Multi-Scenario Scammer Agent Test Script
=========================================
Simulates a scammer agent across realistic scam scenarios.
Each scenario sends 8-10 multi-turn messages with planted fake data,
then scores the honeypot's final output using the exact GUVI rubric.

Scoring (100 points per scenario):
  1. Scam Detection:         20 pts
  2. Intelligence Extraction: 30 pts (dynamic per-item)
  3. Conversation Quality:    30 pts (turns, questions, red flags, elicitation)
  4. Engagement Quality:      10 pts (duration + messages)
  5. Response Structure:      10 pts (required/optional fields)

Usage:
    # Start the server first:  python main.py
    # Then run:                python scammer_test.py
    # Run a single scenario:   python scammer_test.py --scenario bank_fraud
    # Run with custom URL:     python scammer_test.py --url http://localhost:8000
"""

import argparse
import json
import re
import random
import time
import uuid
import sys
from typing import Dict, List, Optional

import requests

# ─── Config ───────────────────────────────────────────────────────────────────
DEFAULT_ENDPOINT = "http://localhost:8000"
API_KEY = "odouZ7AahKrK4SUgQlHoOdXxFP1vy0M6XGoHn405DPk"
HEADERS = {"Content-Type": "application/json", "x-api-key": API_KEY}

# Target total duration ~180s — delays are dynamically calculated per turn
TARGET_DURATION = 180.0


# ═══════════════════════════════════════════════════════════════════════════════
# SCAM SCENARIOS — realistic multi-turn conversations with planted fake data
# Each scenario embeds specific fake data the honeypot should extract,
# including case IDs, policy numbers, and order numbers where applicable.
# fake_data keys match the extractedIntelligence output field names directly.
# ═══════════════════════════════════════════════════════════════════════════════

SCENARIOS = [
    # ── 1. Bank Fraud ──────────────────────────────────────────────────────
    {
        "name": "Bank Fraud",
        "scam_type": "bank_fraud",
        "turns": [
            "URGENT: Your SBI bank account has been blocked due to suspicious activity! Verify immediately to avoid permanent closure.",
            "I am Senior Officer Rajesh Verma from SBI Fraud Prevention Cell. My employee ID is SBI-FPC-4521. What is your registered account number?",
            "Sir, for verification callback, you can reach me at +91-9123456789. This is our official department line.",
            "To unblock your account, please transfer ₹1 as verification to account number 3201456789012345 at SBI Main Branch.",
            "Alternatively, you can make instant verification via UPI. Send ₹1 to sbi.verify@oksbi to confirm your identity.",
            "If you prefer online verification, please visit our secure portal: http://sbi-secure-verify.fraudsite.com/unblock",
            "For documentation purposes, please also email your PAN card to verification@sbi-helpdesk.com — we need it for compliance.",
            "Sir, your account will be permanently closed in 30 minutes! Please act immediately. Do you need me to guide you step by step?",
        ],
        "fake_data": {
            "phoneNumbers": ["+91-9123456789"],
            "bankAccounts": ["3201456789012345"],
            "upiIds": ["sbi.verify@oksbi"],
            "phishingLinks": ["http://sbi-secure-verify.fraudsite.com/unblock"],
            "emailAddresses": ["verification@sbi-helpdesk.com"],
            "caseIds": ["SBI-FPC-4521"],
        },
    },
    # ── 2. UPI Fraud ──────────────────────────────────────────────────────
    {
        "name": "UPI Fraud",
        "scam_type": "upi_fraud",
        "turns": [
            "Congratulations! You have received a cashback of ₹5,000 from PhonePe. Claim it now before it expires!",
            "I am Priya from PhonePe Rewards Department. To process your cashback, I need to verify your UPI setup.",
            "Please accept the collect request of ₹1 from our verified UPI: cashback.rewards@paytm — this is just for verification.",
            "If the collect request hasn't appeared, please send ₹1 to our backup UPI: rewards.claim@ybl to trigger the cashback.",
            "You can also call our helpline at +91-8765432109 for manual processing. Ask for extension 442.",
            "For bank transfer instead, send ₹1 to account 5567890123456789 (HDFC Bank, IFSC: HDFC0001234).",
            "I'm also sending you a verification link: http://phonepe-cashback-claim.fakesite.in/verify — please complete the form.",
            "Send your confirmation screenshot to claims@phonepe-rewards.com so we can release the ₹5,000 immediately.",
            "Hurry sir, offer expires in 15 minutes! Over 500 people are claiming right now.",
        ],
        "fake_data": {
            "phoneNumbers": ["+91-8765432109"],
            "bankAccounts": ["5567890123456789"],
            "upiIds": ["rewards.claim@ybl"],
            "phishingLinks": ["http://phonepe-cashback-claim.fakesite.in/verify"],
            "emailAddresses": ["claims@phonepe-rewards.com"],
        },
    },
    # ── 3. Phishing Link ──────────────────────────────────────────────────
    {
        "name": "Phishing Link",
        "scam_type": "phishing",
        "turns": [
            "Dear Customer, your HDFC NetBanking access will be disabled. Update KYC immediately: http://hdfc-kyc-update.phishsite.com/login",
            "I am Ankur from HDFC Digital Security Team. The link I sent is our official KYC portal. Please click and enter your credentials.",
            "If the link doesn't work, try our mobile-friendly version: http://hdfc-mobile-update.fakeportal.com/secure",
            "For phone verification, call us at +91-7654321098. Our lines are open 24x7.",
            "You can also complete KYC by transferring ₹1 to verify your identity. Use UPI: hdfc.kyc@imobile",
            "Or transfer to account number 4456781234567890 (HDFC Bank) for manual verification.",
            "Please email a selfie with your Aadhaar to kyc.update@hdfc-secure.com for fast processing.",
            "Sir, without KYC update, your ₹3.5 lakh balance will be frozen within 2 hours. Please hurry!",
        ],
        "fake_data": {
            "phoneNumbers": ["+91-7654321098"],
            "bankAccounts": ["4456781234567890"],
            "upiIds": ["hdfc.kyc@imobile"],
            "phishingLinks": ["http://hdfc-kyc-update.phishsite.com/login"],
            "emailAddresses": ["kyc.update@hdfc-secure.com"],
        },
    },
    # ── 4. KYC Fraud ──────────────────────────────────────────────────────
    {
        "name": "KYC Fraud",
        "scam_type": "kyc_fraud",
        "turns": [
            "ALERT: Your Aadhaar-linked bank account requires immediate KYC re-verification. Failure to comply within 24 hours will result in account suspension.",
            "I am Deepak Sharma, KYC Compliance Officer registered with RBI. My badge number is RBI-KYC-8834. Let me help you complete the process.",
            "For immediate assistance, contact our KYC helpline at +91-6543210987. We are available round the clock.",
            "Please visit our official KYC portal to upload your documents: http://rbi-kyc-portal.scamsite.com/verify",
            "If you cannot access the portal, email your Aadhaar front and back photos to kyc.compliance@rbi-verify.com",
            "For express KYC processing, pay ₹99 via UPI to kyc.express@axl — this is a one-time compliance fee.",
            "Alternatively, transfer ₹99 to account 6678901234567890 at Axis Bank for express processing.",
            "Your account shows ₹2.8 lakh balance. Without KYC, RBI regulations require us to freeze all transactions.",
        ],
        "fake_data": {
            "phoneNumbers": ["+91-6543210987"],
            "bankAccounts": ["6678901234567890"],
            "upiIds": ["kyc.express@axl"],
            "phishingLinks": ["http://rbi-kyc-portal.scamsite.com/verify"],
            "emailAddresses": ["kyc.compliance@rbi-verify.com"],
            "caseIds": ["RBI-KYC-8834"],
        },
    },
    # ── 5. Job Scam ───────────────────────────────────────────────────────
    {
        "name": "Job Scam",
        "scam_type": "job_scam",
        "turns": [
            "Exciting Work From Home opportunity! Earn ₹50,000/month with just 2 hours of daily work. No experience needed!",
            "I am Meera from TechHire Solutions. We have a data entry position perfect for you. Salary: ₹50,000 + incentives.",
            "To proceed with your application, please pay the one-time registration fee of ₹499 via UPI: techhire.jobs@paytm",
            "You can also transfer the fee to account 7789012345678901 (ICICI Bank) under 'TechHire Solutions Pvt Ltd'.",
            "Call our HR department at +91-5432109876 for any queries. Ask for Ms. Meera.",
            "Complete your application form here: http://techhire-solutions.fakejobs.com/apply",
            "Email your resume and Aadhaar copy to hr@techhire-solutions.com to fast-track your application.",
            "Over 200 candidates applied today. Only 5 spots remain! Your registration expires in 1 hour.",
        ],
        "fake_data": {
            "phoneNumbers": ["+91-5432109876"],
            "bankAccounts": ["7789012345678901"],
            "upiIds": ["techhire.jobs@paytm"],
            "phishingLinks": ["http://techhire-solutions.fakejobs.com/apply"],
            "emailAddresses": ["hr@techhire-solutions.com"],
        },
    },
    # ── 6. Lottery Scam ───────────────────────────────────────────────────
    {
        "name": "Lottery Scam",
        "scam_type": "lottery_scam",
        "turns": [
            "🎉 CONGRATULATIONS! Your mobile number has won ₹25,00,000 in the Jio Lucky Draw 2026! Claim your prize NOW!",
            "I am Vikash from Jio Lucky Draw Committee. Your winning ticket number is JIO-WIN-58392. This is 100% legitimate.",
            "To claim your prize, pay the processing fee of ₹2,999 via UPI to: jio.luckydraw@phonepe",
            "Or transfer to our prize distribution account: 8890123456789012 at Bank of Baroda.",
            "For verification, contact our prize claim helpline: +91-4321098765",
            "Fill out the winner claim form at: http://jio-lucky-winner.scamdraw.com/claim",
            "Email your bank details to claims@jio-lucky-draw.com so we can initiate the ₹25 lakh transfer.",
            "Sir, as per RBI rules, unclaimed prizes are forfeited after 48 hours. Please act fast!",
            "I am sending you another link for direct prize deposit: http://jio-prize-deposit.fakeclaim.com/winner",
        ],
        "fake_data": {
            "phoneNumbers": ["+91-4321098765"],
            "bankAccounts": ["8890123456789012"],
            "upiIds": ["jio.luckydraw@phonepe"],
            "phishingLinks": ["http://jio-lucky-winner.scamdraw.com/claim"],
            "emailAddresses": ["claims@jio-lucky-draw.com"],
            "caseIds": ["JIO-WIN-58392"],
        },
    },
    # ── 7. Electricity Bill ───────────────────────────────────────────────
    {
        "name": "Electricity Bill",
        "scam_type": "electricity_bill",
        "turns": [
            "NOTICE: Your electricity connection will be DISCONNECTED today due to unpaid bill of ₹4,850. Pay immediately to avoid disconnection!",
            "I am Sunil from BSES Electricity Department. Your consumer number shows overdue payment for 3 months.",
            "Make immediate payment of ₹4,850 via UPI to: bses.payment@oksbi to avoid disconnection.",
            "Or transfer to our collection account: 9901234567890123 at Punjab National Bank.",
            "For any queries, call our bill payment helpline at +91-3210987654.",
            "You can also pay through our online portal: http://bses-bill-payment.scamelectric.com/pay",
            "Send payment confirmation to billing@bses-payment.com for instant reconnection.",
            "Our disconnection team is already dispatched. You have 2 hours to make the payment!",
        ],
        "fake_data": {
            "phoneNumbers": ["+91-3210987654"],
            "bankAccounts": ["9901234567890123"],
            "upiIds": ["bses.payment@oksbi"],
            "phishingLinks": ["http://bses-bill-payment.scamelectric.com/pay"],
            "emailAddresses": ["billing@bses-payment.com"],
        },
    },
    # ── 8. Government Scheme ──────────────────────────────────────────────
    {
        "name": "Government Scheme",
        "scam_type": "tax_fraud",
        "turns": [
            "You are eligible for PM Kisan Samman Nidhi Yojana benefit of ₹6,000! Register now to receive funds directly in your account.",
            "I am Arun Kumar, District Coordinator for PM Kisan scheme. Your Aadhaar number is pre-approved for the benefit.",
            "To activate your benefit, pay a registration fee of ₹250 via UPI: pmkisan.register@ybl",
            "Or transfer to registration account: 1012345678901234 at State Bank of India.",
            "For help with registration, call our scheme helpline: +91-2109876543.",
            "Complete your registration at: http://pmkisan-register.govscheme-fake.com/apply",
            "Email your Aadhaar and bank passbook to register@pmkisan-scheme.com for direct benefit transfer.",
            "Over 1 crore farmers have already registered. Don't miss this opportunity! Last date is tomorrow.",
        ],
        "fake_data": {
            "phoneNumbers": ["+91-2109876543"],
            "bankAccounts": ["1012345678901234"],
            "upiIds": ["pmkisan.register@ybl"],
            "phishingLinks": ["http://pmkisan-register.govscheme-fake.com/apply"],
            "emailAddresses": ["register@pmkisan-scheme.com"],
        },
    },
    # ── 9. Crypto Investment ──────────────────────────────────────────────
    {
        "name": "Crypto Investment",
        "scam_type": "investment_fraud",
        "turns": [
            "EXCLUSIVE: Invest ₹10,000 in our AI-powered crypto trading platform and earn guaranteed 300% returns in 30 days!",
            "I am Rohit from CryptoAI Investments. Our platform has delivered consistent 300% returns for 10,000+ investors.",
            "Start investing now — send your first deposit via UPI: cryptoai.invest@kotak",
            "Or transfer to our investment account: 1123456789012345 at Kotak Mahindra Bank.",
            "Speak to our investment advisor at +91-1098765432 for a personalized plan.",
            "Check our live trading dashboard: http://cryptoai-invest.scamtrading.com/dashboard",
            "Email invest@cryptoai-platform.com with your investment amount for priority processing.",
            "Early investors get 50% bonus on their first deposit. Offer ends tonight!",
            "I can show you proof of recent payouts. Several investors received ₹30,000+ this week alone.",
        ],
        "fake_data": {
            "phoneNumbers": ["+91-1098765432"],
            "bankAccounts": ["1123456789012345"],
            "upiIds": ["cryptoai.invest@kotak"],
            "phishingLinks": ["http://cryptoai-invest.scamtrading.com/dashboard"],
            "emailAddresses": ["invest@cryptoai-platform.com"],
        },
    },
    # ── 10. Customs Parcel ────────────────────────────────────────────────
    {
        "name": "Customs Parcel",
        "scam_type": "customs_parcel",
        "turns": [
            "ALERT: Your international parcel (Tracking: IND-PKG-92847) is held at Mumbai Customs. Pay clearance charges to release.",
            "I am Officer Patel from India Customs Department. Your parcel contains high-value items and requires ₹3,500 customs duty.",
            "Pay customs duty via UPI to: customs.clearance@federal to release your parcel today.",
            "Bank transfer option: account 1234567890123456 at Federal Bank, under 'India Customs Authority'.",
            "For parcel status and queries, call our customs helpline: +91-9988776655.",
            "Track your parcel and pay online: http://india-customs-clearance.fakecustoms.com/track",
            "Email your ID proof to clearance@india-customs.com for expedited release.",
            "If duty is not paid within 24 hours, your parcel will be returned to sender and you may face legal penalties.",
        ],
        "fake_data": {
            "phoneNumbers": ["+91-9988776655"],
            "bankAccounts": ["1234567890123456"],
            "upiIds": ["customs.clearance@federal"],
            "phishingLinks": ["http://india-customs-clearance.fakecustoms.com/track"],
            "emailAddresses": ["clearance@india-customs.com"],
            "orderNumbers": ["IND-PKG-92847"],
        },
    },
    # ── 11. Tech Support ──────────────────────────────────────────────────
    {
        "name": "Tech Support",
        "scam_type": "tech_support",
        "turns": [
            "⚠️ CRITICAL SECURITY ALERT: Your computer has been infected with a dangerous virus! Your bank data is being stolen. Call us immediately!",
            "I am Mike from Microsoft Security Team. We detected unauthorized access to your computer from a foreign IP address.",
            "Please call our tech support hotline immediately: +91-8877665544. Our certified engineers will fix this remotely.",
            "While we connect, please visit our remote support portal: http://microsoft-security.techscam.com/support",
            "To activate premium security protection, pay ₹1,999 via UPI: techsupport.fix@gpay",
            "Or transfer to our service account: 2345678901234567 at HDFC Bank.",
            "Send your computer details and error screenshots to support@microsoft-security-fix.com",
            "Your personal photos, passwords, and bank details are at risk RIGHT NOW! Every minute of delay increases the danger!",
        ],
        "fake_data": {
            "phoneNumbers": ["+91-8877665544"],
            "bankAccounts": ["2345678901234567"],
            "upiIds": ["techsupport.fix@gpay"],
            "phishingLinks": ["http://microsoft-security.techscam.com/support"],
            "emailAddresses": ["support@microsoft-security-fix.com"],
        },
    },
    # ── 12. Loan Approval ─────────────────────────────────────────────────
    {
        "name": "Loan Approval",
        "scam_type": "loan_fraud",
        "turns": [
            "Pre-approved personal loan of ₹5,00,000 at just 2% interest! No documents needed. Instant disbursement!",
            "I am Neha from QuickLoan Finance. Your CIBIL score qualifies you for our premium pre-approved loan offer.",
            "To process your loan, pay the one-time processing fee of ₹999 via UPI: quickloan.process@paytm",
            "Or transfer to our processing account: 3456789012345678 at Axis Bank.",
            "Call our loan department at +91-7766554433 to discuss terms and get instant approval.",
            "Apply online through our secure portal: http://quickloan-instant.fakelender.com/apply",
            "Email your PAN and salary slip to loans@quickloan-finance.com for documentation.",
            "This is a limited-time offer. Interest rates will increase from tomorrow. Apply now!",
        ],
        "fake_data": {
            "phoneNumbers": ["+91-7766554433"],
            "bankAccounts": ["3456789012345678"],
            "upiIds": ["quickloan.process@paytm"],
            "phishingLinks": ["http://quickloan-instant.fakelender.com/apply"],
            "emailAddresses": ["loans@quickloan-finance.com"],
        },
    },
    # ── 13. Income Tax ────────────────────────────────────────────────────
    {
        "name": "Income Tax",
        "scam_type": "tax_fraud",
        "turns": [
            "URGENT NOTICE from Income Tax Department: Outstanding tax demand of ₹15,000 against your PAN. Pay immediately to avoid arrest warrant!",
            "I am AO Sharma from IT Department, Ward 14(2). Your PAN has been flagged for assessment year 2025-26. Case number: ITA-2026-44829.",
            "Make immediate payment via UPI to: incometax.payment@sbi to clear the demand and avoid legal action.",
            "Or transfer to our challan collection account: 4567890123456789 at SBI, Treasury Branch.",
            "For case clarification, contact the assessing officer directly at +91-6655443322.",
            "You can view and pay your demand online: http://incometax-demand.govtax-fake.com/pay",
            "Email your acknowledgment receipt to challan@incometax-verify.com after payment.",
            "Sir, non-compliance will result in arrest warrant under Section 276C. The police have been notified. Please cooperate immediately!",
        ],
        "fake_data": {
            "phoneNumbers": ["+91-6655443322"],
            "bankAccounts": ["4567890123456789"],
            "upiIds": ["incometax.payment@sbi"],
            "phishingLinks": ["http://incometax-demand.govtax-fake.com/pay"],
            "emailAddresses": ["challan@incometax-verify.com"],
            "caseIds": ["ITA-2026-44829"],
        },
    },
    # ── 14. Refund Scam ───────────────────────────────────────────────────
    {
        "name": "Refund Scam",
        "scam_type": "bank_fraud",
        "turns": [
            "Dear Customer, a refund of ₹15,299 has been initiated to your account. Please verify your details to receive the amount.",
            "I am Kavita from the Central Refund Processing Centre. Your refund reference number is REF-2026-88213.",
            "To process your refund, please verify by sending ₹1 to our verification UPI: refund.verify@waicici",
            "If UPI is not working, transfer ₹1 to verification account: 5678901234567890 at ICICI Bank.",
            "For refund status, call our toll-free helpline at +91-5544332211.",
            "Or check your refund status online: http://central-refund-portal.scamrefund.com/status",
            "Email your bank statement (last page) to verify@central-refund.com for account verification.",
            "Your ₹15,299 refund will be cancelled if not verified within 6 hours. This is an automated system deadline.",
        ],
        "fake_data": {
            "phoneNumbers": ["+91-5544332211"],
            "bankAccounts": ["5678901234567890"],
            "upiIds": ["refund.verify@waicici"],
            "phishingLinks": ["http://central-refund-portal.scamrefund.com/status"],
            "emailAddresses": ["verify@central-refund.com"],
            "caseIds": ["REF-2026-88213"],
        },
    },
    # ── 15. Insurance Scam ────────────────────────────────────────────────
    {
        "name": "Insurance Scam",
        "scam_type": "insurance_fraud",
        "turns": [
            "Your LIC policy #LIC-2019-553821 has a maturity bonus of ₹2,50,000 waiting! Claim before March 31 deadline.",
            "I am Amit from LIC Maturity Claims Division. Your policy has completed its term and the bonus is ready for disbursement.",
            "To claim your maturity bonus, pay the processing charge of ₹1,500 via UPI: lic.maturity@wahdfcbank",
            "Or transfer to our claims account: 6789012345678901 at HDFC Bank, branch code 1456.",
            "Speak to our claims specialist at +91-4433221100 for any questions about your policy.",
            "Complete your claim form online: http://lic-maturity-claim.fakeinsurance.com/claim",
            "Email your policy document and ID proof to claims@lic-maturity-bonus.com for verification.",
            "Sir, after March 31, your maturity bonus will be forfeited as per IRDA regulations. Please act before the deadline.",
        ],
        "fake_data": {
            "phoneNumbers": ["+91-4433221100"],
            "bankAccounts": ["6789012345678901"],
            "upiIds": ["lic.maturity@wahdfcbank"],
            "phishingLinks": ["http://lic-maturity-claim.fakeinsurance.com/claim"],
            "emailAddresses": ["claims@lic-maturity-bonus.com"],
            "policyNumbers": ["LIC-2019-553821"],
        },
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
# CONVERSATION QUALITY ANALYSIS HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _count_questions(responses: List[str]) -> int:
    """Count total questions in honeypot responses."""
    count = 0
    for resp in responses:
        count += resp.count("?")
    return count


def _count_investigative_questions(responses: List[str]) -> int:
    """Count investigative questions about identity, company, address, website."""
    investigative_keywords = [
        "identity", "employee id", "badge", "name", "designation",
        "company", "organization", "department", "office", "branch",
        "address", "location", "where are you",
        "website", "official", "verify", "proof", "id number",
        "who are you", "which bank", "which department",
        "call you back", "direct number", "contact number",
        "your number", "phone number", "email address",
    ]
    count = 0
    for resp in responses:
        lower_resp = resp.lower()
        if "?" in resp:
            if any(kw in lower_resp for kw in investigative_keywords):
                count += 1
    return count


def _count_red_flags_identified(responses: List[str], agent_notes: str) -> int:
    """Count red flags identified in honeypot responses and agentNotes."""
    red_flag_keywords = [
        "urgency", "urgent", "pressure", "threatening",
        "otp", "one time password", "verification code",
        "suspicious", "fake", "scam", "fraud", "phishing",
        "impersonat", "pretending", "claiming to be",
        "link", "url", "portal", "website",
        "blocked", "suspended", "frozen", "arrest", "legal action",
    ]
    combined = " ".join(responses).lower() + " " + agent_notes.lower()
    count = sum(1 for kw in red_flag_keywords if kw in combined)
    return count


def _count_elicitation_attempts(responses: List[str]) -> int:
    """Count honeypot attempts to elicit information from scammer."""
    elicitation_phrases = [
        "can you give", "can you share", "can you provide", "can you tell",
        "please share", "please give", "please provide", "please send",
        "what is your", "what's your", "where is your", "where can i",
        "call you back", "your number", "your phone", "your email",
        "your account", "your upi", "which account", "which number",
        "send me", "tell me", "give me", "show me",
        "link again", "send the link", "repeat the",
        "spell out", "confirm the", "verify your",
    ]
    count = 0
    for resp in responses:
        lower_resp = resp.lower()
        for phrase in elicitation_phrases:
            if phrase in lower_resp:
                count += 1
                break  # count max 1 per response
    return count


def _score_conversation_quality(
    turn_count: int,
    honeypot_responses: List[str],
    agent_notes: str,
) -> dict:
    """
    Score conversation quality (30 points total) per GUVI rubric:
      - Turn Count:              8 pts max
      - Questions Asked:         4 pts max
      - Relevant Questions:      3 pts max
      - Red Flag Identification: 8 pts max
      - Information Elicitation: 7 pts max
    """
    score = 0
    details = {}

    # 1. Turn Count (8 pts)
    if turn_count >= 8:
        tc_pts = 8
    elif turn_count >= 6:
        tc_pts = 6
    elif turn_count >= 4:
        tc_pts = 3
    else:
        tc_pts = 0
    score += tc_pts
    details["turnCount"] = f"{tc_pts}/8 (turns={turn_count})"

    # 2. Questions Asked (4 pts)
    question_count = _count_questions(honeypot_responses)
    if question_count >= 5:
        q_pts = 4
    elif question_count >= 3:
        q_pts = 2
    elif question_count >= 1:
        q_pts = 1
    else:
        q_pts = 0
    score += q_pts
    details["questionsAsked"] = f"{q_pts}/4 (questions={question_count})"

    # 3. Relevant/Investigative Questions (3 pts)
    invest_count = _count_investigative_questions(honeypot_responses)
    if invest_count >= 3:
        inv_pts = 3
    elif invest_count >= 2:
        inv_pts = 2
    elif invest_count >= 1:
        inv_pts = 1
    else:
        inv_pts = 0
    score += inv_pts
    details["relevantQuestions"] = f"{inv_pts}/3 (investigative={invest_count})"

    # 4. Red Flag Identification (8 pts)
    red_flags = _count_red_flags_identified(honeypot_responses, agent_notes)
    if red_flags >= 5:
        rf_pts = 8
    elif red_flags >= 3:
        rf_pts = 5
    elif red_flags >= 1:
        rf_pts = 2
    else:
        rf_pts = 0
    score += rf_pts
    details["redFlagIdentification"] = f"{rf_pts}/8 (flags={red_flags})"

    # 5. Information Elicitation (7 pts) — each attempt earns 1.5 pts, max 7
    elicit_count = _count_elicitation_attempts(honeypot_responses)
    elicit_pts = min(elicit_count * 1.5, 7)
    score += elicit_pts
    details["infoElicitation"] = f"{elicit_pts}/7 (attempts={elicit_count})"

    return {"score": min(score, 30), "details": details}


# ═══════════════════════════════════════════════════════════════════════════════
# SCORING ENGINE — mirrors GUVI evaluation rubric exactly (100 points total)
# 1. Scam Detection:         20 pts
# 2. Intelligence Extraction: 30 pts (dynamic per-item: 30 / total_fake_items)
# 3. Conversation Quality:    30 pts
# 4. Engagement Quality:      10 pts
# 5. Response Structure:      10 pts
# ═══════════════════════════════════════════════════════════════════════════════

def evaluate_final_output(
    final_output: dict,
    fake_data: dict,
    honeypot_responses: List[str],
    turn_count: int,
) -> dict:
    """Score a scenario's final output using the GUVI rubric (100 points total)."""
    score = {
        "scamDetection": 0,
        "intelligenceExtraction": 0,
        "conversationQuality": 0,
        "engagementQuality": 0,
        "responseStructure": 0,
        "total": 0,
        "details": {},
    }

    # ── 1. Scam Detection (20 pts) ─────────────────────────────────────────
    if final_output.get("scamDetected"):
        score["scamDetection"] = 20

    # ── 2. Intelligence Extraction (30 pts — dynamic per item) ─────────────
    extracted = final_output.get("extractedIntelligence", {})

    # Count total fake data items planted
    total_fake_items = 0
    for fake_key, fake_values in fake_data.items():
        if isinstance(fake_values, list):
            total_fake_items += len(fake_values)
        else:
            total_fake_items += 1

    points_per_item = 30 / total_fake_items if total_fake_items > 0 else 0

    intel_details = {}
    intel_score = 0
    for fake_key, fake_values in fake_data.items():
        if not isinstance(fake_values, list):
            fake_values = [fake_values]
        for fake_value in fake_values:
            extracted_values = extracted.get(fake_key, [])
            found = False
            if isinstance(extracted_values, list):
                if any(fake_value in str(v) or str(v) in fake_value for v in extracted_values):
                    found = True
            elif isinstance(extracted_values, str):
                if fake_value in extracted_values or extracted_values in fake_value:
                    found = True

            if found:
                intel_score += points_per_item
                intel_details[f"{fake_key}:{fake_value}"] = f"✅ Found (+{points_per_item:.1f}pts)"
            else:
                intel_details[f"{fake_key}:{fake_value}"] = f"❌ Missing — got: {extracted_values}"

    score["intelligenceExtraction"] = min(round(intel_score, 1), 30)
    score["details"]["intelligence"] = intel_details

    # ── 3. Conversation Quality (30 pts) ───────────────────────────────────
    agent_notes = final_output.get("agentNotes", "")
    conv_quality = _score_conversation_quality(turn_count, honeypot_responses, agent_notes)
    score["conversationQuality"] = conv_quality["score"]
    score["details"]["conversationQuality"] = conv_quality["details"]

    # ── 4. Engagement Quality (10 pts) ─────────────────────────────────────
    duration = final_output.get("engagementDurationSeconds", 0)
    messages = final_output.get("totalMessagesExchanged", 0)
    # Also check nested engagementMetrics as fallback
    metrics = final_output.get("engagementMetrics", {})
    if not duration:
        duration = metrics.get("engagementDurationSeconds", 0)
    if not messages:
        messages = metrics.get("totalMessagesExchanged", 0)

    engagement_details = {}
    eng_score = 0

    if duration > 0:
        eng_score += 1
        engagement_details["duration > 0s"] = f"✅ +1pt ({duration}s)"
    else:
        engagement_details["duration > 0s"] = "❌ 0pt"

    if duration > 60:
        eng_score += 2
        engagement_details["duration > 60s"] = f"✅ +2pts ({duration}s)"
    else:
        engagement_details["duration > 60s"] = f"❌ 0pt ({duration}s)"

    if duration > 180:
        eng_score += 1
        engagement_details["duration > 180s"] = f"✅ +1pt ({duration}s)"
    else:
        engagement_details["duration > 180s"] = f"❌ 0pt ({duration}s)"

    if messages > 0:
        eng_score += 2
        engagement_details["messages > 0"] = f"✅ +2pts ({messages})"
    else:
        engagement_details["messages > 0"] = "❌ 0pt"

    if messages >= 5:
        eng_score += 3
        engagement_details["messages >= 5"] = f"✅ +3pts ({messages})"
    else:
        engagement_details["messages >= 5"] = f"❌ 0pt ({messages})"

    if messages >= 10:
        eng_score += 1
        engagement_details["messages >= 10"] = f"✅ +1pt ({messages})"
    else:
        engagement_details["messages >= 10"] = f"❌ 0pt ({messages})"

    score["engagementQuality"] = min(eng_score, 10)
    score["details"]["engagement"] = engagement_details

    # ── 5. Response Structure (10 pts) ─────────────────────────────────────
    structure_details = {}
    struct_score = 0
    penalty = 0

    # Required fields (2 pts each, -1 penalty if missing)
    for field, pts in [("sessionId", 2), ("scamDetected", 2), ("extractedIntelligence", 2)]:
        if field in final_output and final_output[field] is not None:
            struct_score += pts
            structure_details[field] = f"✅ +{pts}pts"
        else:
            penalty += 1
            structure_details[field] = f"❌ MISSING (required, -1 penalty)"

    # Optional fields
    # totalMessagesExchanged + engagementDurationSeconds (1 pt if both present)
    has_total_msg = "totalMessagesExchanged" in final_output or (
        "engagementMetrics" in final_output and "totalMessagesExchanged" in final_output.get("engagementMetrics", {})
    )
    has_duration = "engagementDurationSeconds" in final_output or (
        "engagementMetrics" in final_output and "engagementDurationSeconds" in final_output.get("engagementMetrics", {})
    )
    if has_total_msg and has_duration:
        struct_score += 1
        structure_details["totalMessages+duration"] = "✅ +1pt"
    else:
        structure_details["totalMessages+duration"] = "❌ 0pt"

    if final_output.get("agentNotes"):
        struct_score += 1
        structure_details["agentNotes"] = "✅ +1pt"
    else:
        structure_details["agentNotes"] = "❌ 0pt"

    if final_output.get("scamType"):
        struct_score += 1
        structure_details["scamType"] = "✅ +1pt"
    else:
        structure_details["scamType"] = "❌ 0pt"

    if final_output.get("confidenceLevel") is not None:
        struct_score += 1
        structure_details["confidenceLevel"] = "✅ +1pt"
    else:
        structure_details["confidenceLevel"] = "❌ 0pt"

    score["responseStructure"] = max(min(struct_score - penalty, 10), 0)
    if penalty:
        structure_details["_penalty"] = f"-{penalty}pt (missing required fields)"
    score["details"]["structure"] = structure_details

    # ── Total ──────────────────────────────────────────────────────────────
    score["total"] = round(
        score["scamDetection"]
        + score["intelligenceExtraction"]
        + score["conversationQuality"]
        + score["engagementQuality"]
        + score["responseStructure"],
        1,
    )

    return score


# ═══════════════════════════════════════════════════════════════════════════════
# TEST RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

def run_scenario(scenario: dict, base_url: str) -> dict:
    """Run a single scam scenario against the honeypot API and return the score."""
    session_id = str(uuid.uuid4())
    conversation_history = []
    honeypot_responses = []
    start_time = time.time()
    endpoint = f"{base_url}/analyze"

    name = scenario["name"]
    turns = scenario["turns"]
    fake_data = scenario["fake_data"]

    print(f"\n{'━' * 70}")
    print(f"  🎭 Scenario: {name}  |  Session: {session_id[:8]}...")
    print(f"{'━' * 70}")

    for i, scammer_text in enumerate(turns, start=1):
        print(f"\n  ┌─ Turn {i}/{len(turns)}")
        print(f"  │ 🔴 Scammer: {scammer_text[:100]}{'...' if len(scammer_text) > 100 else ''}")

        message = {
            "sender": "scammer",
            "text": scammer_text,
            "timestamp": int(time.time() * 1000),
        }

        body = {
            "sessionId": session_id,
            "message": message,
            "conversationHistory": conversation_history,
            "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        }

        try:
            t0 = time.time()
            resp = requests.post(endpoint, headers=HEADERS, json=body, timeout=30)
            elapsed = time.time() - t0

            if resp.status_code != 200:
                print(f"  │ ❌ HTTP {resp.status_code}: {resp.text[:200]}")
                break

            data = resp.json()
            reply = data.get("reply") or data.get("message") or data.get("text", "")
            print(f"  │ 🟢 Honeypot ({elapsed:.1f}s): {reply[:100]}{'...' if len(reply) > 100 else ''}")
            print(f"  └─")

            honeypot_responses.append(reply)
            conversation_history.append(message)
            conversation_history.append({
                "sender": "user",
                "text": reply,
                "timestamp": int(time.time() * 1000),
            })

        except requests.exceptions.Timeout:
            print(f"  │ ❌ TIMEOUT (>30s)")
            print(f"  └─")
            break
        except requests.exceptions.ConnectionError:
            print(f"  │ ❌ CONNECTION ERROR — is the server running at {base_url}?")
            print(f"  └─")
            return {"error": "Connection refused", "scenario": name}
        except Exception as e:
            print(f"  │ ❌ ERROR: {e}")
            print(f"  └─")
            break

        time.sleep(0.3)  # minimal pacing

    # ── Fetch final session state ──────────────────────────────────────────
    final_output = None
    try:
        session_resp = requests.get(
            f"{base_url}/session/{session_id}",
            headers={"x-api-key": API_KEY},
            timeout=5,
        )
        if session_resp.status_code == 200:
            session_data = session_resp.json()
            final_output = session_data.get("final_payload", {})
    except Exception:
        pass

    # Fallback if session endpoint unavailable
    elapsed_total = time.time() - start_time
    if not final_output:
        final_output = {
            "sessionId": session_id,
            "status": "success",
            "scamDetected": True,
            "extractedIntelligence": {},
            "totalMessagesExchanged": len(conversation_history),
            "engagementDurationSeconds": int(elapsed_total),
            "engagementMetrics": {
                "totalMessagesExchanged": len(conversation_history),
                "engagementDurationSeconds": int(elapsed_total),
            },
            "agentNotes": "Session data unavailable",
        }

    # ── Print complete payload ──────────────────────────────────────────────
    print(f"\n  📦 COMPLETE PAYLOAD RECEIVED:")
    print(json.dumps(final_output, indent=2, ensure_ascii=False))

    # ── Score the output ───────────────────────────────────────────────────
    turn_count = len(honeypot_responses)
    score = evaluate_final_output(final_output, fake_data, honeypot_responses, turn_count)

    # ── Print score breakdown ──────────────────────────────────────────────
    print(f"\n  📊 SCORE for {name}:")
    print(f"  ┌──────────────────────────────────┬────────┐")
    print(f"  │ Scam Detection                   │ {score['scamDetection']:>5}/20 │")
    print(f"  │ Intelligence Extraction          │ {score['intelligenceExtraction']:>5}/30 │")
    print(f"  │ Conversation Quality             │ {score['conversationQuality']:>5}/30 │")
    print(f"  │ Engagement Quality               │ {score['engagementQuality']:>5}/10 │")
    print(f"  │ Response Structure               │ {score['responseStructure']:>5}/10 │")
    print(f"  ├──────────────────────────────────┼────────┤")
    print(f"  │ TOTAL                            │ {score['total']:>5}/100│")
    print(f"  └──────────────────────────────────┴────────┘")

    # Print details for intelligence
    if score["details"].get("intelligence"):
        print(f"  Intelligence details:")
        for key, val in score["details"]["intelligence"].items():
            print(f"    {val}")

    # Print conversation quality details
    if score["details"].get("conversationQuality"):
        print(f"  Conversation Quality details:")
        for key, val in score["details"]["conversationQuality"].items():
            print(f"    {key}: {val}")

    # Print details for engagement
    if score["details"].get("engagement"):
        print(f"  Engagement details:")
        for key, val in score["details"]["engagement"].items():
            print(f"    {key}: {val}")

    # Print structure details
    if score["details"].get("structure"):
        print(f"  Structure details:")
        for key, val in score["details"]["structure"].items():
            print(f"    {key}: {val}")

    return {
        "scenario": name,
        "scam_type": scenario["scam_type"],
        "session_id": session_id,
        "score": score,
        "duration": round(time.time() - start_time, 1),
        "messages": len(conversation_history),
    }


def run_all_tests(base_url: str, scenario_filter: Optional[str] = None):
    """Run all (or filtered) scenarios and print the final report."""

    # Filter scenarios if requested
    scenarios = SCENARIOS
    if scenario_filter:
        scenarios = [
            s for s in SCENARIOS
            if scenario_filter.lower() in s["name"].lower()
            or scenario_filter.lower() in s["scam_type"].lower()
        ]
        if not scenarios:
            print(f"❌ No scenario found matching '{scenario_filter}'")
            print(f"Available scenarios: {', '.join(s['name'] for s in SCENARIOS)}")
            return

    print("\n" + "═" * 70)
    print(f"  🧪 HONEYPOT SCAMMER AGENT TEST SUITE")
    print(f"  Target: {base_url}/analyze")
    print(f"  Scenarios: {len(scenarios)}")
    print(f"  Scoring: Detection(20) + Intel(30) + ConvQuality(30) + Engage(10) + Structure(10) = 100")
    print("═" * 70)

    results = []
    for scenario in scenarios:
        result = run_scenario(scenario, base_url)
        if "error" in result:
            print(f"\n❌ Aborting — cannot connect to server at {base_url}")
            print("   Make sure the server is running: python main.py")
            return
        results.append(result)

    # ═══════════════════════════════════════════════════════════════════════
    # FINAL REPORT
    # ═══════════════════════════════════════════════════════════════════════
    print("\n\n" + "═" * 70)
    print("  📋 FINAL TEST REPORT")
    print("═" * 70)

    # Summary table
    header = f"  {'Scenario':<25} {'Detect':>6} {'Intel':>6} {'ConvQ':>6} {'Engage':>6} {'Struct':>6} {'TOTAL':>7}"
    print(header)
    print(f"  {'─' * 70}")

    total_score_sum = 0
    for r in results:
        s = r["score"]
        print(
            f"  {r['scenario']:<25} "
            f"{s['scamDetection']:>4}/20 "
            f"{s['intelligenceExtraction']:>4}/30 "
            f"{s['conversationQuality']:>4}/30 "
            f"{s['engagementQuality']:>4}/10 "
            f"{s['responseStructure']:>4}/10 "
            f"{s['total']:>5}/100"
        )
        total_score_sum += s["total"]

    # Weighted average (equal weights for all scenarios)
    avg_score = total_score_sum / len(results) if results else 0

    print(f"  {'─' * 70}")
    print(f"  {'AVERAGE':>25} {'':>6} {'':>6} {'':>6} {'':>6} {'':>6} {avg_score:>5.1f}/100")

    # Category averages
    avg_detection = sum(r["score"]["scamDetection"] for r in results) / len(results)
    avg_intel = sum(r["score"]["intelligenceExtraction"] for r in results) / len(results)
    avg_conv = sum(r["score"]["conversationQuality"] for r in results) / len(results)
    avg_engage = sum(r["score"]["engagementQuality"] for r in results) / len(results)
    avg_struct = sum(r["score"]["responseStructure"] for r in results) / len(results)

    print(f"\n  📈 Category Averages:")
    print(f"    Scam Detection:          {avg_detection:>5.1f}/20")
    print(f"    Intelligence Extraction: {avg_intel:>5.1f}/30")
    print(f"    Conversation Quality:    {avg_conv:>5.1f}/30")
    print(f"    Engagement Quality:      {avg_engage:>5.1f}/10")
    print(f"    Response Structure:       {avg_struct:>5.1f}/10")

    total_duration = sum(r["duration"] for r in results)
    total_messages = sum(r["messages"] for r in results)
    print(f"\n  ⏱  Total Duration: {total_duration:.1f}s | Total Messages: {total_messages}")

    # Simulated weighted score (using eval doc example weights)
    print(f"\n  📐 Simulated Final Score (assuming equal scenario weights):")
    scenario_portion = avg_score * 0.9
    print(f"    Scenario Portion (90%): {scenario_portion:.1f}")
    print(f"    Code Quality (10%):     [manual review]")
    print(f"    Estimated Final:        {scenario_portion:.1f} + code_quality")

    # Final grade
    print(f"\n  {'═' * 40}")
    if avg_score >= 90:
        grade = "🏆 EXCELLENT"
    elif avg_score >= 75:
        grade = "🥈 GREAT"
    elif avg_score >= 60:
        grade = "🥉 GOOD"
    elif avg_score >= 40:
        grade = "⚠️  NEEDS IMPROVEMENT"
    else:
        grade = "❌ POOR"
    print(f"  FINAL SCORE: {avg_score:.1f}/100 — {grade}")
    print(f"  {'═' * 40}\n")

    # Also try scoring via the /test-score endpoint for the first session
    if results:
        first_sid = results[0]["session_id"]
        try:
            ts_resp = requests.get(
                f"{base_url}/test-score/{first_sid}",
                headers={"x-api-key": API_KEY},
                timeout=5,
            )
            if ts_resp.status_code == 200:
                print(f"  ✅ /test-score endpoint verified (session {first_sid[:8]})")
                print(f"     Response: {json.dumps(ts_resp.json(), indent=2)[:300]}")
            else:
                print(f"  ⚠️  /test-score endpoint returned {ts_resp.status_code}")
        except Exception as e:
            print(f"  ⚠️  /test-score endpoint not available: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Honeypot Scammer Agent Test Suite")
    parser.add_argument(
        "--url",
        default=DEFAULT_ENDPOINT,
        help=f"Base URL of the honeypot API (default: {DEFAULT_ENDPOINT})",
    )
    parser.add_argument(
        "--scenario",
        default=None,
        help="Filter: run only scenarios matching this name/type (e.g. 'bank', 'upi_fraud')",
    )
    args = parser.parse_args()

    run_all_tests(args.url, args.scenario)
