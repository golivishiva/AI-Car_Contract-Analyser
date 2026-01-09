# summarization.py
"""
Wrappers to call Groq (Chat Completions) for:
1) Summarization
2) Negotiation / reasoning

Requires:
- requests
- python-dotenv
- groq (pip install groq)

Set GROQ_API_KEY in .env or environment variables.
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


# ======================================================
# 1) EXISTING FUNCTION — DO NOT REMOVE
# ======================================================
def summarize_with_groq(text: str) -> str:
    """
    Send text to Groq API and return a short clear summary string.
    """
    if not text or not text.strip():
        return "No text found to summarize."

    if not GROQ_API_KEY:
        return "GROQ_API_KEY is missing. Check your .env file."

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {
                "role": "system",
                "content": "You are a helpful assistant that summarizes legal and contract text clearly."
            },
            {
                "role": "user",
                "content": f"Summarize the following contract text in a concise, human-readable way:\n\n{text}"
            }
        ],
        "temperature": 0.2,
        "max_tokens": 512
    }

    try:
        resp = requests.post(GROQ_URL, headers=headers, json=payload, timeout=60)
        data = resp.json()
    except Exception as e:
        return f"Groq request failed: {e}"

    if "choices" in data and data["choices"]:
        return data["choices"][0]["message"]["content"].strip()

    return f"Groq Error: {data}"


# ======================================================
# 2) STEP 4 — NEGOTIATION CALL (NEW)
# ======================================================
def negotiate_with_groq(prompt: str) -> str:
    """
    Call Groq for negotiation / reasoning style answers.
    Uses Groq Python SDK.
    """
    if not prompt or not prompt.strip():
        return "No prompt provided."

    if not GROQ_API_KEY:
        return "GROQ_API_KEY is missing. Check your .env file."

    try:
        from groq import Groq
    except ImportError:
        return "Groq SDK not installed. Run: pip install groq"

    try:
        client = Groq(api_key=GROQ_API_KEY)

        resp = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert car lease and loan negotiation assistant."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.4,
            max_tokens=800
        )

        return resp.choices[0].message.content.strip()

    except Exception as e:
        return f"Negotiation AI error: {e}"
