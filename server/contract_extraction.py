# contract_extraction.py
import os
import requests
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")


def extract_sla_with_groq(text: str) -> dict:
    """
    Use Groq LLM to extract key SLA fields from a car lease/loan contract.
    Returns a Python dict.
    """
    if not text or not text.strip():
        return {"error": "No text found to analyze."}

    if not GROQ_API_KEY:
        return {"error": "GROQ_API_KEY is missing. Check your .env file."}

    url = "https://api.groq.com/openai/v1/chat/completions"

    # We force the model to return JSON ONLY
    system_prompt = """
You are an AI assistant that extracts structured data from car lease/loan contracts.

Given the contract text, you must extract the following fields:
- interest_rate_apr
- lease_term_duration
- monthly_payment
- down_payment
- residual_value
- mileage_allowance_and_overage
- early_termination_clause
- purchase_option_buyout_price
- maintenance_responsibilities
- warranty_and_insurance_coverage
- penalties_or_late_fee_clauses

Return your answer as **valid JSON only**, with exactly these keys.
If a field is not found, set its value to "Not found".
Do NOT add any explanation text outside the JSON.
"""

    user_prompt = f"Extract the requested fields from this contract:\n\n{text}"

    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,  # more consistent outputs
    }

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(url, headers=headers, json=payload)
        data = resp.json()
        print("FULL GROQ SLA RESPONSE:\n", data)

        if "choices" not in data or not data["choices"]:
            return {"error": f"Groq error: {data}"}

        content = data["choices"][0]["message"]["content"]

        # Safely parse JSON string to dict
        import json
        try:
            sla_dict = json.loads(content)
        except json.JSONDecodeError:
            # If model returned extra text, try to clean it
            first_brace = content.find("{")
            last_brace = content.rfind("}")
            if first_brace != -1 and last_brace != -1:
                try:
                    sla_dict = json.loads(content[first_brace:last_brace+1])
                except json.JSONDecodeError:
                    return {"error": "Failed to parse JSON from model response.", "raw": content}
            else:
                return {"error": "No JSON object found in model response.", "raw": content}

        return sla_dict

    except Exception as e:
        return {"error": f"SLA extraction failed: {e}"}
