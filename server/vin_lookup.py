# vin_lookup.py
import requests

NHTSA_DECODE_URL = "https://vpic.nhtsa.dot.gov/api/vehicles/decodevinvalues/{vin}?format=json"


def decode_vin_nhtsa(vin: str) -> dict:
    """
    Decode VIN via NHTSA vPIC. Returns a dict with useful vehicle fields.
    No API key required.
    """
    vin = (vin or "").strip().upper()
    if not vin or len(vin) != 17:
        return {"error": "VIN must be 17 characters."}

    url = NHTSA_DECODE_URL.format(vin=vin)
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = r.json()
        results = data.get("Results", [])
        if not results:
            return {"error": "No decode results from NHTSA."}
        info = results[0]

        # pick useful keys (fallback to "Not found")
        fields = {
            "VIN": vin,
            "Make": info.get("Make") or "Not found",
            "Model": info.get("Model") or "Not found",
            "ModelYear": info.get("ModelYear") or "Not found",
            "Trim": info.get("Trim") or "Not found",
            "BodyClass": info.get("BodyClass") or "Not found",
            "EngineModel": info.get("EngineModel") or "Not found",
            "Manufacturer": info.get("Manufacturer") or "Not found",
            "PlantCountry": info.get("PlantCountry") or "Not found",
            "ErrorCode": info.get("ErrorCode") or None
        }
        return {"success": True, "data": fields}
    except Exception as e:
        return {"error": f"NHTSA request failed: {e}"}
