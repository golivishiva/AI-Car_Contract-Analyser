# price_estimator.py
"""
Price estimator with VehicleDatabases.com integration (preferred), MarketCheck fallback, heuristic fallback.

Env variables used:
 - VEHICLEDATABASES_KEY  (preferred)
 - MARKETCHECK_API_KEY   (optional fallback)
If none exist, uses heuristic.

VehicleDatabases endpoints (docs):
 - GET https://api.vehicledatabases.com/market-value/v2/{vin}?state={state}&mileage={mileage}
 - GET https://api.vehicledatabases.com/market-value/ymm/{year}/{make}/{model}?state={state}&mileage={mileage}
Header: x-AuthKey: <KEY>

Docs: VehicleDatabases (market-value API). See docs for response examples.
"""
import os
import statistics
import requests
from datetime import datetime

# VehicleDatabases endpoints (v2)
VD_VIN_URL = "https://api.vehicledatabases.com/market-value/v2/{vin}"
VD_YMM_URL = "https://api.vehicledatabases.com/market-value/ymm/{year}/{make}/{model}"

# MarketCheck v1 search (optional fallback)
MARKETCHECK_SEARCH_URL = "https://api.marketcheck.com/v1/search"

# Heuristic anchors
BASE_PRICE_BY_BODY = {
    "sedan": 30000.0, "coupe": 32000.0, "hatchback": 22000.0,
    "suv": 40000.0, "truck": 45000.0, "van": 35000.0,
    "wagon": 30000.0, "motorcycle": 12000.0, "unknown": 30000.0
}


def _normalize_body_class(body: str) -> str:
    if not body:
        return "unknown"
    b = body.lower()
    if "coupe" in b: return "coupe"
    if "suv" in b or "crossover" in b: return "suv"
    if "truck" in b or "pickup" in b: return "truck"
    if "van" in b or "minivan" in b: return "van"
    if "hatch" in b: return "hatchback"
    if "wagon" in b: return "wagon"
    if "motorcycle" in b or "motorbike" in b: return "motorcycle"
    if "sedan" in b or "car" in b: return "sedan"
    return "unknown"


# ---------------- VehicleDatabases integration ----------------
def fetch_vehicledb_by_vin(vin: str, state: str = None, mileage: int = None, key: str = None, timeout: int = 30):
    """
    Query VehicleDatabases market-value by VIN.
    Returns dict with keys:
      - available: bool
      - data: parsed market values or raw response
      - reason: message on failure
    """
    if not key:
        return {"available": False, "reason": "No VehicleDatabases key provided."}

    url = VD_VIN_URL.format(vin=vin)
    params = {}
    if state:
        params["state"] = state
    if mileage is not None:
        params["mileage"] = int(mileage)

    headers = {"x-AuthKey": key, "Accept": "application/json"}

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        # docs show shape: {"status":"success","data":{ "basic":..., "market_value": {"market_value_data":[{ "trim":..., "market value":[ {Condition, Trade-In, Private Party, Dealer Retail}, ... ]}]}}}
        if not isinstance(data, dict) or data.get("status") != "success":
            return {"available": False, "reason": "VehicleDatabases returned error", "raw": data}

        d = data.get("data", {})
        mv = d.get("market_value", {}).get("market_value_data", [])
        # Build a clean output: { "conditions": {...}, "trim": ..., "basic": {...} }
        out = {"basic": d.get("basic", {}), "trim_values": []}
        for item in mv:
            trim = item.get("trim", "")
            cond_list = item.get("market value") or item.get("market_value") or []
            parsed_conditions = {}
            for cond in cond_list:
                # cond expected to have keys like Condition, Trade-In, Private Party, Dealer Retail (strings with $)
                condition_name = cond.get("Condition") or cond.get("condition") or "Unknown"
                # parse numeric values
                def _parse_money(v):
                    if not v: 
                        return None
                    try:
                        return float(str(v).replace("$","").replace(",","").strip())
                    except Exception:
                        return None
                parsed_conditions[condition_name] = {
                    "trade_in": _parse_money(cond.get("Trade-In") or cond.get("TradeIn") or cond.get("trade_in")),
                    "private_party": _parse_money(cond.get("Private Party") or cond.get("PrivateParty") or cond.get("private_party")),
                    "dealer_retail": _parse_money(cond.get("Dealer Retail") or cond.get("DealerRetail") or cond.get("dealer_retail"))
                }
            out["trim_values"].append({"trim": trim, "conditions": parsed_conditions})
        return {"available": True, "source": "vehicledatabases", "data": out}
    except requests.exceptions.Timeout:
        return {"available": False, "reason": f"VehicleDatabases request timed out (timeout={timeout}s)"}
    except requests.exceptions.HTTPError as he:
        return {"available": False, "reason": f"VehicleDatabases HTTP error: {he}", "status_code": getattr(he.response, "status_code", None)}
    except Exception as e:
        return {"available": False, "reason": f"VehicleDatabases request failed: {e}"}


def fetch_vehicledb_by_ymm(year: str, make: str, model: str, state: str = None, mileage: int = None, key: str = None, timeout: int = 30):
    """YMM endpoint fallback when VIN not available."""
    if not key:
        return {"available": False, "reason": "No VehicleDatabases key provided."}
    url = VD_YMM_URL.format(year=year, make=make, model=model)
    params = {}
    if state:
        params["state"] = state
    if mileage is not None:
        params["mileage"] = int(mileage)
    headers = {"x-AuthKey": key, "Accept": "application/json"}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict) or data.get("status") != "success":
            return {"available": False, "reason": "VehicleDatabases returned error", "raw": data}
        # reuse parsing logic from VIN path
        d = data.get("data", {})
        mv = d.get("market_value", {}).get("market_value_data", [])
        out = {"basic": d.get("basic", {}), "trim_values": []}
        for item in mv:
            trim = item.get("trim", "")
            cond_list = item.get("market value") or item.get("market_value") or []
            parsed_conditions = {}
            for cond in cond_list:
                condition_name = cond.get("Condition") or cond.get("condition") or "Unknown"
                def _parse_money(v):
                    if not v: 
                        return None
                    try:
                        return float(str(v).replace("$","").replace(",","").strip())
                    except Exception:
                        return None
                parsed_conditions[condition_name] = {
                    "trade_in": _parse_money(cond.get("Trade-In") or cond.get("TradeIn") or cond.get("trade_in")),
                    "private_party": _parse_money(cond.get("Private Party") or cond.get("PrivateParty") or cond.get("private_party")),
                    "dealer_retail": _parse_money(cond.get("Dealer Retail") or cond.get("DealerRetail") or cond.get("dealer_retail"))
                }
            out["trim_values"].append({"trim": trim, "conditions": parsed_conditions})
        return {"available": True, "source": "vehicledatabases", "data": out}
    except Exception as e:
        return {"available": False, "reason": f"VehicleDatabases request failed: {e}"}


# ---------------- MarketCheck (kept as fallback) ----------------
def fetch_marketcheck(make: str, model: str, year: str, zip_code: str = "94103", marketcheck_key: str = None, timeout: int = 30):
    if not marketcheck_key:
        return {"available": False, "reason": "No MarketCheck API key provided."}
    params = {
        "api_key": marketcheck_key,
        "make": make or "",
        "model": model or "",
        "year": year or "",
        "zip": zip_code,
        "radius": 50,
        "rows": 100,
        "start": 0
    }
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    try:
        resp = requests.get(MARKETCHECK_SEARCH_URL, params=params, headers=headers, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        listings = []
        if isinstance(data, dict):
            for k in ("listings", "results", "cars", "data", "search_results"):
                if k in data and isinstance(data[k], list):
                    listings = data[k]
                    break
        if not listings and isinstance(data, list):
            listings = data
        prices = []
        for it in listings:
            if not isinstance(it, dict):
                continue
            p = it.get("price") or it.get("list_price") or it.get("sale_price") or it.get("price_usd")
            if not p:
                nested = it.get("vc") or it.get("vehicle") or {}
                if isinstance(nested, dict):
                    p = nested.get("price") or nested.get("list_price")
            if p is None:
                continue
            try:
                if isinstance(p, str):
                    p = float(p.replace("$", "").replace(",", "").strip())
                else:
                    p = float(p)
            except Exception:
                continue
            if p > 0:
                prices.append(p)
        if not prices:
            return {"available": False, "reason": "MarketCheck returned no numeric prices.", "raw": data}
        prices.sort()
        try:
            p25 = statistics.quantiles(prices, n=4)[0]
            p75 = statistics.quantiles(prices, n=4)[2]
        except Exception:
            n = len(prices)
            p25 = prices[max(0, int(n * 0.25) - 1)]
            p75 = prices[min(n - 1, int(n * 0.75) - 1)]
        median = statistics.median(prices)
        return {"available": True, "source": "marketcheck", "count": len(prices), "p25": round(p25,2), "median": round(median,2), "p75": round(p75,2), "sample": prices[:50]}
    except Exception as e:
        return {"available": False, "reason": f"MarketCheck request failed: {e}"}


# ---------------- Heuristic fallback ----------------
def heuristic_price_estimate(body_class: str, model_year: str):
    try:
        year = int(model_year)
    except Exception:
        year = datetime.now().year
    age = max(0, datetime.now().year - year)
    body = _normalize_body_class(body_class)
    base = BASE_PRICE_BY_BODY.get(body, BASE_PRICE_BY_BODY["unknown"])
    price = base * (0.85 * (0.9 ** max(0, age - 1))) if age > 0 else base
    lower = round(price * 0.88, 2)
    median = round(price, 2)
    upper = round(price * 1.12, 2)
    return {"method": "heuristic", "body_class": body, "age": age, "lower": lower, "median": median, "upper": upper, "note": "Fallback estimate (no provider configured)"}


# ---------------- High-level entrypoint ----------------
def estimate_price(make: str = None, model: str = None, year: str = None,
                   body_class: str = None, vin: str = None, state: str = None, mileage: int = None,
                   zip_code: str = "94103", env: dict = None):
    """
    Tries providers in order:
      1) VehicleDatabases (by VIN if provided, else YMM)
      2) MarketCheck if VEHICLEDATABASES not configured or returns no prices
      3) Heuristic fallback

    Returns a dict describing provider/data/fallbacks.
    """
    env = env or os.environ
    vd_key = env.get("VEHICLEDATABASES_KEY") or env.get("VEHICLEDATABASES_API_KEY")
    # 1) VehicleDatabases
    if vd_key and vin:
        vd = fetch_vehicledb_by_vin(vin=vin, state=state, mileage=mileage, key=vd_key, timeout=30)
        if vd.get("available"):
            # prefer Clean condition if available
            out = {"provider": "vehicledatabases", "data": vd["data"]}
            # attempt to extract Clean condition first (trade-in/private-party/dealer-retail)
            try:
                # get first trim
                tv = vd["data"].get("trim_values", [])
                if tv:
                    # choose first trim and pick Clean if present
                    conds = tv[0].get("conditions", {})
                    if "Clean" in conds:
                        clean = conds["Clean"]
                        out["summary"] = {"trade_in": clean.get("trade_in"), "private_party": clean.get("private_party"), "dealer_retail": clean.get("dealer_retail")}
                    else:
                        # if Clean missing, pick Outstanding->Average order fallback
                        for key in ("Outstanding","Average","Rough"):
                            if key in conds:
                                c = conds[key]
                                out["summary"] = {"trade_in": c.get("trade_in"), "private_party": c.get("private_party"), "dealer_retail": c.get("dealer_retail")}
                                break
            except Exception:
                pass
            return out
        # if VehicleDatabases attempted but failed, continue to MarketCheck below but include vd reason
        vd_reason = vd.get("reason")
    else:
        vd_reason = "No VehicleDatabases key or VIN not provided."

    # 2) MarketCheck fallback (if configured)
    mc_key = env.get("MARKETCHECK_API_KEY") or env.get("MARKETCHECK_KEY")
    if mc_key and make and model and year:
        mc = fetch_marketcheck(make=make, model=model, year=year, zip_code=zip_code, marketcheck_key=mc_key, timeout=60)
        if mc.get("available"):
            return {"provider": "marketcheck", "data": mc}
        else:
            # return marketcheck attempted with reason and include vd_reason if present
            fallback = heuristic_price_estimate(body_class or env.get("BODY_CLASS", "unknown"), year or datetime.now().year)
            return {"provider": "marketcheck", "data": mc, "vd_reason": vd_reason, "fallback": fallback}

    # 3) Heuristic fallback
    heuristic = heuristic_price_estimate(body_class or env.get("BODY_CLASS", "unknown"), year or datetime.now().year)
    return {"provider": "heuristic", "vd_reason": vd_reason, "data": heuristic}
