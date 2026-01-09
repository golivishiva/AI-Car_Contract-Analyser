def calculate_fairness_score(
    apr=None,
    monthly_payment=None,
    market_monthly=None,
    vehicle_price=None,
    market_price=None,
    penalties_count=0,
    mileage=None
):
    score = 0
    breakdown = {}

    # 1. APR
    if apr is not None:
        if apr <= 6:
            breakdown["apr"] = 25
        elif apr <= 9:
            breakdown["apr"] = 18
        elif apr <= 12:
            breakdown["apr"] = 10
        else:
            breakdown["apr"] = 5
    else:
        breakdown["apr"] = 10
    score += breakdown["apr"]

    # 2. Monthly payment
    if monthly_payment and market_monthly:
        if monthly_payment <= market_monthly:
            breakdown["monthly_payment"] = 20
        elif monthly_payment <= market_monthly * 1.1:
            breakdown["monthly_payment"] = 12
        else:
            breakdown["monthly_payment"] = 5
    else:
        breakdown["monthly_payment"] = 10
    score += breakdown["monthly_payment"]

    # 3. Vehicle price
    if vehicle_price and market_price:
        if vehicle_price < market_price:
            breakdown["vehicle_price"] = 25
        elif abs(vehicle_price - market_price) <= market_price * 0.05:
            breakdown["vehicle_price"] = 18
        else:
            breakdown["vehicle_price"] = 8
    else:
        breakdown["vehicle_price"] = 12
    score += breakdown["vehicle_price"]

    # 4. Penalties
    if penalties_count == 0:
        breakdown["penalties"] = 20
    elif penalties_count <= 2:
        breakdown["penalties"] = 10
    else:
        breakdown["penalties"] = 3
    score += breakdown["penalties"]

    # 5. Mileage
    if mileage:
        if mileage >= 15000:
            breakdown["mileage"] = 10
        elif mileage >= 10000:
            breakdown["mileage"] = 6
        else:
            breakdown["mileage"] = 3
    else:
        breakdown["mileage"] = 5
    score += breakdown["mileage"]

    return {
        "fairness_score": score,
        "breakdown": breakdown,
        "verdict": (
            "Excellent Deal" if score >= 80 else
            "Fair Deal" if score >= 60 else
            "Risky Deal"
        )
    }
