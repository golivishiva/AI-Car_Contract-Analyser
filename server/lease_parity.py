# lease_parity.py

def estimate_residual_value(market_price: float, residual_pct: float = 0.55):
    """
    Estimate residual value if not explicitly present.
    Default: 55% (industry average for 36-month leases)
    """
    if not market_price:
        return None
    return market_price * residual_pct


def calculate_market_monthly_lease(
    dealer_retail_price: float,
    lease_term_months: int,
    residual_value: float = None,
    residual_pct: float = 0.55
):
    """
    Calculate equivalent market monthly lease payment.
    """
    if not dealer_retail_price or not lease_term_months:
        return None

    if not residual_value:
        residual_value = estimate_residual_value(
            dealer_retail_price, residual_pct
        )

    monthly = (dealer_retail_price - residual_value) / lease_term_months
    return round(monthly, 2)
