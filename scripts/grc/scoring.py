"""Transparent 5x5 qualitative risk scoring."""

from typing import Dict, Tuple


def calculate_risk_score(likelihood: int, impact: int) -> Tuple[int, str]:
    """Return (score, level) using a 1..5 likelihood x 1..5 impact matrix."""
    if not 1 <= likelihood <= 5:
        raise ValueError("likelihood must be between 1 and 5")
    if not 1 <= impact <= 5:
        raise ValueError("impact must be between 1 and 5")

    score = likelihood * impact
    if score <= 4:
        level = "Low"
    elif score <= 9:
        level = "Medium"
    elif score <= 16:
        level = "High"
    else:
        level = "Critical"
    return score, level


def score_payload(likelihood: int, impact: int) -> Dict[str, object]:
    score, level = calculate_risk_score(likelihood, impact)
    return {"score": score, "level": level}
