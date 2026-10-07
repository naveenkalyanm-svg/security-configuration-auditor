def calculate_risk(finding):
    severity = finding.get("severity", "Low").lower()

    risk_scores = {
        "critical": 10,
        "high": 8,
        "medium": 5,
        "low": 2
    }

    score = risk_scores.get(severity, 0)

    if score >= 8:
        risk = "High"
    elif score >= 5:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "score": score,
        "risk": risk
    }