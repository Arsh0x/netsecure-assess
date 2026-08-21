from dataclasses import dataclass


SEVERITY_WEIGHT = {"informational": 5, "low": 20, "medium": 45, "high": 75, "critical": 100}


@dataclass
class RiskResult:
    score: float
    rating: str
    factors: dict[str, float]
    formula: str


def risk_rating(score: float) -> str:
    if score <= 20:
        return "Low"
    if score <= 40:
        return "Moderate"
    if score <= 60:
        return "Elevated"
    if score <= 80:
        return "High"
    return "Critical"


def calculate_risk(
    severity: str,
    confidence: int,
    asset_criticality: int = 3,
    exposure: int = 3,
    likelihood: int = 3,
    business_impact: int = 3,
    existing_controls: int = 2,
    remediation_status: str = "open",
) -> RiskResult:
    factors = {
        "technical_severity": SEVERITY_WEIGHT[severity] * 0.30,
        "confidence": max(0, min(confidence, 100)) * 0.10,
        "asset_criticality": max(1, min(asset_criticality, 5)) * 20 * 0.15,
        "exposure": max(1, min(exposure, 5)) * 20 * 0.10,
        "likelihood": max(1, min(likelihood, 5)) * 20 * 0.10,
        "business_impact": max(1, min(business_impact, 5)) * 20 * 0.15,
    }
    control_reduction = max(0, min(existing_controls, 5)) * 3
    status_reduction = {"open": 0, "acknowledged": 2, "in_progress": 8, "resolved": 35, "accepted_risk": 0}.get(remediation_status, 0)
    factors["control_reduction"] = -control_reduction
    factors["remediation_reduction"] = -status_reduction
    positive = sum(value for value in factors.values() if value > 0)
    reductions = sum(value for value in factors.values() if value < 0)
    score = round(max(0, min(100, positive / 0.9 + reductions)), 1)
    return RiskResult(score, risk_rating(score), factors, "weighted factors normalized to 100, minus existing-control and remediation reductions")


def assessment_scores(responses: list[str]) -> dict:
    weights = {"implemented": 1.0, "partially_implemented": 0.5, "not_implemented": 0.0, "not_reviewed": 0.0}
    applicable = [response for response in responses if response != "not_applicable"]
    if not applicable:
        score = 0.0
    else:
        score = round(sum(weights.get(response, 0) for response in applicable) / len(applicable) * 100, 1)
    return {
        "score": score,
        "maturity_score": round(score / 20, 2),
        "residual_risk": round(100 - score, 1),
        "open_gaps": sum(response in {"not_implemented", "not_reviewed"} for response in applicable),
        "formula": "Implemented=100%, Partial=50%, Not implemented/Not reviewed=0%; N/A controls are excluded.",
    }
