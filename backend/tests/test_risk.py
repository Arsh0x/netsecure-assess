from app.services.risk import assessment_scores, calculate_risk


def test_risk_is_bounded_and_transparent():
    result = calculate_risk("critical", 100, 5, 5, 5, 5, 0, "open")
    assert result.score == 100
    assert result.rating == "Critical"
    assert "technical_severity" in result.factors


def test_controls_and_remediation_reduce_risk():
    open_risk = calculate_risk("high", 90, remediation_status="open", existing_controls=0)
    resolved_risk = calculate_risk("high", 90, remediation_status="resolved", existing_controls=5)
    assert resolved_risk.score < open_risk.score


def test_assessment_formula_excludes_not_applicable():
    score = assessment_scores(["implemented", "partially_implemented", "not_implemented", "not_applicable"])
    assert score["score"] == 50.0
    assert score["open_gaps"] == 1

