def make_decision(total_score: int) -> str:
    if total_score >= 120:
        return "BLOCK"
    elif total_score >= 70:
        return "VERIFY"
    elif total_score >= 35:
        return "WARN"
    return "ALLOW"