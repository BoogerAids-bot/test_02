def generate_explanation(decision: str, reasons: list[str], ai_score: int, event: dict) -> str:
    parts = [f"Decision: {decision}"]

    app_name = event.get("app_name", "UnknownApp")
    action = event.get("action", "unknown_action")
    domain = event.get("domain", "unknown-domain")

    parts.append(f"Application: {app_name}")
    parts.append(f"Action: {action}")
    parts.append(f"Target Domain: {domain}")

    if reasons:
        parts.append("Reasons:")
        for reason in reasons:
            parts.append(f"- {reason}")

    if ai_score > 0:
        parts.append("- AI anomaly detector found unusual behavior")

    if decision == "BLOCK":
        parts.append("Action blocked due to high risk.")
        parts.append("Recommended next step: review the domain, file trust, and privilege request before retrying.")
    elif decision == "VERIFY":
        parts.append("User verification is required for temporary restricted access.")
        parts.append("Only limited, short-term access should be granted after verification.")
    elif decision == "WARN":
        parts.append("Action allowed with warning and monitoring.")
    elif decision == "ALLOW":
        if reasons or ai_score > 0:
            parts.append("Action allowed, but the event is logged for observation.")
        else:
            parts.append("Activity appears normal.")

    return "\n".join(parts)