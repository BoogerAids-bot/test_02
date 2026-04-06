def rule_based_score(event: dict, rules: list):
    score = 0
    reasons = []

    app_name = str(event.get("app_name", ""))
    domain = str(event.get("domain", ""))
    port = int(event.get("port", 0))
    is_known_bad_ip = int(event.get("is_known_bad_ip", 0))
    untrusted_file = int(event.get("untrusted_file", 0))
    privilege_request = int(event.get("privilege_request", 0))
    child_process_spawn = int(event.get("child_process_spawn", 0))
    sensitive_file_access = int(event.get("sensitive_file_access", 0))
    request_count = int(event.get("request_count", 0))
    failed_logins = int(event.get("failed_logins", 0))
    action = str(event.get("action", ""))

    # Static risk logic
    if is_known_bad_ip == 1:
        score += 80
        reasons.append("Destination or source matched known malicious IP intelligence")

    if failed_logins >= 5:
        score += 30
        reasons.append("Too many failed login attempts detected")

    if request_count > 100:
        score += 25
        reasons.append("Abnormally high request count detected")

    if untrusted_file == 1:
        score += 25
        reasons.append("Action involves untrusted file or download")

    if privilege_request == 1:
        score += 35
        reasons.append("Privilege escalation attempt detected")

    if child_process_spawn == 1:
        score += 30
        reasons.append("Unexpected child process spawned by application")

    if sensitive_file_access == 1:
        score += 35
        reasons.append("Sensitive file access attempt detected")

    if action == "download_file" and untrusted_file == 1:
        score += 20
        reasons.append("Executable or risky file download from untrusted source")

    # JSON rule checks
    for rule in rules:
        if not rule.get("enabled", True):
            continue

        rule_type = rule.get("type")
        rule_value = rule.get("value")

        if rule_type == "block_domain" and domain == rule_value:
            score += 90
            reasons.append(f"Domain is blocked by policy: {domain}")

        elif rule_type == "block_port" and port == int(rule_value):
            score += 70
            reasons.append(f"Port is blocked by policy: {port}")

        elif rule_type == "restricted_app" and app_name == rule_value:
            score += 40
            reasons.append(f"Application is under restricted monitoring: {app_name}")

        elif rule_type == "restricted_action" and action == rule_value:
            score += 30
            reasons.append(f"Action is flagged by security policy: {action}")

    return score, reasons