from datetime import datetime, timedelta


def request_override(user_verified: bool, feature_name: str) -> dict:
    if not user_verified:
        return {
            "approved": False,
            "message": "Override denied: verification failed."
        }

    start_time = datetime.now()
    end_time = start_time + timedelta(minutes=10)

    return {
        "approved": True,
        "feature": feature_name,
        "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "end_time": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "message": f"Temporary restricted access granted for '{feature_name}' until {end_time.strftime('%Y-%m-%d %H:%M:%S')}"
    }