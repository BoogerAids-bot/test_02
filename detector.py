import pandas as pd
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.25, random_state=42)
        self.feature_columns = [
            "port",
            "failed_logins",
            "request_count",
            "is_known_bad_ip",
            "untrusted_file",
            "privilege_request",
            "child_process_spawn",
            "sensitive_file_access"
        ]

    def train(self, df: pd.DataFrame):
        X = df[self.feature_columns]
        self.model.fit(X)

    def predict_risk(self, event: dict) -> int:
        sample = pd.DataFrame([event])[self.feature_columns]
        result = self.model.predict(sample)[0]
        return 40 if result == -1 else 0