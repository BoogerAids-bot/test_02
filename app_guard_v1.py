import pandas as pd
from rules import rule_based_score
from detector import AnomalyDetector
from decision import make_decision
from explain import generate_explanation
from override import request_override
from rule_loader import load_rules


def main():
    df = pd.read_csv("data/app_events.csv")
    rules = load_rules("data/rules.json")

    detector = AnomalyDetector()
    detector.train(df)

    with open("app_guard_log.txt", "w") as log_file:
        log_file.write("Adaptive App Guard Log\n")
        log_file.write("=" * 70 + "\n")

    print("=" * 70)
    print("Adaptive App Guard - Browser/App Protection Prototype")
    print("=" * 70)

    event_number = 1

    for _, row in df.iterrows():
        event = row.to_dict()

        rule_score, reasons = rule_based_score(event, rules)
        ai_score = detector.predict_risk(event)
        total_score = rule_score + ai_score

        decision = make_decision(total_score)
        explanation = generate_explanation(decision, reasons, ai_score, event)

        print(f"\nEvent #{event_number}")
        print("Event Data:", event)
        print(f"Rule Score: {rule_score}")
        print(f"AI Score: {ai_score}")
        print(f"Total Score: {total_score}")
        print(explanation)

        with open("app_guard_log.txt", "a") as log_file:
            log_file.write(f"\nEvent #{event_number}\n")
            log_file.write("Event Data:\n")
            log_file.write(str(event) + "\n")
            log_file.write(f"Rule Score: {rule_score}\n")
            log_file.write(f"AI Score: {ai_score}\n")
            log_file.write(f"Total Score: {total_score}\n")
            log_file.write(explanation + "\n")

        if decision == "VERIFY":
            print("\nTrying temporary override...")
            override_result = request_override(
                user_verified=True,
                feature_name=event.get("action", "restricted_action")
            )
            print(override_result["message"])

            with open("app_guard_log.txt", "a") as log_file:
                log_file.write("Override Attempt:\n")
                log_file.write(override_result["message"] + "\n")

        with open("app_guard_log.txt", "a") as log_file:
            log_file.write("-" * 70 + "\n")

        event_number += 1


if __name__ == "__main__":
    main()