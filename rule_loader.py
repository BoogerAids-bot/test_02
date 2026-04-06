import json


def load_rules(path="data/rules.json"):
    with open(path, "r") as file:
        return json.load(file)