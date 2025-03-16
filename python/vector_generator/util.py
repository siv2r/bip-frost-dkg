import json

def write_json(filename: str, data: dict):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)