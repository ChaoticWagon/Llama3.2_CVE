import os
import json

containers = None
cve_metadata = None
cve_id = None
affected_products = None
description = None
references = None
cve_state = None

def extract_json_data(filename):
    global containers, cve_metadata, cve_id, affected_products, description, references, cve_state

    with open(filename, "r", newline="", encoding="utf-8") as json_file:
        data = json.load(json_file)

    containers = data["containers"]
    cve_metadata = data["cveMetadata"]

    try:
        cna = containers["cna"]
    except KeyError:
        cna = "N\A"
    try:
        affected_products = cna["affected"][0]["product"]
    except KeyError:
        affected_products = "N\A"
    try:
        description = cna["descriptions"][0]["value"]
    except KeyError:
        description = "N\A"
    try:
        references = cna["references"]
    except KeyError:
        references = "N\A"
    try:
        cve_state = cve_metadata["state"]
    except KeyError:
        cve_state = "N\A"
    try:
        cve_id = cve_metadata["cveId"]
    except KeyError:
        cve_id = "N\A"

def write_json_entry(filename, human_input, assistant_response):
    global cve_id, affected_products, description, references, cve_state
    entry = {
        "messages": [
            {"role": "system", "content": "CVE Vulnerability Information"},
            {"role": "user", "content": human_input},
            {"role": "assistant", "content": assistant_response}
        ]
    }
    with open(filename, "a", newline="", encoding="utf-8") as json_file:
        json.dump(entry, json_file, ensure_ascii=False)
        json_file.write("\n")

def convert_jsonl_to_json(jsonl_filename, json_filename):
    json_data = []

    # Read data from JSONL file
    with open(jsonl_filename, "r", encoding="utf-8") as jsonl_file:
        for line in jsonl_file:
            entry = json.loads(line)
            json_data.append(entry)

    # Write data to JSON file
    with open(json_filename, "w", encoding="utf-8") as json_file:
        json.dump(json_data, json_file, ensure_ascii=False, indent=4)

def main():
    for year in range(1999, 2024):
        year_folder = f"cves/{year}"
        if os.path.exists(year_folder) and os.path.isdir(year_folder):
            for subfolder in ["0xxx", "1xxx"]:
                subfolder_path = os.path.join(year_folder, subfolder)
                if os.path.exists(subfolder_path) and os.path.isdir(subfolder_path):
                    for root, _, files in os.walk(subfolder_path):
                        for file in files:
                            if file.startswith(f"CVE-{year}-") and file.endswith(".json"):
                                json_file = os.path.join(root, file)
                                extract_json_data(json_file)
                                human_input = f"Explain the vulnerability: {cve_id}"
                                assistant_response = f"{description}\nAffected Products: {affected_products}\nReferences: {references}\nCVE State: {cve_state}"
                                write_json_entry("train.jsonl", human_input, assistant_response)
    convert_jsonl_to_json("train.jsonl", "train.json")

if __name__ == "__main__":
    main()