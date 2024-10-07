import os
import json
import csv

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

def write_csv_entry(filename, human_input, analyst_response):
    global cve_id, affected_products, description, references, cve_state
    prompt = f"###HUMAN: {human_input} ###Analyst: {analyst_response}"
    with open(filename, "a", newline="", encoding="utf-8") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow([cve_id, description, affected_products, references, cve_state, prompt])

def convert_csv_to_jsonl(csv_filename, jsonl_filename):
    jsonl_data = []

    # Read data from CSV file
    with open(csv_filename, "r", encoding="utf-8") as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            jsonl_data.append(row)

    # Write data to JSONL file
    with open(jsonl_filename, "w", encoding="utf-8") as jsonl_file:
        for data in jsonl_data:
            json.dump(data, jsonl_file, ensure_ascii=False)
            jsonl_file.write("\n")


def main():
    with open("data.csv", "w", newline="", encoding="utf-8") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["CVE ID", "Description", "Affected Products", "References", "CVE State", "Prompt"])
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
                                analyst_response = f"{cve_id}"
                                human_input = f"{description}\nAffected Products: {affected_products}\nReferences: {references}\nCVE State: {cve_state}"
                                write_csv_entry("data.csv", human_input, analyst_response)
    convert_csv_to_jsonl("data.csv", "train.jsonl")

if __name__ == "__main__":
    main()
