# CVE-llm_dataset
This dataset is intended to train an LLM model for an utterly CVE-focused input and output.

## Data extraction:
For the data extraction, I first downloaded the CVE database from NVD lists and then loaded them using the `cve_dataset_2.py` and `cve_dataset.py` Both have produced different datasets one is for llama and the other is for openai GPT.

The CVE json files are mapped in this format:
```mermaid
graph TD
    cves(CVEs)
    cves1999(1999)
    cves19990xxx(0xxx - 1999)
    cves19991xxx(1xxx - 1999)
    cve19990001(CVE-1999-0001.json - 1999)
    cve19990999(CVE-1999-0999.json - 1999)
    cve19991000(CVE-1999-1000.json - 1999)
    cve19991598(CVE-1999-1598.json - 1999)
    cves2023(2023)
    cves20230xxx(0xxx - 2023)
    cves20231xxx(1xxx - 2023)
    cve20230001(CVE-2023-0001.json)
    cve20230999(CVE-2023-0999.json)
    cve20231000(CVE-2023-1000.json)
    cve20231598(CVE-2023-1598.json)

    cves --> cves1999
    cves --> cves2023
    cves1999 --> cves19990xxx
    cves1999 --> cves19991xxx
    cves19990xxx --> cve19990001
    cves19990xxx --> m[more 1999]
    cves19990xxx --> cve19990999
    cves19991xxx --> cve19991000
    cves19991xxx --> m1[more 1999]
    cves19991xxx --> cve19991598
    cves2023 --> cves20230xxx
    cves2023 --> cves20231xxx
    cves20230xxx --> cve20230001
    cves20230xxx --> m2[more 2023]
    cves20230xxx --> cve20230999
    cves20231xxx --> cve20231000
    cves20231xxx --> m3[more 2023]
    cves20231xxx --> cve20231598
``` 
The programs traverse through these folders extract the data in the files and arrange them into usable formats for the fine-tuning process.

## llama2 Model dataset:
The llama2 fine-tuned dataset follows this format:
```
    {
        "instruction": "Explain CVE-1999-0001",
        "input": "Explain the vulnerability: CVE-1999-0001",
        "output": "ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets.\nAffected Products: n/a\nReferences: [{'tags': ['x_refsource_CONFIRM'], 'url': 'http://www.openbsd.org/errata23.html#tcpfix'}, {'name': '5707', 'tags': ['vdb-entry', 'x_refsource_OSVDB'], 'url': 'http://www.osvdb.org/5707'}]\nCVE State: PUBLISHED"
    }
```
The instruction is what we instruct the AI to do with the data provided For example we can command the AI `To take in user input analyze it and then based on what he asks return an answer` This is also where we can add a `role` or a `personal` to the AI.

The input is the user Input of the main query or data that must be processed by the AI. This is a crucial piece of information that the AI will process to provide an output.

The output is the format that we define and tell the AI to generate answers in that format or provide that answer to the question asked.

## OpenAI fine-tune dataset:
The OpenAI fine-tune format is way different from the Llama dataset this requires us to define roles and messages for the output and using this we can provide more details and increase the answer accuracy.

```
    {
        "messages": [
            {
                "role": "system",
                "content": "CVE Vulnerability Information"
            },
            {
                "role": "user",
                "content": "Explain the vulnerability: CVE-1999-0001"
            },
            {
                "role": "assistant",
                "content": "ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets.\nAffected Products: n/a\nReferences: [{'tags': ['x_refsource_CONFIRM'], 'url': 'http://www.openbsd.org/errata23.html#tcpfix'}, {'name': '5707', 'tags': ['vdb-entry', 'x_refsource_OSVDB'], 'url': 'http://www.osvdb.org/5707'}]\nCVE State: PUBLISHED"
            }
        ]
    }
```
In this dataset, we define the AI and user roles and also the AI content and output for the user's content. The core working is similar to a llama or any text generation model dataset.

## OpenAI price calculation:
The `price-openai.py` file calculates the dataset's total tokens and does the necessary calculations to decide the overall price to train a custom gpt model from openai. The same goes for `tokencount.py` it mainly counts the total amount of tokens present in the dataset.

## Links
- Dataset HuggingFace link: https://huggingface.co/datasets/morpheuslord/cve-llm-training
- Secllama: https://huggingface.co/morpheuslord/secllama
- My LinkedIn Link: https://www.linkedin.com/in/chiranjeevi-g-naidu/
