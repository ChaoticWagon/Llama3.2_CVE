# CVE-llm_dataset
This dataset is intended to train an LLM model for an utterly CVE-focused input and output.

## Data extraction:
For the data extraction, I first downloaded the CVE database from NVD lists and then loaded them using the `cve_dataset_2.py` and `cve_dataset.py` Both have produced different datasets one is for llama and the other is for openai GPT.

The CVE json files are mapped in this format:
```
cves:
|
├─1999
|   ├─0xxx
|   |   ├─CVE-1999-0001.json
|   |   └─CVE-1999-0999.json
|   └─1xxx
|      ├─CVE-1999-1000.json
|      └─CVE-1999-1598.json
└─2023

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
- My LinkedIn Link: https://www.linkedin.com/in/chiranjeevi-g-naidu/
