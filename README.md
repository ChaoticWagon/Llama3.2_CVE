# CVE-llm_dataset
This dataset is intended to train an LLM model for an utterly CVE-focused input and output.

## Data extraction:
For the data extraction I first downloaded the CVE database from NVD lists and then loaded them using the `cve_dataset_2.py` and `cve_dataset.py` both have produce different datasets one is for llama and the other is for openai GPT.

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
The programs traverse trough these folders and extracts the data in the files and arrainges them into usable formats for the fine-tune process.

## llama2 Model dataset:
The llama2 fine-tune dataset follows this format:
```
    {
        "instruction": "Explain CVE-1999-0001",
        "input": "Explain the vulnerability: CVE-1999-0001",
        "output": "ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets.\nAffected Products: n/a\nReferences: [{'tags': ['x_refsource_CONFIRM'], 'url': 'http://www.openbsd.org/errata23.html#tcpfix'}, {'name': '5707', 'tags': ['vdb-entry', 'x_refsource_OSVDB'], 'url': 'http://www.osvdb.org/5707'}]\nCVE State: PUBLISHED"
    }
```
The instruction is what we instruct the AI to do with the data provided for example we can command the AI `To take in user input analyze it and then based on what he asks returns an answer` This is also where we can add a `role` or a `personal` to the AI.

The input is the user Inputs the main query or data that must be processed by the AI. This is a crucial peace of information that the AI will process in order to provide an output.

The output is the format that we define and tell the AI to generate anwers in that format or provide that answer to the question asked.

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
In this dataset we define the AI and user role's and also the AI content and output for the users content. The core working is similar to llama or any text generation models datasets.

## OpenAI price calculation:
The `price-openai.py` file is calculates the datasets total tokens and does the necessary calculations to decide the operall price to train a custom gpt model from openai. The same goes for `tokencount.py` it mainly counts the total amount of tokens present in the dataset.
