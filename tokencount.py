import tokenize
from io import BytesIO

def count_tokens_in_file(file_path):
    with open(file_path, "rb") as file:
        content = file.read()

    tokens = tokenize.tokenize(BytesIO(content).readline)
    token_count = sum(1 for _ in tokens)
    
    return token_count

if __name__ == "__main__":
    file_path = "train.jsonl"  # Replace with the actual path to your Python file
    token_count = count_tokens_in_file(file_path)
    print(f"Number of tokens in the file: {token_count}")
