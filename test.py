#!/usr/bin/env python3

from crypto.Hash import RIPEMD160
import sys

def generate_ripemd160_hash(filename):
    try:
        with open(filename, 'rb') as f:
            data = f.read()
        hash_obj = RIPEMD160.new()
        hash_obj.update(data)
        print(f"RIPEMD-160 Hash of '{filename}': {hash_obj.hexdigest()}")
    except FileNotFoundError:
        print(f"File '{filename}' not found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ripemd160_hash.py <filename>")
    else:
        generate_ripemd160_hash(sys.argv[1])
