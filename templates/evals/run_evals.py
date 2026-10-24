"""Validate the evaluation dataset; the scheduled Foundry evaluation consumes the same file."""

import argparse
import json
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--dataset", required=True)
parser.add_argument("--validate-only", action="store_true")
args = parser.parse_args()

rows = 0
with open(args.dataset, encoding="utf-8") as handle:
    for number, line in enumerate(handle, 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if set(row) != {"query", "expected"}:
            sys.exit(f"line {number}: expected exactly query and expected")
        rows += 1
if rows == 0:
    sys.exit("dataset is empty")
print(f"{rows} evaluation rows are valid")
