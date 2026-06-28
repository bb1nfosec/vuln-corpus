#!/usr/bin/env python3
"""Generate corpus.json from corpus.yaml."""
import json
import sys
try:
    import yaml
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

with open("corpus.yaml") as f:
    data = yaml.safe_load(f)
with open("corpus.json", "w") as f:
    json.dump(data, f, indent=2)
count = len(data["corpus"]["entries"])
print(f"Generated corpus.json ({count} entries)")
