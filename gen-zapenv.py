import argparse
import json
import jsonschema
import pathlib
import sys


parser = argparse.ArgumentParser()
parser.add_argument('-o', '--out-dir', default='.')
args = parser.parse_args()

jsch = {"type": "object", "required": ["endpoints"], "additionalProperties": False, "properties": {
    "endpoints": {"type": "array",
        "items": {"type": "string"}},
    # "header": {"type": "object", "properties": {
    #     "name": {"type": "string"},
    #     "value": {"type": "string"}}},
    "headers": {"type": "array",
        "items": {"type": "array", "minItems": 2, "maxItems": 2,
            "prefixItems": [{"type": "string"}, {"type": "string"}]}},
    "oas": {"oneOf": [
        {"type": "object", "properties":
            {"file": {"type": "string"}}},
        {"type": "object", "properties":
            {"url": {"type": "string"}}}
    ]}
}}

print(args.out_dir)

try:
    # data = json.load(sys.stdin)
    jsonschema.validate(json.load(sys.stdin), schema=jsch)
except Exception as e:
    print(type(e).__name__, str(e))
    sys.exit(1)
