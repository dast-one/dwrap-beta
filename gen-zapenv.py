import argparse
import jinja2
import json
import jsonschema
import sys
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument('-o', '--out-dir', default='.')
parser.add_argument('-t', '--templates-dir', default='./templates-zap')
args = parser.parse_args()

cfg_sch = {"type": "object", "required": ["endpoints"], "additionalProperties": False, "properties": {
    "endpoints": {"type": "array",
        "items": {"type": "string"}},
    # "header": {"type": "object", "properties": {
    #     "name": {"type": "string"},
    #     "value": {"type": "string"}}},
    "headers": {"type": "array",
        "items": {"type": "array", "minItems": 2, "maxItems": 2,
            "prefixItems": [{"type": "string"}, {"type": "string"}]}},
    # "oas": {"oneOf": [
    #     {"type": "object", "properties":
    #         {"file": {"type": "string"}}},
    #     {"type": "object", "properties":
    #         {"url": {"type": "string"}}}
    # ]}
    "oas": {"type": "object",
        "properties": {
            "file": {"type": "string"},
            "url": {"type": "string"}},
        "oneOf": [
            {"required": ["file"]},
            {"required": ["url"]}]}
}}


try:
    cfg = json.load(sys.stdin)
    jsonschema.validate(cfg, schema=cfg_sch)
except Exception as e:
    print(type(e).__name__, str(e))
    sys.exit(1)

jenv = jinja2.Environment(
    loader=jinja2.FileSystemLoader(args.templates_dir),
    trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True)

jenv.globals = cfg

for template_file in [
        'zap-af.yaml.j2',      # urls
        'zap-options.cfg.j2',  # (Not parametrized yet)
        'hsendr.py.j2',        # headers
        ]:
    try:
        if template_rendered := jenv.get_template(template_file).render():
            with open(Path(args.out_dir, Path(template_file).stem), 'w') as fo:
                fo.write(template_rendered)
    except Exception as e:
        print(type(e).__name__, str(e))
        sys.exit(1)
