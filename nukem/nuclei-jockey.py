#!/usr/bin/env python3

import argparse
import json
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import jsonschema


SCAN_REQUEST_SCH = {"type": "object", "required": ["endpoints"], "additionalProperties": False, "properties": {
    "endpoints": {"type": "array", "minItems": 1,
        "items": {"type": "string"}},
    "headers": {"type": "array",
        "items": {"type": "array", "minItems": 2, "maxItems": 2,
            "prefixItems": [{"type": "string"}, {"type": "string"}]}},
    "oas": {"anyOf": [{"type": "null"}, {"type": "object",
        "properties": {
            "file": {"type": "string"},
            "url": {"type": "string"}},
        "oneOf": [
            {"required": ["file"]},
            {"required": ["url"]}]}]},
    "excludepaths": {"type": "array",
        "items": {"type": "string"}}
}}

ap = argparse.ArgumentParser()
ap.add_argument('-i', '--scan-request-from-file', default=None, help='Get scan request from JSON-file instead of STDIN.')
ap.add_argument('-o', '--out-dir', default='.') # default='/wrk/out'
ap.add_argument('--reportfile', default='nu-report', help='Override report filename (without extension)')
ap.add_argument('--hack-upload-report-to')
ap.add_argument('--hack-upload-report-for')
args = ap.parse_args()

if args.scan_request_from_file is None:
    # Parse STDIN data
    try:
        cfg = json.load(sys.stdin)
        jsonschema.validate(cfg, schema=SCAN_REQUEST_SCH)
    except Exception as e:
        print(type(e).__name__, str(e))
        sys.exit(1)
else:
    try:
        with open(args.scan_request_from_file) as fo:
            cfg = json.load(fo)
        jsonschema.validate(cfg, schema=SCAN_REQUEST_SCH)
    except Exception as e:
        print(type(e).__name__, str(e))
        sys.exit(1)

# Output (reports) will go there
Path(args.out_dir).mkdir(parents=False, exist_ok=True)


subprocess.run([
    'nuclei'
    , '-duc', '-ni'
    , '-fr', '-mr', '3'
    , '-stats', '-sj', '-si', '20'
    , '-u', cfg['endpoints'][0]
    , '-irr', '-json', '-o', Path(args.out_dir, args.reportfile).with_suffix('.nuorig').as_posix()
    , *shlex.split(''.join(f" -H '{h}:{v}'" for (h, v) in cfg['headers']))
])


## --------------------------------------------------------------------
## -- Zap-format the result

report = {
    '@version': 'x3',
    '@generated': datetime.now().ctime(),
    'site': [{
        '@name': cfg['endpoints'][0],
        '@host': cfg['endpoints'][0],
        '@port': '-',
        '@ssl': '-',
        'alerts': list(),
    }]
}

with open(Path(args.out_dir, args.reportfile).with_suffix('.nuorig')) as fo:
    z = [json.loads(rline) for rline in fo.readlines()]
    for r in z:
        alert = {
            'pluginid': '-8',
            'alertRef': '-8',
            'alert': r['info']['name'],
            'name': r['info']['name'],
            'riskcode': {
                'info': '1',
                'low': '1',
                'medium': '2',
                'high': '3',
                'critical': '3',
                'unknown': 'x3',
            }.get(r['info']['severity'], 'x3 (WTF?!)'),
            'confidence': '2',
            'riskdesc': '',
            'desc': r['info']['name'],
            'instances': [{
                'uri': r['matched-at'],
                'method': '',
                'param': '',
                'attack': '',
                'evidence': '',
                'request-header': '',
                'request-body': r.get('request', ''),
                'response-header': '',
                'response-body': r.get('response', ''),
            }],
            'count': '1',
            'solution': '',
            'otherinfo': '\n'.join(r.get('extracted-results', [])),
            'reference': '\n'.join(r['info']['reference'] or []),
            'cweid': '',
            'wascid': '',
            'sourceid': '',
        }
        report['site'][0]['alerts'].append(alert)

with open(Path(args.out_dir, args.reportfile), 'w') as fo:
    json.dump(report, fo)

if args.hack_upload_report_to and args.hack_upload_report_for:
    subprocess.run(
        shlex.split(f'/usr/local/bin/zreprt-pgup.py -r {Path(args.out_dir, args.reportfile)} -t {args.hack_upload_report_for} --pg_host {args.hack_upload_report_to}'),
        cwd='/usr/local/bin'
    )

