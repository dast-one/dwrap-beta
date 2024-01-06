#!/usr/bin/env python3

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

import jsonschema
from attrs import evolve

from zreprt import ZapAlertInfo, ZapAlertInstance, ZapReport, ZapSite


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
ap.add_argument('-i', '--scan-request-from-file', default=None,
    help='Get scan request from JSON-file instead of STDIN.')
ap.add_argument('-o', '--out-dir', default='.')  # default='/wrk/out'
ap.add_argument('--reportfile', default='nu-report', help='Override report filename (without extension)')
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
    'nuclei',
    '-duc', '-ni',
    '-fr', '-mr', '3',
    '-stats', '-sj', '-si', '20',
    '-u', cfg['endpoints'][0],
    '-irr', '-jsonl', '-o', Path(args.out_dir, args.reportfile).with_suffix('.nuorig').as_posix(),
    *shlex.split(''.join(f" -H '{h}:{v}'" for (h, v) in cfg['headers'])),
])


# --------------------------------------------------------------------
# -- Zap-format the result

report = ZapReport(
    # version='x3',
    # generated_ts=datetime.now(timezone.utc).isoformat(),
    site=[ZapSite(
        name=cfg['endpoints'][0],
        host=cfg['endpoints'][0],
        port='-',
        ssl='-',
        alerts=list(),
    )]
)

alert_template = ZapAlertInfo(
    pluginid=-8,
    riskcode='',
    confidence=2,
    instances=list(),
    alertref='-8',
    alert='', name='', riskdesc='', description='', solution='',
    otherinfo='', reference='', cweid='', wascid='', sourceid='',
)

alert_instance_template = ZapAlertInstance(
    uri='', method='', param='', attack='', evidence='',
    request_header='', request_body='', response_header='', response_body='',
)


with open(Path(args.out_dir, args.reportfile).with_suffix('.nuorig')) as fo:
    z = [json.loads(rline) for rline in fo.readlines()]
    for r in z:
        report.site[0].alerts.append(evolve(alert_template, **{
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
            'description': r['info']['name'],
            'instances': [evolve(alert_instance_template, **{
                'uri': r['matched-at'],
                'request_body': r.get('request', ''),
                'response_body': r.get('response', ''),
            }),],
            'count': '1',
            'otherinfo': '\n'.join(r.get('extracted-results', [])),
            'reference': '\n'.join(r['info'].get('reference', [])),
        }))

with open(Path(args.out_dir, args.reportfile).with_suffix('.json'), 'w') as fo:
    fo.write(report.json())
