#!/usr/bin/env python3

import argparse
import json
import shlex
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

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
ap.add_argument('--reportfile', default='rlr-report', help='Override report filename (without extension)')
ap.add_argument('--hack-upload-report-to')
ap.add_argument('--hack-upload-report-for')
## TODO: Maybe, worth adding options
##  --dry-run    compile only
##  --lite       compile+test
##  --full-scan  FuzzLean+Fuzz
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


def u2r(url):
    """Parse endpoint URL into the options required by Restler."""
    u = urlparse(url if '//' in url else f'//{url}',
                 scheme='http', allow_fragments=False)
    try:
        host_resolved = socket.gethostbyname(u.hostname)
    except Exception as e:
        print(f'Failed to resolve "{u.hostname}" (from the URL "{url}")\n', file=sys.stderr)
        raise e
    return {
        'target_ip': host_resolved,
        'target_port': u.port or 80,
        'no_ssl': not u.scheme.lower().endswith('s'),
        'host': u.hostname if u.hostname != host_resolved else None,
        'basepath': u.path,
    }


# Output (reports) will go there
Path(args.out_dir).mkdir(parents=False, exist_ok=True)


## Compile the spec, alse prepare engine_settings
subprocess.run([
    '/RESTler/restler/Restler'
    , 'compile'
    , '--api_spec', '/wrk/_____________________.yaml'
])


## Update the config (engine_settings.json)
with open('..../engine_settings.json') as fo:
    rlr_cfg = json.load(fo)

rlr_cfg.update({
    'include_user_agent': False,
    'disable_cert_validation': True,
    'ignore_decoding_failures': True,
})

rlr_cfg.update(
    u2r(cfg['endpoints'][0])
)

'''
exclude_requests: list (default empty list=No filtering)
    # "exclude_requests": [
    #     {
    #         "endpoint": "/api/blog/posts/{postId}",
    #         "methods": ["GET", "DELETE"]
    #     }
    # ]

token_refresh_cmd: str (default None)
token_refresh_interval: int (default None)

save_results_in_fixed_dirname: bool (default False, ??, "skip the 'experiment<pid>' subdir")
'''

with open('..../engine_settings.json', 'w') as fo:
    json.dump(rlr_cfg, fo, indent=4)


# The action
subprocess.run([
    '/RESTler/restler/Restler'
    # , 'test'       # \
    # , 'fuzz-lean'  #  > TODO
    # , 'fuzz'       # /
    , '--target_ip', '127.0.0.1'
    , '--target_port', '10013'
    , '--grammar_file', 'Compile/grammar.py'
    , '--dictionary_file', 'Compile/dict.json'
    # , '--no_ssl' if ____ else ''
    , '--settings', 'Compile/engine_settings.json'
])


## --------------------------------------------------------------------
## -- Zap-format the result

report = {
    '@version': 'x3',
    '@generated': datetime.now().ctime(),
    'site': [{
        '@name': cfg['endpoints'][0],
        '@host': rlr_cfg['host'] or rlr_cfg['target_ip'],
        '@port': str(rlr_cfg['target_port']),
        '@ssl': str(not rlr_cfg['no_ssl']),
        'alerts': list(),
    }]
}

# with open(Path(args.out_dir, args.reportfile).with_suffix('.nuorig')) as fo:
#     z = [json.loads(rline) for rline in fo.readlines()]
#     for r in z:
#         alert = {
#             'pluginid': '-8',
#             'alertRef': '-8',
#             'alert': r['info']['name'],
#             'name': r['info']['name'],
#             'riskcode': {
#                 'info': '1',
#                 'low': '1',
#                 'medium': '2',
#                 'high': '3',
#                 'critical': '3',
#                 'unknown': 'x3',
#             }.get(r['info']['severity'], 'x3 (WTF?!)'),
#             'confidence': '2',
#             'riskdesc': '',
#             'desc': r['info']['name'],
#             'instances': [{
#                 'uri': r['matched-at'],
#                 'method': '',
#                 'param': '',
#                 'attack': '',
#                 'evidence': '',
#                 'request-header': '',
#                 'request-body': r.get('request', ''),
#                 'response-header': '',
#                 'response-body': r.get('response', ''),
#             }],
#             'count': '1',
#             'solution': '',
#             'otherinfo': '\n'.join(r.get('extracted-results', [])),
#             'reference': '\n'.join(r['info']['reference'] or []),
#             'cweid': '',
#             'wascid': '',
#             'sourceid': '',
#         }
#         report['site'][0]['alerts'].append(alert)

# with open(Path(args.out_dir, args.reportfile), 'w') as fo:
#     json.dump(report, fo)

# if args.hack_upload_report_to and args.hack_upload_report_for:
#     subprocess.run(
#         shlex.split(f'/usr/local/bin/zreprt-pgup.py -r {Path(args.out_dir, args.reportfile)} -t {args.hack_upload_report_for} --pg_host {args.hack_upload_report_to}'),
#         cwd='/usr/local/bin'
#     )

