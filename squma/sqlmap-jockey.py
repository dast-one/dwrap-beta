#!/usr/bin/env python3

import argparse
import json
import jsonschema
import pathlib
import shlex
import subprocess
import sys
import threading
from datetime import datetime

from lib.utils.api import *
from lib.utils.api import _client
from thirdparty.six.moves import http_client as _http_client
from thirdparty.six.moves import input as _input
from thirdparty.six.moves import urllib as _urllib

from openapi_sqlmap import oas_load, sqlmap_tasks


class SqlmapApiClient:
    """Based on sqlmapapi client.

    [lib/utils/api.py](https://github.com/sqlmapproject/sqlmap/blob/master/lib/utils/api.py)
    """

    def __init__(
        self,
        host=RESTAPI_DEFAULT_ADDRESS, port=RESTAPI_DEFAULT_PORT,
        username=None, password=None
    ):
        DataStore.username = username
        DataStore.password = password

        self.addr = "http://%s:%d" % (host, port)
        logger.info("Starting REST-JSON API client to '%s'..." % self.addr)

        try:
            _client(self.addr)
        except Exception as ex:
            if not isinstance(ex, _urllib.error.HTTPError) or ex.code == _http_client.UNAUTHORIZED:
                errMsg = "There has been a problem while connecting to the "
                errMsg += "REST-JSON API server at '%s' " % self.addr
                errMsg += "(%s)" % getSafeExString(ex)
                logger.critical(errMsg)
                return

    def new_scan_w(self, command):
        """Create and start new scan, waiting for finish.
        """
        if isinstance(command, str):
            try:
                argv = ["sqlmap.py"] + shlex.split(command)[1:]
            except Exception as ex:
                logger.error("Error occurred while parsing arguments ('%s')" % getSafeExString(ex))
                taskid = None
                raise
        elif all(isinstance(x, str) for x in command):
            argv = list(command)
        else:
            logger.error("Cannot decide WTF is ('%s')" % getSafeExString(ex))

        logger.info(argv)

        try:
            cmdLineOptions = cmdLineParser(argv).__dict__
        except:
            taskid = None
            raise

        del cmdLineOptions['stdinPipe'] # A hack against callable_iterator in different docker container environments
        for key in list(cmdLineOptions):
            if cmdLineOptions[key] is None:
                del cmdLineOptions[key]

        raw = _client("%s/task/new" % self.addr)
        res = dejsonize(raw)
        if not res["success"]:
            logger.error("Failed to create new task ('%s')" % res.get("message", ""))
            raise
        taskid = res["taskid"]
        logger.info("New task ID is '%s'" % taskid)

        raw = _client("%s/scan/%s/start" % (self.addr, taskid), cmdLineOptions)
        res = dejsonize(raw)
        if not res["success"]:
            logger.error("Failed to start scan ('%s')" % res.get("message", ""))
            raise
        logger.info(f"[{taskid}] started")

        while dejsonize(_client("%s/scan/%s/%s" % (self.addr, taskid, 'status'))).get('status') == 'running':
            time.sleep(2)
        logger.info(f"[{taskid}] finished")

        return {
            'taskid': taskid,
            'log': dejsonize(_client("%s/scan/%s/%s" % (self.addr, taskid, 'log'))),
            'status': dejsonize(_client("%s/scan/%s/%s" % (self.addr, taskid, 'status'))),
            'data': dejsonize(_client("%s/scan/%s/%s" % (self.addr, taskid, 'data'))),
            'config': dejsonize(_client("%s/option/%s/list" % (self.addr, taskid))),
        }

    def list_tasks(self):
        command = 'list'
        raw = _client("%s/admin/%s" % (self.addr, command))
        res = dejsonize(raw)
        if not res["success"]:
            logger.error("Failed to execute command %s" % command)
        elif command == "flush":
            taskid = None
        # dataToStdout("%s\n" % raw)
        return res


def dump_reports(scan_result):
    pathlib.Path(args.out_dir, 'jy').mkdir(parents=False, exist_ok=True)
    with open(pathlib.Path(args.out_dir, 'jy', f"{scan_result['taskid']}.log.ndjson"), 'w') as fo:
        fo.writelines(json.dumps(e) + '\n' for e in scan_result.get('log', []).get('log'))
    with open(pathlib.Path(args.out_dir, 'jy', f"{scan_result['taskid']}.status.json"), 'w') as fo:
        json.dump(scan_result['status'], fo)
    with open(pathlib.Path(args.out_dir, 'jy', f"{scan_result['taskid']}.data.json"), 'w') as fo:
        json.dump(scan_result['data'], fo)
    with open(pathlib.Path(args.out_dir, 'jy', f"{scan_result['taskid']}.config.json"), 'w') as fo:
        json.dump(scan_result['config'], fo)

def thread_worker(sqlmap_task):
    with pool_sema:
        logger.debug(sqlmap_task)
        if not args.dry_run:
            dump_reports(sm.new_scan_w(sqlmap_task))


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
ap.add_argument('--reportfile', default='sq-report', help='Override report filename (without extension)')
# ap.add_argument('-u', '--url', required=True, help='Base URL')
# ap.add_argument('-s', '--oas', required=False, type=pathlib.Path, help='OpenAPI Spec file')
# ap.add_argument('-H', action='append', default=list(), help='Additional header, may be used multiple times')
ap.add_argument('-n', '--dry-run', '--dry_run', action='store_true', help='Do not actually run scan (useful for debugging)')
ap.add_argument('-v', '--log-debug', '--log_debug', action='store_true', help='Be verbose (setLevel logging.DEBUG)')
ap.add_argument('-t', '--threads', type=int, default=3, help='max_threads for threading.BoundedSemaphore()')
args = ap.parse_args()

if args.log_debug:
    logger.setLevel(logging.DEBUG)

if args.scan_request_from_file is None:
    ## Parse STDIN data
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

## Output (reports) will go there
pathlib.Path(args.out_dir).mkdir(parents=False, exist_ok=True)

subprocess.Popen(shlex.split('sqlmapapi -s'))
time.sleep(2)

pool_sema = threading.BoundedSemaphore(args.threads)

sm = SqlmapApiClient()
# if not args.dry_run:
#     sm.list_tasks()

if (cfg.get('oas') or dict()).get('file'):
    # Scanning all the methods defined in the spec.
    for smt in sqlmap_tasks(oas_load(cfg['oas']['file'])):
        u = '/'.join((cfg['endpoints'][0].rstrip('/'), smt['url'].lstrip('/')))
        t = threading.Thread(
            target=thread_worker,
            args=(
                f"new -u {u} -X {smt['method']}"
                # + (f" --output-dir={pathlib.Path(args.out_dir, 'sm').as_posix()}" if args.log_debug else '')
                + ' -H "User-Agent:masc-fu-squma"'
                + ''.join(f" -H '{h}:{v}'" for (h, v) in cfg['headers']) # TODO: maybe, ...replace("'", r"\'") ?
                + (f" --data '{smt['data']}'" if smt.get('data') else '')
                + ' --random-agent --level=2 --risk=3 --skip="Host,Referer,User-Agent" --ignore-code=*',
            )
        )
        t.start()
else:
    # Scanning the web-app
    thread_worker(
        f"new -u {cfg['endpoints'][0]}"
        + (f" --output-dir={pathlib.Path(args.out_dir, 'sm').as_posix()}" if args.log_debug else '')
        + ' -H "User-Agent:masc-fu-squma"'
        + ''.join(f" -H '{h}:{v}'" for (h, v) in cfg['headers']) # TODO: maybe, ...replace("'", r"\'") ?
        + ' --crawl-exclude="logout"' # WARN: exclude-paths regex hardcoded
        + ' --crawl=2 --forms --level=2 --risk=3 --skip="Host,Referer,User-Agent" --ignore-code=*',
    )


## --------------------------------------------------------------------
## -- Combine all the reports and zap-format the result

while not (
    all(task_status == 'terminated' for task_status in sm.list_tasks()['tasks'].values())
    and sm.list_tasks()['tasks_num'] > 0
    ):
    time.sleep(7)

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

for f in pathlib.Path(args.out_dir, 'jy').glob('*.data.json'):
    with open(f) as fo:
        r = json.load(fo)
    if not r['success'] or not r['data']:
        continue

    # WARN Fail-driven dev. part; refs:
    # - srch. '/data' at https://github.com/sqlmapproject/sqlmap/blob/master/lib/utils/api.py
    # - sample test at SQLite > 2.0 OR time-based blind (heavy query)
    r['data'].sort(key=lambda d: d['type'])
    c0, c1 = r['data'][0:2]
    assert isinstance(c0['value'], dict)
    assert isinstance(c1['value'], list)
    for c1_value in c1['value']:
        c1_value_data = c1_value['data'].popitem()[1]
        alert = {
            'pluginid': '-9',
            'alertRef': '-9',
            'alert': c1_value_data['title'],
            'name': c1_value_data['title'],
            'riskcode': '3',
            'confidence': '3',
            'riskdesc': '',
            'desc': 'SQL Injection possible',
            'instances': [{
                'uri': c0['value']['url'],
                'method': c1_value['place'],
                'param': c1_value['parameter'],
                'attack': c1_value_data['vector'],
                'evidence': c1_value_data['payload'],
                'request-header': '',
                'request-body': '',
                'response-header': '',
                'response-body': '',
            }],
            'count': '1',
            'solution': '',
            'otherinfo': '\n'.join(filter(None, (
                *c1_value['notes'],
                c1_value_data['comment'],
                ))),
            'reference': '',
            'cweid': '',
            'wascid': '',
            'sourceid': '',
        }
        report['site'][0]['alerts'].append(alert)

with open(pathlib.Path(args.out_dir, args.reportfile), 'w') as fo:
    json.dump(report, fo)

