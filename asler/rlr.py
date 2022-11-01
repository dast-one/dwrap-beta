import re
from dataclasses import field

from pydantic.dataclasses import dataclass


@dataclass
class RequestData:
    """..."""
    method: str
    path: str
    query: str = field(repr=False)
    body: str = field(repr=False)


@dataclass
class ResponseData:
    """..."""
    code: int
    codeDescription: str
    content: str
    isFailure: bool | None
    isBug: bool | None

    def __post_init__(self):
        # code: str to non negative integer (negative result is a sign of an error)
        try:
            self.code = int(self.code)
        except ValueError:
            self.code = -1
        except TypeError:
            self.code = -2


@dataclass
class Err:
    """..."""
    c: str
    bkt: str
    qry: RequestData
    res: ResponseData
    # 
    def is_consistent(self) -> bool:
        return (
            self.c == str(self.res.code),
        )
    #
    def risk_value(self):
        """Returns riskcode in terms of ZAP."""
        if self.res.isBug:
            return '3'
        elif self.res.isFailure:
            return '2'
        else:
            return '1'


@dataclass
class ErrorBucket:
    """...
    """
    c: str
    bkt: str
    rrz: list[Err] = field(default_factory=list)
    #
    checker: str|None = None
    checker_tag: str|None = None
    checker_data: str|None = None
    #
    def is_consistent(self) -> bool:
        return (
            all(all(rr.is_consistent()) for rr in self.rrz),
        )
    #
    def risk_value(self):
        """Returns riskcode in terms of ZAP."""
        return max(map(Err.risk_value, self.rrz))


def ebkt_collection_from_errbuckets_json(jfo) -> list[ErrorBucket]:
    """errorBuckets.json contents -> collection of buckets"""
    for c, bkts in jfo.items():
        # print('----', f'code-group: {c}', f'{len(bkts)} bucket(s) here', sep='\t')
        for b, rrz in bkts.items():
            # print(f'bucket: {b}', 'with', f'{len(rrz)} sample(s)', sep='\t')
            yield ErrorBucket(
                c,
                b,
                [
                    Err(
                        c,
                        b,
                        RequestData(**rr['request']['RequestData']),
                        ResponseData(**rr['response']['ResponseData'])
                    )
                    for rr in rrz
                ]
            )

def ebkt_collection_from_bugbuckets_txts(jfo, bp) -> list[ErrorBucket]:
    """experiment/bug_buckets/* -> collection of buckets"""
    # 
    def _get_checker_contents(text, p=re.compile(
        r'#+?\n'                    # ###
        r'\s*?(\S+?)(?:_(\d+))?\n'   # checker name, http code
        r'(?:\s+(.+?)(?:\n(.+?))?\s+)?' # checker specific tag, data
        r'\s*?Hash: \1(?:_\2)?_(\w+)\n'  # (bucket/checker?) hash
        r'.*?'                      # ...
        r'#+?\n'                    # ###
        r'\n'
        r'-> ["\']?(\w+) (.*?) (HTTP/\S+.*?)["\']?\n' # method, path, request
        r'(?:^!.*?\n)*?'            # engine/checker settings
        r'PREVIOUS RESPONSE: .(.*?).\n' # response
        # WARN: Single (first matched) request-response block supported.
        # TODO: Research how many request-response blocks may be there, and adjust the regex.
    , re.MULTILINE + re.DOTALL)):
        if m := p.match(text):
            return m.groups()
    # 
    for bx, fref in jfo.items():
        print('---- from', fref['file_path'])
        with open(Path(bp, fref['file_path'])) as fo:
            try:
                (
                    checker, code,
                    checker_tag, checker_data,
                    some_hash,
                    method, path, request,
                    response
                ) = _get_checker_contents(fo.read())
            except Exception as e:
                print('Parser failed:', bx, fref, _get_checker_contents(fo.read()))
                raise e
        request = eval('str("' + request.replace('"', r'\"') + '")')
        response = eval('str("' + response.replace('"', r'\"') + '")')
        print('got', f'::{checker}::{code}::{some_hash}::', 'with sample for', method, path)
        print()
        yield ErrorBucket(
            c=code,
            bkt=some_hash,
            rrz=[Err(
                c=code,
                bkt=some_hash,
                qry=RequestData(
                    method=method,
                    path=path,
                    query=f'{method}\n{path}',
                    body=request,
                ),
                res=ResponseData(
                    code=code,
                    codeDescription='',
                    content=response,
                    isFailure=None,
                    isBug=None,
                )
            ),],
            checker=checker,
            checker_tag=checker_tag,
            checker_data=checker_data,
        )


if __name__ == '__main__':

    import argparse
    import json
    # import shlex
    # import subprocess
    import sys
    from datetime import datetime
    from pathlib import Path

    sys.path.insert(1, str(Path(Path.home(), 'd1/src/dyna-misc').expanduser()))

    from zreprt import ZapReport


    ap = argparse.ArgumentParser()
    ap.add_argument('-r', '--rlr-wrk', default='.', help='Restler wrk-dir as base path for its data to read.')
    ap.add_argument('-o', '--out-report', default=None, help='Output report file')
    # ap.add_argument('--hack-upload-report-to')
    # ap.add_argument('--hack-upload-report-for')
    ap.add_argument('-n', '--dry-run', default=False, action='store_true')
    # ap.add_argument('--skip_errbuckets_json', default=False, action='store_true')
    args = ap.parse_args()

    rlr_cfg = {
        'host': None,
        'no_ssl': False,
        'target_port': -1,
        'basepath': '',
    }
    with open(Path(args.rlr_wrk, 'Compile/engine_settings.json')) as fo:
        rlr_cfg.update(json.load(fo))


    ## --------------------------------------------------------------------
    ## -- Zap-format the result

    whether_default_port_configured = (
        rlr_cfg['no_ssl'] and rlr_cfg['target_port'] == 80
        or not rlr_cfg['no_ssl'] and rlr_cfg['target_port'] == 443
    )
    report = {
        # '@version': 'x3',
        # '@generated': datetime.now().ctime(),
        'site': [{
            '@name': f"http{'' if rlr_cfg['no_ssl'] else 's'}://"
                     f"{rlr_cfg['host'] or '...'}"
                     f"{'' if (whether_default_port_configured) else ':' + str(rlr_cfg['target_port'])}"
                     f"/{rlr_cfg['basepath'].strip('/')}",
            '@host': rlr_cfg['host'],
            '@port': str(rlr_cfg['target_port']),
            '@ssl': str(not rlr_cfg['no_ssl']),
            'alerts': list(),
        }]
    }

    print(f'-- Mining at {args.rlr_wrk}')

    # ResponseBuckets contains a run summary, which bucketizes the responses
    #   by error code and message (if Restler.ResultsAnalyzer not failed).
    #   This is a basis for an optional summary.
    if (p := Path(args.rlr_wrk, 'FuzzLean/ResponseBuckets/errorBuckets.json')).is_file():
        # print('J', end=' ')
        with open(p) as fo:
            jfo = json.load(fo)
            # print(len(str(jfo)), end=' ')
            ebc = ebkt_collection_from_errbuckets_json(jfo)
        print('[DEBUG]', f'Loaded ResponseBuckets from {p.name}')

    # Collect individual bug buckets created for each bug found.
    #   This is a basis for the main report.
    if (p := Path(next(Path(args.rlr_wrk, 'FuzzLean/RestlerResults').glob('experiment*')), 'bug_buckets/bug_buckets.json')).is_file():
        # print('T', end=' ')
        with open(p) as fo:
            jfo = json.load(fo)
            # print(len(str(jfo)), end=' ')
            ebc = ebkt_collection_from_bugbuckets_txts(jfo, p.parent)
        print('[DEBUG]', f'Loaded bug_buckets from {p.name}')

    for eb in ebc:
        report['site'][0]['alerts'].append(
            {
                'pluginid': '-9',
                'alertRef': f'{eb.c}-{eb.bkt}',
                'alert': f'{eb.c}-{eb.bkt}',
                'name': (
                    ', '.join(sorted(set(rr.res.codeDescription for rr in eb.rrz)))
                    + (' [fail]' if any(rr.res.isFailure for rr in eb.rrz) else '')
                    + (' [bug]' if any(rr.res.isBug for rr in eb.rrz) else '')
                ),
                'riskcode': eb.risk_value(),
                'confidence': '2',
                'riskdesc': '',
                'desc': '',
                'instances': [
                    {
                        'uri': rr.qry.path,
                        'method': rr.qry.method,
                        'param': '',
                        'attack': '',
                        'evidence': '',
                        'request-header': '',
                        'request-body': rr.qry.body,
                        'response-header': '',
                        'response-body': rr.res.content,
                    }
                    for rr in eb.rrz
                ],
                'count': str(len(eb.rrz)),
                'solution': '',
                'otherinfo': '',
                'reference': '',
                'cweid': '',
                'wascid': '',
                'sourceid': '',
            }
        )

    ## --------------------------------------------------------------------

    if args.dry_run or args.out_report is None: 
        print(json.dumps(report, indent=4, ensure_ascii=False), file=sys.stderr)
        sys.exit()

    with open(args.out_report, 'w') as fo:
        json.dump(report, fo, indent=4, ensure_ascii=False)

    # if args.hack_upload_report_to and args.hack_upload_report_for:
    #     subprocess.run(
    #         shlex.split(f'/usr/local/bin/zreprt-pgup.py -r {args.out_report} -t {args.hack_upload_report_for} --pg_host {args.hack_upload_report_to}'),
    #         cwd='/usr/local/bin'
    #     )
