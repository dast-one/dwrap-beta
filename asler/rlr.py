from dataclasses import dataclass, field


@dataclass
class RequestData:
    """..."""
    method: str
    path: str
    query: str
    body: str


@dataclass
class ResponseData:
    """..."""
    code: int
    codeDescription: str
    content: str
    isFailure: bool
    isBug: bool


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
        """Returns riskcode interms of ZAP."""
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
    def is_consistent(self) -> bool:
        return (
            all(all(rr.is_consistent()) for rr in self.rrz),
        )
    #
    def risk_value(self):
        """Returns riskcode interms of ZAP."""
        return max(map(Err.risk_value, self.rrz))


def eb_collection(jfo) -> list[ErrorBucket]:
    """errorBuckets.json contents -> collection of buckets"""
    for c, bkts in jfo.items():
        print('----', f'code-group: {c}', f'{len(bkts)} bucket(s) here', sep='\t')
        for b, rrz in bkts.items():
            print(f'bucket: {b}', 'with', f'{len(rrz)} sample(s)', sep='\t')
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


if __name__ == '__main__':

    import json
    import sys
    from collections import Counter as C
    from functools import reduce
    from itertools import groupby
    from pathlib import Path

    import argparse
    import json
    import shlex
    import socket
    import subprocess
    import sys
    from datetime import datetime
    from pathlib import Path
    from urllib.parse import urlparse


    ap = argparse.ArgumentParser()
    ap.add_argument('-i', '--scan-request-from-file', default=None, help='Scan request from JSON-file')
    ap.add_argument('-e', '--extra', default='', help='endpoint/subdir(tricky-hacky) TODO doc this!')
    ap.add_argument('-o', '--out_report', default=None, help='Output report file')
    # ap.add_argument('--hack-upload-report-to')
    # ap.add_argument('--hack-upload-report-for')
    ap.add_argument('-n', '--dry-run', action='store_true')
    args = ap.parse_args()

    with open(args.scan_request_from_file) as fo:
        cfg = json.load(fo)

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
            'host': u.hostname,
            'basepath': u.path,
        }

    rlr_cfg = u2r(cfg['endpoints'][0])

    # def P(x):
    #     print(json.dumps(x, indent=4, ensure_ascii=False))

    # def PC(z, flt=None):
    #     for x, n in C(z).items():
    #         print(f'{n:6}  {x}')

    # # P(C(f"{r['code']:6} {q['method']} {q['path']}" for q, r in rrz))
    # PC(f"{r['code']:6} {q['method']} {q['path']}" for q, r in rrz)

    # endpoints = []
    # for ep in endpoints:
    #     with open(Path(bp, '_reprt', 'details', f'c500-{ep}.txt'), 'w') as fo:
    #         dump_rr(gather_rrz(ep), lambda rr: rr[1]['code'] == 500, fo)
    # ## -- brief reports
    # rrz = gather_rrz(endpoints)
    # with open(Path(bp, '_reprt', 'c500.txt'), 'w') as fo:
    #     dump_rr(rrz, lambda rr: rr[1]['code'] == 500, fo, short=True)


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

    bp = Path(args.scan_request_from_file).expanduser().parent
    e = args.extra

    with open(Path(bp, e, 'FuzzLean/ResponseBuckets/errorBuckets.json')) as fo:
        jfo = json.load(fo)

    for eb in eb_collection(jfo):
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

    with open(args.out_report, 'w') as fo:
        json.dump(report, fo, indent=4, ensure_ascii=False)

    # if args.hack_upload_report_to and args.hack_upload_report_for:
    #     subprocess.run(
    #         shlex.split(f'/usr/local/bin/zreprt-pgup.py -r {args.out_report} -t {args.hack_upload_report_for} --pg_host {args.hack_upload_report_to}'),
    #         cwd='/usr/local/bin'
    #     )
