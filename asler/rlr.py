import re
from attrs import asdict, define, field
from cattrs import structure
# from datetime import datetime, timezone
from itertools import groupby
from pathlib import Path
from typing import Iterator

from attrs import evolve

from zreprt import ZapAlertInfo, ZapAlertInstance, ZapReport, ZapSite


@define
class RequestData:
    """..."""
    method: str
    path: str
    query: str = field(repr=False)
    body: str = field(repr=False)


@define
class ResponseData:
    """..."""
    code: int
    codeDescription: str
    content: str
    isFailure: bool | None
    isBug: bool | None

    def __attrs_post_init__(self):
        # Since `code` should be a non-negative integer,
        # we use negative result to indicate an error.
        try:
            self.code = int(self.code)
        except ValueError:
            self.code = -1
        except TypeError:
            self.code = -2


@define
class Err:
    """..."""
    c: str # WARN Sometimes 0(int) comes!
    bkt: str
    qry: RequestData
    res: ResponseData

    def is_consistent(self) -> bool:
        return (
            self.c == str(self.res.code),
        )

    def risk_value(self):
        """Returns riskcode in terms of ZAP."""
        if self.res.isBug:
            return '3'
        elif self.res.isFailure:
            return '2'
        else:
            return '1'


@define
class ErrorBucket:
    """..."""
    c: str
    bkt: str
    rrz: list[Err] = field(factory=list)
    checker: str | None = None
    checker_tag: str | None = None
    checker_data: str | None = None

    def is_consistent(self) -> bool:
        return (
            all(all(rr.is_consistent()) for rr in self.rrz),
        )

    def risk_value(self):
        """Returns riskcode in terms of ZAP."""
        return max(map(Err.risk_value, self.rrz))


def collect_errbuckets(jfo) -> Iterator[ErrorBucket]:
    """errorBuckets.json contents -> collection of errbuckets"""
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


def collect_bugbuckets(jfo, bp, archive=None) -> Iterator[ErrorBucket]:
    """RestlerResults/[experiment...]/bug_buckets/* -> collection of ~~bugbuckets~~ errbuckets

    TarFile is also accepted (then `bp` treated as base path inside the archive).

    NOTE: BUGBUCK
    _Bug-Bucket_ term here should be reconsidered as a _sequence_
    as we encounter a file with more than one request marked `->`.

    bp = Path('~/d1/deed').expanduser()
    for bbdir in bp.glob('**/bug_buckets'):
        print(f' -- {bbdir}')
        for bf in bbdir.glob('*.txt'):
            with open(bf) as fo:
                n = len(list(filter(
                    None,
                    (line.startswith('->') for line in fo.readlines())
                )))
            print('.' if n == 1 else n, end='')
        print()
    """

    def _get_checker_contents(text, p=re.compile(
        r'#+?\n'                         #
        r'\s*?(\S+?)(?:_(\d+))?\n'       # checker name, http code
        r'(?:\s+(.+?)(?:\n(.+?))?\s+)?'  # checker specific tag, data
        r'\s*?Hash: \1(?:_\2)?_(\w+)\n'  # (bucket/checker?) hash
        r'.*?'                           # ...
        r'#+?\n'                         #
        r'\n'
        r'-> ["\']?(\w+) (.*?) (HTTP/\S+.*?)["\']?\n'  # method, path, request
        r'(?:^!.*?\n)*?'                 # engine/checker settings
        r'PREVIOUS RESPONSE: .(.*?).\n'  # response
        # WARN: Single (first matched) request-response block supported;
        # TO BE REFACTORED as soon as BUGBUCK NOTE condition triggers.
    , re.MULTILINE + re.DOTALL)):
        if m := p.match(text):
            return m.groups()

    for bx, fref in jfo.items():
        # print('---- from', fref['file_path'])
        if archive:
            bbdata = archive.extractfile(str(Path(bp, fref['file_path']))).read().decode()
        else:
            with open(Path(bp, fref['file_path'])) as fo:
                bbdata = fo.read()
        try:
            (
                checker, code,
                checker_tag, checker_data,
                some_hash,
                method, path, request,
                response
            ) = _get_checker_contents(bbdata)
        except Exception as e:
            print('Parser failed:', bx, fref)
            raise e
        request = eval('str("' + request.replace('"', r'\"') + '")')
        response = eval('str("' + response.replace('"', r'\"') + '")')
        code = code or '0'
        # print('got', f'::{checker}::{code}::{some_hash}::', 'with sample for', method, path)
        # print()
        yield ErrorBucket(
            c=code,
            bkt=some_hash,
            # This is already BUGBUCK NOTE compliant.
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


def zreprt_the_result(rlr_cfg, ebc):
    """Returns ZAP-like report for given
    Restler config and collection of Err-like objects.

    WARN: Written for collect_bugbuckets() output.
    """
    whether_default_port_configured = (
        rlr_cfg['no_ssl'] and rlr_cfg['target_port'] == 80
        or not rlr_cfg['no_ssl'] and rlr_cfg['target_port'] == 443
    )

    zr = ZapReport(
        # version='x3',
        # generated_ts=datetime.now(timezone.utc).isoformat(),
        site=[ZapSite(
            name=f"http{'' if rlr_cfg['no_ssl'] else 's'}://"
                     f"{rlr_cfg['host'] or '...'}"
                     f"{'' if (whether_default_port_configured) else ':' + str(rlr_cfg['target_port'])}"
                     f"/{rlr_cfg['basepath'].strip('/')}",
            host=rlr_cfg['host'],
            port=str(rlr_cfg['target_port']),
            ssl=str(not rlr_cfg['no_ssl']),
            alerts=list(),
        )]
    )

    alert_template = ZapAlertInfo(
        pluginid=-9,
        riskcode=2,
        confidence=2,
        instances=list(),
        alertref='', alert='', name='', riskdesc='', description='', solution='',
        otherinfo='', reference='', cweid='', wascid='', sourceid='',
    )

    alert_instance_template = ZapAlertInstance(
        uri='', method='', param='', attack='', evidence='',
        request_header='', request_body='', response_header='', response_body='',
    )

    datep = re.compile(r'([Dd]ate: .*? )(\d\d:\d\d:\d\d)( [A-Z]{3}\b)|(\b202\d-\d\d-\d\d[T ]?)(\d\d:\d\d:\d\d(?:\.\d+)?)(.\d\d:\d\d\b)')
    clenp = re.compile(r'^Content-Length:.*$', re.M + re.I)
    etagp = re.compile(r'^ETag:.*$', re.M + re.I)
    uuidp = re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I)
    # klmnp = re.compile(r'^(.*?Нетипизированная ошибка.{33}).*$', re.M + re.S) # Manual editing is not a final solution. TODO: Improve this.
    errs_for_summary = list()

    for eb in ebc:

        ## Original raw report would be built like that.
        # zr.site[0].alerts.append(alert_template.copy(update={
        #     'alertref': f'{eb.c}-{eb.bkt}',
        #     'alert': f'{eb.c}-{eb.bkt}',
        #     'name': (
        #         ', '.join(sorted(set(rr.res.codeDescription for rr in eb.rrz)))
        #         + (' [fail]' if any(rr.res.isFailure for rr in eb.rrz) else '')
        #         + (' [bug]' if any(rr.res.isBug for rr in eb.rrz) else '')
        #     ),
        #     # 'riskcode': eb.risk_value(),
        #     'instances': [
        #         alert_instance_template.copy(update={
        #             'uri': rr.qry.path,
        #             'method': rr.qry.method,
        #             'request_body': rr.qry.body,
        #             'response_body': rr.res.content,
        #         }) for rr in eb.rrz
        #     ],
        #     'count': len(eb.rrz),
        # }))

        # Normalize for further grouping.
        e2 = structure(asdict(eb.rrz[-1]), Err) # TODO: Why simply not `e2 = eb.rrz[-1]`?
        # e2.res.content = datep.sub(r'_date_HH:MM:SS\3', e2.res.content)
        normalized_res_content = datep.sub(r'_date_HH:MM:SS\3', e2.res.content)
        normalized_res_content = clenp.sub(r'Content-Length: ...', normalized_res_content)
        normalized_res_content = etagp.sub(r'ETag: ...', normalized_res_content)
        normalized_res_content = uuidp.sub(r'<UUID>', normalized_res_content)
        # normalized_res_content = klmnp.sub(r'\1', normalized_res_content) # Manual editing is not a final solution. TODO: Improve this.
        # breakpoint()
        errs_for_summary.append(
            (
                e2,
                {
                    'nrc': normalized_res_content,
                    'checker': eb.checker,
                    'checker_tag': eb.checker_tag,
                    'checker_data': eb.checker_data,
                }
            )
        )

    # Generate our own summary-samples.
    samples = list()
    # kf = lambda e: (e[0].res.content, e[0].c, e[1]['checker'])
    kf = lambda e: (e[1]['nrc'], e[0].c, e[1]['checker'])
    errs_for_summary.sort(key=kf)
    critp = re.compile('INSERT INTO') # Manual editing is not a final solution. TODO: Improve this.
    for (_, response_code, checker), err_grp in groupby(errs_for_summary, key=kf):
        err_grp = list(err_grp)
        samples.append(
            (
                [e[0].qry for e in err_grp],
                err_grp[-1][0].res.content,
                response_code,
                checker,
                any(critp.search(e[0].res.content) for e in err_grp), # Severity raise condition
            )
        )

    print(f'  {len(errs_for_summary)} Err(s)  ->  {len(samples)} group(s)'
          f'  with items:  {", ".join(map(str, (len(q) for q, _, _, _, _ in samples)))}')

    for qz, r, c, ch, raise_condition in samples:
        issue_locations = sorted(set(
            (q.method, q.path[:q.path.find("?") if q.path.find("?") > 0 else None])
            for q in qz
        ))
        zr.site[0].alerts.append(evolve(alert_template, **{
            'alertref': f'{c}-{ch}',
            'alert': f'{c}-{ch}',
            'name': f'{c}-{ch}',  # TODO
            # 'riskcode':  # TODO, eb.risk_value(),
            'riskcode': 3 if raise_condition else 2,
            'instances': [
                # First fake instance with request-response.
                evolve(alert_instance_template, **{
                    'uri': '(SAMPLE)',
                    # 'method': '__',
                    'request_body': f'{qz[0].query}\n{qz[0].body}\n',
                    'response_body': r,
                }),
            ] + [
                # List where such issues found.
                evolve(alert_instance_template, **{
                    'uri': p,
                    'method': m,
                }) for (m, p) in issue_locations
            ],
            'count': len(issue_locations),
        }))

    return (samples, zr)


if __name__ == '__main__':
    import argparse
    import json
    import sys
    import tarfile

    ap = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument('rlr_wrk', default=['.',], nargs='*',
        help='''Restler wrk-dir as base path for its data to read.
            Set multiple times to gather data from several directories.
            Defaults to the current working dir.''')
    ap.add_argument('-m', '--rlr-mode', default='FuzzLean',
        choices=['Test', 'FuzzLean', 'Fuzz'],
        help='''Restler job sub-directory, named afer scan mode used.
             By default "FuzzLean" is looked under each wrk-dir.''')
    ap.add_argument('-o', '--out-report', default=None,
        help='Output report JSON file.')
    ap.add_argument('-s', '--summary', default=None,
        help='Summary-samples TXT file.')
    ap.add_argument('-n', '--dry-run', default=False, action='store_true',
        help='Do not write output files even those are set.')
    # ap.add_argument('--skip_errbuckets_json', default=False, action='store_true')
    args = ap.parse_args()

    ebc = list()

    for rlr_base_path in args.rlr_wrk:
        rlr_cfg = {
            'host': None,
            'no_ssl': False,
            'target_port': -1,
            'basepath': '',
        }

        with open(Path(rlr_base_path, 'Compile/engine_settings.json')) as fo:
            rlr_cfg.update(json.load(fo))

        print(f'-- Mining at {rlr_base_path}')

        # # ResponseBuckets contains a run summary, which bucketizes the responses
        # #   by error code and message (if Restler.ResultsAnalyzer not failed).
        # #   This is a basis for an optional summary.
        # if (p := Path(rlr_base_path, 'FuzzLean/ResponseBuckets/errorBuckets.json')).is_file():
        #     # print('J', end=' ')
        #     with open(p) as fo:
        #         jfo = json.load(fo)
        #         # print(len(str(jfo)), end=' ')
        #         ebc = collect_errbuckets(jfo)
        #     print(f'Loaded ResponseBuckets from {p.name}')

        # Collect individual bug buckets created for each bug found;
        # this is a basis for the main report.
        if (
            (p := Path(next(Path(rlr_base_path, args.rlr_mode, 'RestlerResults').glob('experiment*'), '.'),
                       'bug_buckets/bug_buckets.json')).is_file()
            or (p := Path(rlr_base_path, args.rlr_mode, 'RestlerResults/bug_buckets/bug_buckets.json')).is_file()
        ):
            # print('T', end=' ')
            with open(p) as fo:
                jfo = json.load(fo)
                # print(len(str(jfo)), end=' ')
                # ebc = collect_bugbuckets(jfo, p.parent)
                ebc.extend(collect_bugbuckets(jfo, p.parent))
            print(f'Processing bug_buckets from `{p}`')
        elif (
            (p := Path(next(Path(rlr_base_path, args.rlr_mode, 'RestlerResults').glob('experiment*'), '.'),
                       'bug_buckets.txz')).is_file()
            or (p := Path(rlr_base_path, args.rlr_mode, 'RestlerResults/bug_buckets.txz')).is_file()
        ):
            with tarfile.open(p, 'r:xz') as txz:
                if (bbfile := next(filter(lambda tm: (Path(tm.name).name == 'bug_buckets.json'
                                                      and tm.isfile()),
                                          txz.getmembers()), None)):
                    jfo = json.load(txz.extractfile(bbfile))
                    ebc.extend(collect_bugbuckets(jfo, Path(bbfile.name).parent, archive=txz))
                    print(f'Processing bug_buckets from `{p}:{bbfile.name}`')

    (samples, zr) = zreprt_the_result(rlr_cfg, ebc)
    # print(*dir(zr.site[0].alerts[0]), sep='\n')
    zr.site[0].alerts.sort(key=lambda a: a.riskcode, reverse=True)

    if args.out_report and not args.dry_run:
        with open(args.out_report, 'w') as fo:
            fo.write(zr.json())

    if args.summary and not args.dry_run:
        with open(args.summary, 'w') as fo:
            for qz, r, c, ch, raise_condition in samples:
                fo.write('\n' + '-' * 79 + '\n\n')
                fo.write(f'Response: {c}\nChecker: {ch}\nraise_condition: {raise_condition}\n\n')
                fo.writelines(sorted(set(f'{q.method} {q.path[:q.path.find("?") if q.path.find("?") > 0 else None]}\n' for q in qz)))
                fo.write(f'\n\n{qz[0].query}\n{qz[0].body}\n')
                fo.write(f'\nSAMPLE RESPONSE:\n\n{r}\n')
