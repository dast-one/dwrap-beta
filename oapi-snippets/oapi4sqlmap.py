"""openapi spec -> sqlmap tasks
"""

import json
import os
import pathlib


def ss(sd):
    """Returns a sample for given schema dict."""
    return {
        'string': 'qwe',
        'integer': 123,
    }.get(sd['type'], sd['type'])


bp = pathlib.Path(r'.../...')
os.chdir(bp)

for s in ('fu-...', 'fu-...',):
    with open(pathlib.Path(bp, s, 'oas.json')) as fo:
        oas = json.load(fo)
    for u in oas['paths']:
        # print(u)
        for m in oas['paths'][u]:
            # print('-X {}'.format(m.upper()))
            if m.upper() == 'GET':
                print(u)
                print('-X {}'.format(m.upper()))
                print(
                    '',
                    '&'.join('{}={}'.format(
                        p['name'], ss(p['schema']))
                            for p in oas['paths'][u][m]['parameters']
                            if p['in'] == 'query'
                    ),
                    sep='\t'
                )
