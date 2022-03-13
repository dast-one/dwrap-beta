"""Supplementary module: openapi spec -> sqlmap tasks.
"""

import json
import os
import pathlib
import re
import yaml


path_param = re.compile(r'\{([^}]+?)\}')

def _sample_for_schema(sd):
    """Returns a sample for given schema dict."""
    if sd['type'] == 'object':
        return dict((p, _sample_for_schema(s)) for (p, s) in sd['properties'].items())
    else:
        return {
            'string': 'qwe',
            'integer': 123,
        }.get(sd['type'], sd['type'] + '(WTF?!)')
    # TODO: Support other types or use full-featured generator.

def sqlmap_tasks(oas):
    """Create sqlmap tasks from openapi spec."""
    tasks = list()
    for u in oas['paths']:
        smt = dict()
        smt['url'] = path_param.sub(r'\1*', u)
        smt['headers'] = list()
        for m in oas['paths'][u]:
            smt['method'] = m.upper()

            if smt['method'] == 'GET':
                if get_params := '&'.join('{}={}'.format(
                    p['name'], _sample_for_schema(p['schema']))
                        for p in oas['paths'][u][m].get('parameters', dict())
                        if p.get('in') == 'query'
                ):
                    smt['url'] += f'&{get_params}'
                # TODO: Support in-header params.

            elif smt['method'] == 'POST':
                if post_data := _sample_for_schema(
                    oas['paths'][u][m]['requestBody']['content']['application/json']['schema']
                ):
                    smt['headers'].append('content-type:application/json')
                    smt['data'] = json.dumps(post_data)
                # TODO: Support in-header params.

            # TODO: Support other methods.

            tasks.append(smt)
    return tasks


def _as_yaml(fp):
    with open(fp) as fo:
        try:
            oas = yaml.load(fo, yaml.Loader)
        except Exception as e:
            return None
        else:
            return oas

def _as_json(fp):
    with open(fp) as fo:
        try:
            oas = json.load(fo)
        except Exception as e:
            return None
        else:
            return oas

def oas_load(file_path):
    fp = pathlib.Path(file_path).expanduser()
    return _as_yaml(fp) or _as_json(fp)


if __name__ == '__main__':
    # main()
    pass

    # bp = pathlib.Path(r'.../...')
    # os.chdir(bp)

    # for s in ('fu-...', 'fu-...',):
    #     with open(pathlib.Path(bp, s, 'oas.json')) as fo:
    #         oas = json.load(fo)
    #     # for u in oas['paths']:
    #     #   ...

