"""Supplementary module: openapi spec -> sqlmap tasks."""

import json
import pathlib
import re

import yaml


class CustomError(Exception):
    pass


path_param = re.compile(r'\{([^}]+?)\}')


def _sample_for_schema(sd, oas):
    """Returns a sample for given schema dict, dereferencing with given oapispec."""
    if sd is None or sd == dict() or sd == list():
        return sd

    if 'oneOf' in sd:
        return _sample_for_schema((sd['oneOf'] + [None,]).pop(), oas)

    if ref := sd.get('$ref'):
        d = oas
        for k in ref.split('/')[1:]:
            d = d[k]
        return _sample_for_schema(d, oas)

    if sd.get('type', 'object') == 'object':  # Absent 'type' should be treated as 'object'?!
        return dict((p, _sample_for_schema(s, oas)) for (p, s) in sd.get('properties', dict()).items())
    elif sd['type'] == 'array':
        return list(_sample_for_schema(sd['items'], oas) for _ in range(3))
    else:
        return {
            'string': 'qwe',
            'integer': 123,
            'number': 123,
            'boolean': True,
        }.get(sd['type'], sd['type'] + '(WTF?!)')
    # TODO: Support other types or use full-featured generator.


def sqlmap_tasks(oas, additional_qryparams=[]):
    """Create sqlmap tasks from openapi spec.

    Additional query params - a list of strings,
    like ['apikey=<token>', 'smthelse=...']
    """
    tasks = list()
    for u in oas['paths']:
        smt = dict()
        smt['url'] = path_param.sub(r'\1*', u)
        smt['headers'] = list()
        for m in oas['paths'][u]:
            smt['method'] = m.upper()

            if smt['method'] == 'GET':
                if qry_params := '&'.join(
                    additional_qryparams
                    + ['{}={}'.format(p['name'], _sample_for_schema(p['schema'], oas))
                        for p in oas['paths'][u][m].get('parameters', dict())
                        if p.get('in') == 'query']
                ):
                    smt['url'] += f'?{qry_params}'
                # TODO: Support in-header params.

            elif smt['method'] == 'POST':
                if qry_params := '&'.join(
                    additional_qryparams
                    + ['{}={}'.format(p['name'], _sample_for_schema(p['schema'], oas))
                        for p in oas['paths'][u][m].get('parameters', dict())
                        if p.get('in') == 'query']
                ):
                    smt['url'] += f'?{qry_params}'
                # TODO: Support in-header params.

                reqbody_content_item = oas['paths'][u][m].get(
                    'requestBody',
                    {'content': {'application/json': {'schema': None}}}
                )['content'].popitem()

                if post_data := _sample_for_schema(
                        reqbody_content_item[1]['schema'],
                        oas
                ):
                    smt['headers'].append(f'content-type:{reqbody_content_item[0]}')
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
    if r := (_as_yaml(fp) or _as_json(fp)):
        return r
    else:
        raise CustomError('oas_load() tried several formats and finally got None')


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
